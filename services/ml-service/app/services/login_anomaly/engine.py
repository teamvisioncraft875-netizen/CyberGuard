"""
CYBERGUARD — Production Login Anomaly Detection Engine (Phase C)

Loads the production Isolation Forest model checkpoint and feature schema
trained on the Cowrie honeypot dataset (Phase B).
Provides:
- Safe, once-only model loading with deserialization caching
- Strict 20-feature validation against login_feature_schema.json
- NaN, Infinite, and missing feature fail-loud protection
- Monotonic, bounded anomaly score normalization (Phase B calibration)
- CYBERGUARD 5-tier risk mapping (Safe, Low, Medium, High, Critical)
- Zero fabricated supervised probabilities (Phase B confirmed absence of ground truth)
- Bounded, thread-safe session tracking (5-minute rolling window, TTL eviction)
- Deterministic, plain-English signal explanations and prescriptive actions
- Backwards compatibility for legacy Phase 1 synthetic unit tests
"""

import json
import logging
import math
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.schemas.analyze import LoginAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel
from app.services.login_anomaly.features import FeatureExtractor, LoginEvent
from app.services.login_anomaly.synthetic import SyntheticTelemetryGenerator
from app.utils.cowrie_preprocessor import calculate_shannon_entropy

logger = logging.getLogger("cyberguard.login_anomaly.engine")

DEFAULT_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"


class BoundedLoginSessionTracker:
    """
    Thread-safe, memory-bounded session and rate tracker for incoming authentication streams.
    Aggregates authentication sequences over a 5-minute rolling window (300 seconds),
    matching the Phase A Cowrie preprocessor window.
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 5000):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._sessions: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def record_event(
        self,
        key: str,
        timestamp: datetime,
        is_success: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        protocol: str = "ssh",
        has_client_version: int = 0,
        has_hassh: int = 0,
    ) -> Dict[str, Any]:
        """
        Integrates a live authentication attempt into the bounded tracker state.
        Discards raw passwords immediately after deriving privacy-safe entropy.
        """
        with self._lock:
            now_ts = timestamp.timestamp()
            self._prune_expired(now_ts)

            if key in self._sessions:
                state = self._sessions[key]
                self._sessions.move_to_end(key)
            else:
                if len(self._sessions) >= self.max_entries:
                    self._sessions.popitem(last=False)
                state = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "failed_count": 0,
                    "success_count": 0,
                    "usernames": set(),
                    "password_entropies": [],
                    "unique_passwords_count": 0,
                    "protocol": protocol,
                    "has_client_version": has_client_version,
                    "has_hassh": has_hassh,
                }
                self._sessions[key] = state

            # Update state
            state["last_seen"] = timestamp
            if is_success:
                state["success_count"] += 1
            else:
                state["failed_count"] += 1

            if username:
                state["usernames"].add(str(username))

            if password is not None:
                # Privacy invariant: compute Shannon entropy and discard raw password
                ent = calculate_shannon_entropy(str(password))
                state["password_entropies"].append(ent)
                state["unique_passwords_count"] += 1

            if has_client_version:
                state["has_client_version"] = 1
            if has_hassh:
                state["has_hassh"] = 1
            if protocol:
                state["protocol"] = protocol

            # Return a snapshot copy of aggregated features
            first_ts = state["first_seen"]
            last_ts = state["last_seen"]
            duration = max(0.0, (last_ts - first_ts).total_seconds())

            failed = state["failed_count"]
            success = state["success_count"]
            total = failed + success

            unique_u = len(state["usernames"])
            u_ratio = unique_u / max(total, 1)

            entropies = state["password_entropies"]
            mean_ent = float(np.mean(entropies)) if entropies else 0.0

            unique_p = state["unique_passwords_count"]
            p_reuse = 0.0 if total <= 1 else max(0.0, (total - unique_p) / total)

            return {
                "failed_attempts_count": failed,
                "successful_attempts_count": success,
                "total_attempts": total,
                "attempt_frequency_hz": total / max(duration, 1.0),
                "unique_usernames_count": unique_u,
                "unique_usernames_ratio": u_ratio,
                "password_entropy": mean_ent,
                "unique_password_count": unique_p,
                "password_reuse_ratio": p_reuse,
                "session_duration": duration,
                "protocol": state["protocol"],
                "has_client_version": state["has_client_version"],
                "has_hassh": state["has_hassh"],
                "success_after_failure": 1 if (success > 0 and failed > 0) else 0,
            }

    def _prune_expired(self, current_ts: float) -> None:
        """Removes sessions inactive for longer than ttl_seconds."""
        cutoff = current_ts - self.ttl_seconds
        keys_to_remove = []
        for k, v in self._sessions.items():
            if v["last_seen"].timestamp() < cutoff:
                keys_to_remove.append(k)
            else:
                break
        for k in keys_to_remove:
            self._sessions.pop(k, None)


class LoginAnomalyEngine:
    """
    Login & Authentication Anomaly Detection Engine.
    Operates in two modes:
    1. Production Mode (`load_checkpoint=True`): Loads the Phase B trained Cowrie Isolation Forest
       model (20 features) from disk, evaluates live authentication requests, and outputs standard
       UnifiedAnalysisResponse contracts.
    2. Legacy Mode (`load_checkpoint=False`, `auto_bootstrap=True`): Operates the synthetic 5-feature
       in-memory baseline for backward-compatibility with Phase 1 unit tests.
    """

    def __init__(
        self,
        contamination: float = 0.04,
        n_estimators: int = 100,
        random_state: int = 42,
        auto_bootstrap: bool = True,
        models_dir: Optional[Path] = None,
        load_checkpoint: bool = False,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.models_dir = Path(models_dir or DEFAULT_MODELS_DIR)
        self.model_path = self.models_dir / "login_anomaly_forest.joblib"
        self.schema_path = self.models_dir / "login_feature_schema.json"
        self.metadata_path = self.models_dir / "login_training_metadata.json"

        self.is_fitted = False
        self.model: Optional[IsolationForest] = None
        self.feature_names: List[str] = []
        self.score_normal_bound: float = 0.15
        self.score_anomaly_bound: float = -0.25
        self.metadata: Dict[str, Any] = {}
        self.is_production_model: bool = False

        self.session_tracker = BoundedLoginSessionTracker(ttl_seconds=300.0, max_entries=5000)

        if load_checkpoint:
            self._load_production_checkpoint()
        elif auto_bootstrap:
            self._bootstrap_default_baseline()
        else:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                max_samples="auto",
            )

    def _load_production_checkpoint(self) -> None:
        """
        Loads the pre-trained Isolation Forest model, schema, and metadata from disk.
        Fails loud if artifacts are missing or corrupted.
        """
        if not self.model_path.exists():
            raise FileNotFoundError(f"Login anomaly model checkpoint not found: {self.model_path}")
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Login anomaly feature schema not found: {self.schema_path}")

        try:
            with open(self.schema_path, "r", encoding="utf-8") as f:
                schema_data = json.load(f)
            self.feature_names = schema_data["feature_names"]
            self.score_normal_bound = float(schema_data.get("score_normal_bound", 0.15))
            self.score_anomaly_bound = float(schema_data.get("score_anomaly_bound", -0.25))

            loaded_model = joblib.load(self.model_path)
            if not hasattr(loaded_model, "decision_function"):
                raise ValueError("Loaded artifact does not implement decision_function.")
            self.model = loaded_model
            self.is_fitted = True
            self.is_production_model = True

            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            logger.info(
                f"Successfully loaded production Login Anomaly Forest ({len(self.feature_names)} features) "
                f"from {self.model_path}"
            )
        except Exception as e:
            self.is_fitted = False
            self.model = None
            self.is_production_model = False
            raise RuntimeError(f"Failed to load login anomaly model artifact: {e}") from e

    def _bootstrap_default_baseline(self) -> None:
        """Fit model on synthetic normal baseline for legacy Phase 1 test compatibility."""
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
        )
        generator = SyntheticTelemetryGenerator(random_state=self.random_state)
        normal_events = generator.generate_normal_events(n_samples=600)
        self.fit(normal_events)
        self.feature_names = FeatureExtractor.FEATURE_NAMES

    def fit(self, events: Sequence[Union[LoginEvent, Dict[str, Any], Any]]) -> "LoginAnomalyEngine":
        """Train the Isolation Forest baseline on telemetry events."""
        X = FeatureExtractor.extract_batch(events)
        if len(X) == 0:
            raise ValueError("Cannot fit LoginAnomalyEngine on empty dataset.")

        self.model.fit(X)
        self.is_fitted = True
        return self

    def normalize_score(self, raw_decision_score: float) -> float:
        """
        Maps IsolationForest decision_function output to a bounded, monotonic anomaly score in [0.0, 1.0].
        0.0 = baseline normal, 1.0 = highly anomalous.
        """
        score_span = self.score_normal_bound - self.score_anomaly_bound
        normalized = (self.score_normal_bound - raw_decision_score) / score_span
        return float(max(0.0, min(1.0, normalized)))

    def validate_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validates feature presence, ordering, and absence of NaN/Inf.
        Fails loud on schema mismatch or non-finite values.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("Login Anomaly Engine is not fitted or model checkpoint is not loaded.")

        missing_cols = [c for c in self.feature_names if c not in df.columns]
        if missing_cols:
            raise ValueError(f"Input features missing required schema columns: {missing_cols}")

        ordered_df = df[self.feature_names]

        # Check for NaN / Inf
        nans = ordered_df.isna().sum().sum()
        if nans > 0:
            raise ValueError(f"Invalid feature input: found {nans} NaN values.")

        infs = np.isinf(ordered_df.select_dtypes(include=[np.number])).sum().sum()
        if infs > 0:
            raise ValueError(f"Invalid feature input: found {infs} infinite values.")

        return ordered_df

    def build_feature_dataframe(
        self,
        request: Union[LoginAnalyzeRequest, LoginEvent, Dict[str, Any], Any],
        track_state: bool = True,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Converts incoming request or event into a validated 20-feature DataFrame.
        """
        if isinstance(request, LoginAnalyzeRequest):
            user_id = request.user_id
            location = request.location
            device_id = request.device_id
            failed_attempts = request.failed_attempts
            ts_str = request.timestamp
        elif isinstance(request, LoginEvent):
            user_id = request.user_id or "unknown_user"
            location = ""
            device_id = ""
            failed_attempts = request.failed_attempts
            ts_str = request.timestamp or ""
        elif hasattr(request, "user_id") and hasattr(request, "failed_attempts"):
            user_id = getattr(request, "user_id", "unknown_user")
            location = getattr(request, "location", "")
            device_id = getattr(request, "device_id", "")
            failed_attempts = int(getattr(request, "failed_attempts", 0))
            ts_str = getattr(request, "timestamp", "")
        else:
            user_id = str(request.get("user_id", "unknown_user"))
            location = str(request.get("location", ""))
            device_id = str(request.get("device_id", ""))
            failed_attempts = int(request.get("failed_attempts", 0))
            ts_str = str(request.get("timestamp", ""))

        # If caller already passed 20 model features directly in a dictionary
        if isinstance(request, dict) and all(k in request for k in self.feature_names):
            df = pd.DataFrame([{k: request[k] for k in self.feature_names}])
            validated_df = self.validate_features(df)
            signals_meta = {
                "failed_attempts": int(request["failed_attempts_count"]),
                "attempt_frequency_hz": float(request["attempt_frequency_hz"]),
                "unique_usernames_count": int(request["unique_usernames_count"]),
                "session_duration": float(request["session_duration"]),
                "password_entropy": float(request["password_entropy"]),
            }
            return validated_df, signals_meta

        # Parse timestamp safely
        try:
            cleaned_ts = ts_str.replace("Z", "+00:00") if ts_str else ""
            dt = datetime.fromisoformat(cleaned_ts) if cleaned_ts else datetime.now(timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)

        if track_state:
            tracker_key = user_id or device_id or "default_source"
            tracked = self.session_tracker.record_event(
                key=tracker_key,
                timestamp=dt,
                is_success=(failed_attempts == 0),
                username=user_id,
            )
            if failed_attempts > tracked["failed_attempts_count"]:
                tracked["failed_attempts_count"] = failed_attempts
                tracked["total_attempts"] = failed_attempts + tracked["successful_attempts_count"]
                tracked["attempt_frequency_hz"] = tracked["total_attempts"] / max(tracked["session_duration"], 1.0)
        else:
            success_count = 1 if failed_attempts == 0 else 0
            total_attempts = max(failed_attempts + success_count, 1)
            tracked = {
                "failed_attempts_count": failed_attempts,
                "successful_attempts_count": success_count,
                "total_attempts": total_attempts,
                "attempt_frequency_hz": total_attempts / 1.0,
                "unique_usernames_count": 1,
                "unique_usernames_ratio": 1.0 / total_attempts,
                "password_entropy": 0.0,
                "unique_password_count": 0,
                "password_reuse_ratio": 0.0,
                "session_duration": 0.0,
                "protocol": "ssh",
                "has_client_version": 0,
                "has_hassh": 0,
                "success_after_failure": 0,
            }

        login_hour = float(dt.hour + dt.minute / 60.0)
        login_hour_sin = math.sin(2.0 * math.pi * login_hour / 24.0)
        login_hour_cos = math.cos(2.0 * math.pi * login_hour / 24.0)
        day_of_week = dt.weekday()

        feat_dict = {
            "failed_attempts_count": float(tracked["failed_attempts_count"]),
            "successful_attempts_count": float(tracked["successful_attempts_count"]),
            "total_attempts": float(tracked["total_attempts"]),
            "attempt_frequency_hz": float(tracked["attempt_frequency_hz"]),
            "unique_usernames_count": float(tracked["unique_usernames_count"]),
            "unique_usernames_ratio": float(tracked["unique_usernames_ratio"]),
            "password_entropy": float(tracked["password_entropy"]),
            "unique_password_count": float(tracked["unique_password_count"]),
            "password_reuse_ratio": float(tracked["password_reuse_ratio"]),
            "session_duration": float(tracked["session_duration"]),
            "login_hour": float(login_hour),
            "login_hour_sin": float(login_hour_sin),
            "login_hour_cos": float(login_hour_cos),
            "day_of_week": float(day_of_week),
            "proto_ssh": 1.0 if tracked["protocol"] == "ssh" else 0.0,
            "proto_telnet": 1.0 if tracked["protocol"] == "telnet" else 0.0,
            "proto_other": 0.0,
            "has_client_version": float(tracked["has_client_version"]),
            "has_hassh": float(tracked["has_hassh"]),
            "success_after_failure": float(tracked["success_after_failure"]),
        }

        df = pd.DataFrame([feat_dict])
        validated_df = self.validate_features(df)
        signals_meta = {
            "user_id": user_id,
            "device_id": device_id,
            "location": location,
            "failed_attempts": int(tracked["failed_attempts_count"]),
            "attempt_frequency_hz": float(tracked["attempt_frequency_hz"]),
            "session_duration": float(tracked["session_duration"]),
            "unique_usernames_count": int(tracked["unique_usernames_count"]),
        }
        return validated_df, signals_meta

    def score_vector(self, df_features: pd.DataFrame) -> Tuple[float, float]:
        """Scores a validated feature DataFrame. Returns (raw_score, normalized_score)."""
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model is not loaded or fitted.")

        validated_df = self.validate_features(df_features)
        raw_score = float(self.model.decision_function(validated_df)[0])
        norm_score = self.normalize_score(raw_score)
        return raw_score, norm_score

    def analyze(
        self,
        request: Union[LoginAnalyzeRequest, Dict[str, Any]],
        track_state: bool = True,
    ) -> UnifiedAnalysisResponse:
        """
        Production analysis method returning CYBERGUARD UnifiedAnalysisResponse contract.
        Fails loud if model is missing or features are invalid.
        """
        features_df, meta = self.build_feature_dataframe(request, track_state=track_state)
        raw_score, norm_score = self.score_vector(features_df)

        failed_count = meta.get("failed_attempts", 0)
        freq_hz = meta.get("attempt_frequency_hz", 0.0)
        unique_users = meta.get("unique_usernames_count", 1)

        # Legitimate baseline calibration:
        # A single successful login with zero failed attempts and normal frequency conforms
        # to standard authenticated human operation and is calibrated as baseline SAFE.
        if failed_count == 0 and unique_users <= 1 and freq_hz <= 1.0:
            norm_score = min(norm_score * 0.15, 0.15)

        risk_score = int(round(norm_score * 100))

        if risk_score <= 19:
            risk_level = RiskLevel.SAFE
        elif risk_score <= 39:
            risk_level = RiskLevel.LOW
        elif risk_score <= 69:
            risk_level = RiskLevel.MEDIUM
        elif risk_score <= 89:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        failed_count = meta.get("failed_attempts", 0)
        freq_hz = meta.get("attempt_frequency_hz", 0.0)
        unique_users = meta.get("unique_usernames_count", 1)

        attack_vector = None
        if features_df["success_after_failure"].iloc[0] == 1.0 and failed_count >= 3:
            attack_vector = "T1110 - Brute Force / Password Guessing"
        elif unique_users >= 3:
            attack_vector = "T1110.003 - Password Spraying"
        elif risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            attack_vector = "Behavioral Authentication Anomaly"

        if risk_level == RiskLevel.SAFE:
            explanation = "Authentication telemetry conforms to baseline normal login patterns."
        elif failed_count >= 3 and freq_hz >= 1.0:
            explanation = (
                f"Elevated authentication failure volume ({failed_count} attempts) at high velocity "
                f"({freq_hz:.2f} Hz) indicates automated brute-force probing."
            )
        elif failed_count >= 3:
            explanation = f"Repeated authentication failures ({failed_count} failed attempts) observed within session window."
        elif unique_users >= 2:
            explanation = f"Multiple distinct usernames ({unique_users}) attempted from same entity within observation window."
        else:
            explanation = "Authentication timing, frequency, or structural features deviate significantly from learned baseline."

        if risk_level == RiskLevel.SAFE:
            recommended_actions = ["No action required; log for audit trail"]
        elif risk_level == RiskLevel.LOW:
            recommended_actions = ["Monitor authentication activity for subsequent anomalies"]
        elif risk_level == RiskLevel.MEDIUM:
            recommended_actions = [
                "Review authentication source context and attempt rate",
                "Log event in security information management system",
            ]
        elif risk_level == RiskLevel.HIGH:
            recommended_actions = [
                "Apply authentication rate-limiting on source identifier",
                "Prompt user for multi-factor authentication (MFA) challenge",
            ]
        else:
            recommended_actions = [
                "Enforce immediate multi-factor authentication verification",
                "Apply temporary rate-limit barrier on source identifier",
                "Notify security operations center (SOC) of brute-force breach pattern",
            ]

        confidence = float(round(min(1.0, max(0.5, 0.5 + abs(raw_score) * 2.5)), 2))

        signals: Dict[str, Any] = {
            "failed_attempts": failed_count,
            "attempt_frequency_hz": round(freq_hz, 4),
            "session_duration": round(meta.get("session_duration", 0.0), 2),
            "unique_usernames_count": unique_users,
            "anomaly_score": round(norm_score, 4),
            "raw_decision_score": round(raw_score, 4),
            "detector_triggered": "Behavioral Login Anomaly Detector",
            "supervised_probability": None,  # Strictly NO fabricated probability
            "is_new_device": None,          # Unsupported in current Cowrie telemetry
            "impossible_travel": None,       # Unsupported in current Cowrie telemetry
            "attack_vector": attack_vector,
        }
        for k in ("user_id", "device_id", "location"):
            if k in meta and meta[k]:
                signals[k] = meta[k]

        return UnifiedAnalysisResponse(
            risk_level=risk_level,
            risk_score=risk_score,
            explanation=explanation,
            signals=signals,
            recommended_actions=recommended_actions,
            confidence_score=confidence,
        )

    # -----------------------------------------------------------------------
    # Backwards-compatibility for Phase 1 tests (test_login_anomaly.py)
    # -----------------------------------------------------------------------
    def score_event(
        self, event: Union[LoginEvent, Dict[str, Any], Any]
    ) -> Tuple[float, Dict[str, float]]:
        """Compute the raw Isolation Forest anomaly score and heuristic signal weights."""
        if not self.is_fitted:
            raise RuntimeError("LoginAnomalyEngine must be fitted before scoring events.")

        parsed_event = FeatureExtractor.parse_event(event)
        x_vec = FeatureExtractor.extract_vector(parsed_event).reshape(1, -1)
        raw_score = float(self.model.decision_function(x_vec)[0])

        signals: Dict[str, float] = {}
        failed = parsed_event.failed_attempts
        if failed >= 8:
            signals["failed_login_burst"] = 1.0
        elif failed >= 5:
            signals["failed_login_burst"] = 0.8
        elif failed >= 3:
            signals["failed_login_burst"] = 0.5

        if parsed_event.impossible_travel:
            signals["impossible_travel_detected"] = 1.0
        if parsed_event.is_new_device:
            signals["unrecognized_device"] = 0.5
        if parsed_event.is_new_location:
            signals["unrecognized_location"] = 0.4

        hour = parsed_event.resolved_hour
        if 1 <= hour <= 4:
            signals["off_hours_activity"] = 0.50
        elif hour in (0, 5):
            signals["off_hours_activity"] = 0.30
        elif hour in (6, 23):
            signals["off_hours_activity"] = 0.15

        return raw_score, signals

    def predict(
        self, event: Union[LoginEvent, Dict[str, Any], Any]
    ) -> Dict[str, Any]:
        """Legacy evaluation method returning dictionary format compatible with Phase 1 tests."""
        if self.is_production_model:
            resp = self.analyze(event)
            signals_list = [
                {"name": k, "weight": float(v) if isinstance(v, (int, float)) else 0.0}
                for k, v in resp.signals.items()
                if isinstance(v, (int, float)) and v is not None
            ]
            return {
                "risk_level": resp.risk_level.value,
                "risk_score": resp.risk_score,
                "explanation": resp.explanation,
                "recommended_action": resp.recommended_actions[0] if resp.recommended_actions else "No action required",
                "signals": signals_list,
            }

        raw_score, signals_dict = self.score_event(event)
        parsed_event = FeatureExtractor.parse_event(event)

        if raw_score >= 0.12:
            base_score = max(5.0, 15.0 - (raw_score - 0.12) * 50.0)
        elif raw_score >= 0.0:
            base_score = 15.0 + (0.12 - raw_score) * 200.0
        elif raw_score >= -0.10:
            base_score = 39.0 + (-raw_score) * 260.0
        else:
            base_score = 65.0 + min(35.0, (-raw_score - 0.10) * 180.0)

        heuristic_boost = 0.0
        if signals_dict.get("impossible_travel_detected", 0) > 0:
            heuristic_boost += 35.0
        if signals_dict.get("failed_login_burst", 0) >= 0.8:
            heuristic_boost += 40.0
        elif signals_dict.get("failed_login_burst", 0) >= 0.5:
            heuristic_boost += 20.0
        if signals_dict.get("off_hours_activity", 0) >= 0.4 and signals_dict.get("unrecognized_device", 0) > 0:
            heuristic_boost += 15.0

        calibrated_score = int(round(min(100.0, max(0.0, base_score + heuristic_boost))))

        if calibrated_score <= 19:
            risk_level = "Safe"
        elif calibrated_score <= 39:
            risk_level = "Low"
        elif calibrated_score <= 69:
            risk_level = "Medium"
        elif calibrated_score <= 89:
            risk_level = "High"
        else:
            risk_level = "Critical"

        signals_list = [
            {"name": name, "weight": float(round(weight, 2))}
            for name, weight in sorted(signals_dict.items(), key=lambda item: item[1], reverse=True)
        ]

        explanation = self._build_explanation(risk_level, calibrated_score, parsed_event, signals_dict)
        recommended_action = self._build_recommended_action(risk_level, signals_dict)

        return {
            "risk_level": risk_level,
            "risk_score": calibrated_score,
            "explanation": explanation,
            "recommended_action": recommended_action,
            "signals": signals_list,
        }

    def _build_explanation(
        self,
        risk_level: str,
        risk_score: int,
        event: LoginEvent,
        signals: Dict[str, float],
    ) -> str:
        if risk_level == "Safe":
            return (
                "Safe: Login telemetry aligns with normal user behavioral patterns. "
                "Familiar device and location verified during standard operational hours."
            )
        flag_details = []
        if signals.get("impossible_travel_detected"):
            flag_details.append("impossible geographic travel speed indicating credential theft or proxy hopping")
        if signals.get("failed_login_burst"):
            flag_details.append(f"{event.failed_attempts} prior consecutive failed login attempts (potential brute-force)")
        if signals.get("unrecognized_device"):
            flag_details.append("unrecognized device hardware fingerprint")
        if signals.get("unrecognized_location"):
            flag_details.append("unrecognized geographic location or IP range")
        if signals.get("off_hours_activity"):
            flag_details.append(f"activity during unusual off-hours ({event.resolved_hour:02d}:00 UTC)")

        if not flag_details:
            return f"{risk_level} Risk (Score: {risk_score}): Minor behavioral variance detected against baseline model."

        reasons_str = "; ".join(flag_details)
        return f"{risk_level} Risk (Score: {risk_score}): Anomalous authentication activity detected — {reasons_str}."

    def _build_recommended_action(self, risk_level: str, signals: Dict[str, float]) -> str:
        if risk_level == "Critical":
            return "Immediately terminate active session, enforce password reset, and revoke session tokens across all endpoints."
        elif risk_level == "High":
            return "Challenge user with immediate Multi-Factor Authentication (MFA) step-up and alert user of potential account takeover."
        elif risk_level == "Medium":
            return "Prompt user to confirm new login location/device via out-of-band notification and increase telemetry monitoring."
        elif risk_level == "Low":
            return "Log informational notice to user audit history; allow normal login without disruption."
        else:
            return "Pass-through; standard security logging."


# ---------------------------------------------------------------------------
# Singleton / Lazy Cached Model Loader
# ---------------------------------------------------------------------------
_LOGIN_ENGINE_INSTANCE: Optional[LoginAnomalyEngine] = None
_LOGIN_ENGINE_LOCK = threading.Lock()


def get_login_anomaly_engine() -> LoginAnomalyEngine:
    """
    Returns the singleton LoginAnomalyEngine instance.
    Loads model checkpoint once on initial invocation and reuses in-memory.
    """
    global _LOGIN_ENGINE_INSTANCE
    if _LOGIN_ENGINE_INSTANCE is None:
        with _LOGIN_ENGINE_LOCK:
            if _LOGIN_ENGINE_INSTANCE is None:
                _LOGIN_ENGINE_INSTANCE = LoginAnomalyEngine(load_checkpoint=True, auto_bootstrap=False)
    return _LOGIN_ENGINE_INSTANCE
