"""
CyberGuard ML Service - Standalone Login Anomaly Detection Engine
Uses scikit-learn IsolationForest combined with behavioral feature attribution
to evaluate login telemetry and return unified CYBERGUARD threat responses.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from app.services.login_anomaly.features import FeatureExtractor, LoginEvent
from app.services.login_anomaly.synthetic import SyntheticTelemetryGenerator


class LoginAnomalyEngine:
    """
    Standalone Login & Behavioral Anomaly Detection Engine.

    Independent of FastAPI and PostgreSQL databases.
    Evaluates login telemetry using scikit-learn Isolation Forest and returns
    standardized CYBERGUARD threat responses.
    """

    def __init__(
        self,
        contamination: float = 0.04,
        n_estimators: int = 100,
        random_state: int = 42,
        auto_bootstrap: bool = True,
    ):
        """
        Initialize the anomaly engine.

        :param contamination: Expected proportion of outliers in the baseline data.
        :param n_estimators: Number of isolation trees in the ensemble.
        :param random_state: Seed for deterministic execution.
        :param auto_bootstrap: If True, automatically fits on synthetic baseline on initialization.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.is_fitted = False

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
        )

        if auto_bootstrap:
            self._bootstrap_default_baseline()

    def _bootstrap_default_baseline(self) -> None:
        """Fit model on synthetic normal baseline to ensure out-of-the-box readiness."""
        generator = SyntheticTelemetryGenerator(random_state=self.random_state)
        normal_events = generator.generate_normal_events(n_samples=600)
        self.fit(normal_events)

    def fit(self, events: Sequence[Union[LoginEvent, Dict[str, Any], Any]]) -> "LoginAnomalyEngine":
        """
        Train the Isolation Forest baseline on normal login telemetry events.

        :param events: Sequence of benign LoginEvent objects or dictionaries.
        :return: self
        """
        X = FeatureExtractor.extract_batch(events)
        if len(X) == 0:
            raise ValueError("Cannot fit LoginAnomalyEngine on empty dataset.")

        self.model.fit(X)
        self.is_fitted = True
        return self

    def score_event(
        self, event: Union[LoginEvent, Dict[str, Any], Any]
    ) -> Tuple[float, Dict[str, float]]:
        """
        Compute the raw Isolation Forest anomaly score and extract heuristic signal weights.

        :return: (raw_score, signals_dict)
        """
        if not self.is_fitted:
            raise RuntimeError("LoginAnomalyEngine must be fitted before scoring events.")

        parsed_event = FeatureExtractor.parse_event(event)
        x_vec = FeatureExtractor.extract_vector(parsed_event).reshape(1, -1)

        # IsolationForest decision_function: lower = more anomalous
        # Normal samples typically > 0.0 (up to +0.20), anomalies < 0.0 (down to -0.30)
        raw_score = float(self.model.decision_function(x_vec)[0])

        # Compute granular signal activations (normalized 0.0 to 1.0)
        signals: Dict[str, float] = {}

        # 1. Failed attempts signal
        failed = parsed_event.failed_attempts
        if failed >= 8:
            signals["failed_login_burst"] = 1.0
        elif failed >= 5:
            signals["failed_login_burst"] = 0.85
        elif failed >= 3:
            signals["failed_login_burst"] = 0.60
        elif failed >= 1:
            signals["failed_login_burst"] = round(failed * 0.18, 2)

        # 2. Impossible travel (geo-velocity anomaly)
        if parsed_event.impossible_travel:
            signals["impossible_travel_detected"] = 0.95

        # 3. New device signal
        if parsed_event.is_new_device:
            signals["unrecognized_device"] = 0.40

        # 4. New location signal
        if parsed_event.is_new_location:
            signals["unrecognized_location"] = 0.40

        # 5. Off-hours signal (e.g. 01:00 - 05:00)
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
        """
        Evaluate a login event and return CYBERGUARD's unified detection contract:
        {
          "risk_level": "Safe | Low | Medium | High | Critical",
          "risk_score": 0-100,
          "explanation": "...",
          "recommended_action": "...",
          "signals": [{"name": "...", "weight": 0.0}]
        }
        """
        raw_score, signals_dict = self.score_event(event)
        parsed_event = FeatureExtractor.parse_event(event)

        # Calibrate risk score (0 - 100)
        # 1. Map raw IsolationForest decision_function to base score:
        # Decision score ranges roughly from -0.30 (extreme anomaly) to +0.20 (very normal)
        # Map: > +0.10 -> < 15, 0.00 -> ~45, < -0.15 -> > 80
        if raw_score >= 0.12:
            base_score = max(5.0, 15.0 - (raw_score - 0.12) * 50.0)
        elif raw_score >= 0.0:
            # 0.0 to 0.12: transitional Safe/Low
            base_score = 15.0 + (0.12 - raw_score) * 200.0  # 15 to 39
        elif raw_score >= -0.10:
            # -0.10 to 0.0: Low/Medium
            base_score = 39.0 + (-raw_score) * 260.0  # 39 to 65
        else:
            # Below -0.10: High/Critical
            base_score = 65.0 + min(35.0, (-raw_score - 0.10) * 180.0)  # 65 to 100

        # 2. Adjust using active signal weights to ensure domain alignment
        heuristic_boost = 0.0
        if signals_dict.get("impossible_travel_detected", 0) > 0:
            heuristic_boost += 35.0
        if signals_dict.get("failed_login_burst", 0) >= 0.8:
            heuristic_boost += 40.0
        elif signals_dict.get("failed_login_burst", 0) >= 0.5:
            heuristic_boost += 20.0
        if signals_dict.get("off_hours_activity", 0) >= 0.4 and signals_dict.get("unrecognized_device", 0) > 0:
            heuristic_boost += 15.0

        calibrated_score = int(np.clip(round(base_score + heuristic_boost * 0.45), 0, 100))

        # Guarantee high thresholds for severe attack patterns
        if parsed_event.impossible_travel and (parsed_event.is_new_device or parsed_event.is_new_location):
            calibrated_score = max(calibrated_score, 85)
        if parsed_event.failed_attempts >= 6:
            calibrated_score = max(calibrated_score, 82)
        if parsed_event.failed_attempts >= 10:
            calibrated_score = max(calibrated_score, 92)
        if parsed_event.impossible_travel and parsed_event.failed_attempts >= 3:
            calibrated_score = max(calibrated_score, 95)

        # Determine calibrated Risk Tier
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

        # Format signals list
        signals_list = [
            {"name": name, "weight": round(weight, 2)}
            for name, weight in sorted(signals_dict.items(), key=lambda item: item[1], reverse=True)
        ]

        # Generate contextual explanation & recommended action
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
        """Synthesize a human-readable plain-English explanation of the detection verdict."""
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
        """Synthesize a prescriptive mitigation step based on risk tier and threat signals."""
        if risk_level == "Critical":
            return (
                "Immediately terminate active session, enforce password reset, and revoke session tokens across all endpoints."
            )
        elif risk_level == "High":
            return (
                "Challenge user with immediate Multi-Factor Authentication (MFA) step-up and alert user of potential account takeover."
            )
        elif risk_level == "Medium":
            return (
                "Prompt user to confirm new login location/device via out-of-band notification and increase telemetry monitoring."
            )
        elif risk_level == "Low":
            return (
                "Log informational notice to user audit history; allow normal login without disruption."
            )
        else:
            return "Pass-through; standard security logging."
