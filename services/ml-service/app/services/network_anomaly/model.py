"""
CYBERGUARD — Network & System Threat Model

Trained on CTU-13 network telemetry (Scenarios 42, 43, 44).
Uses HistGradientBoostingClassifier for deterministic, sub-millisecond
threat classification of network flow anomalies and botnet C2 traffic.
Adheres strictly to the UnifiedAnalysisResponse contract.
"""

from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union, List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from app.utils.ctu13_preprocessor import FEATURE_COLUMNS, parse_flow_record
from app.schemas.analyze import UnifiedAnalysisResponse, RiskLevel


def calibrate_risk(probability: float) -> Tuple[int, RiskLevel]:
    """
    Calibrates raw model probability [0.0, 1.0] to CyberGuard's 5-tier risk scale.
    - 0-19: Safe
    - 20-39: Low
    - 40-69: Medium
    - 70-89: High
    - 90-100: Critical
    """
    prob_clamped = max(0.0, min(1.0, float(probability)))
    score = int(round(prob_clamped * 100))

    if score <= 19:
        tier = RiskLevel.SAFE
    elif score <= 39:
        tier = RiskLevel.LOW
    elif score <= 69:
        tier = RiskLevel.MEDIUM
    elif score <= 89:
        tier = RiskLevel.HIGH
    else:
        tier = RiskLevel.CRITICAL

    return score, tier


class NetworkThreatModel:
    """
    Supervised Network Threat & Botnet Detection Model.
    Supports fit, evaluation, real-time single-flow scoring, and persistence.
    """

    def __init__(
        self,
        random_state: int = 42,
        max_iter: int = 100,
        min_samples_leaf: int = 20,
        l2_regularization: float = 0.1,
        anomaly_detector: Optional[Any] = None,
    ):
        self.random_state = random_state
        self.max_iter = max_iter
        self.min_samples_leaf = min_samples_leaf
        self.l2_regularization = l2_regularization
        self.anomaly_detector = anomaly_detector
        self.is_fitted = False
        self.feature_columns = FEATURE_COLUMNS

        self.classifier = HistGradientBoostingClassifier(
            max_iter=self.max_iter,
            min_samples_leaf=self.min_samples_leaf,
            l2_regularization=self.l2_regularization,
            random_state=self.random_state,
        )

    def fit(self, X: pd.DataFrame, y: Union[pd.Series, np.ndarray]) -> "NetworkThreatModel":
        """Fits the underlying classifier on feature matrix X and target y."""
        X_clean = self._validate_features(X)
        y_clean = np.asarray(y, dtype=np.int32)

        # Allow small test fixtures to split nodes while maintaining robustness on production data
        effective_min_samples = min(self.min_samples_leaf, max(1, len(X_clean) // 2))
        self.classifier = HistGradientBoostingClassifier(
            max_iter=self.max_iter,
            min_samples_leaf=effective_min_samples,
            l2_regularization=self.l2_regularization,
            random_state=self.random_state,
        )

        self.classifier.fit(X_clean, y_clean)
        self.is_fitted = True
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Returns threat probability array P(is_threat=1)."""
        if not self.is_fitted:
            raise RuntimeError("NetworkThreatModel is not fitted yet. Call fit() first.")
        X_clean = self._validate_features(X)
        probabilities = self.classifier.predict_proba(X_clean)
        return probabilities[:, 1]

    def predict(self, X: pd.DataFrame, threshold: float = 0.5) -> np.ndarray:
        """
        Returns binary threat predictions {0, 1} calibrated against decision threshold.
        Deterministic and monotonic with respect to threshold.
        """
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(np.int32)

    def score_anomaly(self, X: pd.DataFrame) -> Tuple[float, float]:
        """
        Computes IsolationForest raw anomaly score and normalized anomaly score in [0.0, 1.0].
        Lower decision_function -> more anomalous -> higher normalized anomaly score.
        """
        if self.anomaly_detector is None:
            return 0.0, 0.0
        X_clean = self._validate_features(X)
        try:
            raw_score = float(self.anomaly_detector.decision_function(X_clean)[0])
            norm_score = float(1.0 / (1.0 + np.exp(np.clip(8.0 * raw_score, -20.0, 20.0))))
            return raw_score, norm_score
        except Exception:
            return 0.0, 0.0

    def score_flow(self, flow: Dict[str, Any]) -> Tuple[int, RiskLevel]:
        """Scores a single network flow dictionary, returning (risk_score, risk_level)."""
        df_single = self._flow_to_df(flow)
        prob = self.predict_proba(df_single)[0]
        return calibrate_risk(prob)

    def analyze_flow(
        self,
        user_id: str,
        event_type: str,
        flow_details: Dict[str, Any],
    ) -> UnifiedAnalysisResponse:
        """
        Evaluates network flow telemetry using hybrid detection architecture:
        - Known-pattern detector: HistGradientBoosting
        - Novel/anomaly detector: IsolationForest
        Returns strict UnifiedAnalysisResponse with distinguishable scores.
        """
        df_single = self._flow_to_df(flow_details)
        prob = float(self.predict_proba(df_single)[0])
        raw_anomaly, norm_anomaly = self.score_anomaly(df_single)
        is_anomaly_outlier = bool(self.anomaly_detector is not None and raw_anomaly < 0.0)

        # Combination Logic:
        if prob >= 0.50:
            score, risk_tier = calibrate_risk(prob)
            detector_triggered = "Supervised HistGradientBoosting (Known Threat Pattern)"
        elif is_anomaly_outlier and norm_anomaly >= 0.52:
            # Map anomaly score [0.52, 1.0] across Medium (50-69) and High (70-88)
            norm_fraction = min(1.0, max(0.0, (norm_anomaly - 0.52) / 0.48))
            score = int(round(50 + norm_fraction * 38))
            risk_tier = RiskLevel.HIGH if score >= 70 else RiskLevel.MEDIUM
            detector_triggered = "IsolationForest (Unsupervised Zero-Day / Novel Anomaly)"
        else:
            score, risk_tier = calibrate_risk(prob)
            detector_triggered = "Baseline Normal (No threat signatures or anomalies detected)"

        dur = df_single["dur"].iloc[0]
        tot_bytes = df_single["tot_bytes"].iloc[0]
        byte_rate = df_single["byte_rate"].iloc[0]
        proto = "TCP" if df_single["proto_tcp"].iloc[0] == 1 else ("UDP" if df_single["proto_udp"].iloc[0] == 1 else ("ICMP" if df_single["proto_icmp"].iloc[0] == 1 else "Other"))

        if risk_tier in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            explanation = (
                f"High-confidence network threat detected via {detector_triggered}: anomalous {proto} outbound flow "
                f"({byte_rate:.1f} bytes/sec, total {tot_bytes:.0f} bytes) matching malicious activity signatures."
            )
            recommended_actions = [
                "Isolate endpoint network connection immediately",
                "Terminate suspicious parent process",
                "Block destination IP on enterprise gateway",
            ]
        elif risk_tier == RiskLevel.MEDIUM:
            explanation = (
                f"Moderate network anomaly via {detector_triggered}: unusual {proto} communication behavior "
                f"exceeding standard rolling baseline."
            )
            recommended_actions = [
                "Monitor endpoint connection",
                "Inspect process tree for unverified executables",
            ]
        else:
            explanation = "Network flow conforms to standard benign baseline communication patterns."
            recommended_actions = ["No action required; log for audit trail"]

        return UnifiedAnalysisResponse(
            risk_level=risk_tier,
            risk_score=score,
            explanation=explanation,
            signals={
                "user_id": user_id,
                "event_type": event_type,
                "duration_seconds": float(dur),
                "total_bytes": float(tot_bytes),
                "byte_rate": float(byte_rate),
                "protocol": proto,
                "supervised_threat_probability": float(round(prob, 4)),
                "anomaly_score": float(round(norm_anomaly, 4)),
                "is_novel_anomaly": is_anomaly_outlier,
                "detector_triggered": detector_triggered,
                "combination_logic": (
                    "Hybrid detection: Supervised HistGradientBoosting evaluates known C2/botnet vectors; "
                    "IsolationForest baseline flags out-of-distribution protocol or port anomalies."
                ),
                "engine": "System & Network Threat Engine",
            },
            recommended_actions=recommended_actions,
            confidence_score=float(round(max(prob, 1.0 - prob), 4)),
        )

    def save(self, path: Union[str, Path]) -> None:
        """Serializes the model to disk using joblib."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save an unfitted model.")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "NetworkThreatModel":
        """Loads a serialized NetworkThreatModel instance from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"No model checkpoint found at {p}")
        loaded = joblib.load(p)
        if not isinstance(loaded, cls):
            raise TypeError(f"Loaded object is of type {type(loaded)}, expected {cls}")
        return loaded

    def _flow_to_df(self, flow: Dict[str, Any]) -> pd.DataFrame:
        """Converts flow dict (raw, preprocessed, or guard-app telemetry) to single-row DataFrame matching FEATURE_COLUMNS."""
        if not isinstance(flow, dict):
            flow = {}

        if "Dur" in flow or "TotPkts" in flow:
            parsed = parse_flow_record(flow)
            row_dict = {col: parsed.get(col, 0.0) for col in self.feature_columns}
        elif "packet_rate" not in flow or "proto_tcp" not in flow:
            from app.utils.telemetry_adapter import transform_guard_telemetry
            row_dict = transform_guard_telemetry(flow)
        else:
            row_dict = {col: float(flow.get(col, 0.0)) for col in self.feature_columns}
        return pd.DataFrame([row_dict], columns=self.feature_columns)

    def _validate_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Validates and aligns DataFrame columns to exact expected FEATURE_COLUMNS."""
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_columns)

        missing = [col for col in self.feature_columns if col not in X.columns]
        if missing:
            X_copy = X.copy()
            for col in missing:
                X_copy[col] = 0.0
            return X_copy[self.feature_columns].astype(np.float64)

        return X[self.feature_columns].astype(np.float64)
