"""
CYBERGUARD — Phase 6.5 Model Artifact Validation Tests

Verifies all required model artifacts on disk:
- network_threat_model.joblib
- network_anomaly_forest.joblib

For each artifact verifies:
- exists on disk
- loads successfully
- correct model type
- prediction works on sample input
- reload behavior is strictly deterministic
"""

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest

from app.services.network_anomaly.model import NetworkThreatModel
from app.utils.ctu13_preprocessor import FEATURE_COLUMNS


MODELS_DIR = Path(__file__).resolve().parents[1] / "app" / "models"


def test_required_model_artifacts_exist():
    """Verify that all required model artifact files exist on disk."""
    supervised_path = MODELS_DIR / "network_threat_model.joblib"
    anomaly_path = MODELS_DIR / "network_anomaly_forest.joblib"

    assert supervised_path.exists(), f"Missing required artifact: {supervised_path}"
    assert anomaly_path.exists(), f"Missing required artifact: {anomaly_path}"
    assert supervised_path.stat().st_size > 100_000, "Supervised model file is suspiciously small"
    assert anomaly_path.stat().st_size > 50_000, "Anomaly forest file is suspiciously small"


def test_supervised_network_artifact():
    """Verify loading, type, and prediction for network_threat_model.joblib."""
    model_path = MODELS_DIR / "network_threat_model.joblib"
    model = NetworkThreatModel.load(model_path)

    assert isinstance(model, NetworkThreatModel)
    assert model.is_fitted is True

    # Test prediction on dummy valid feature vector
    sample_df = pd.DataFrame([{col: 0.0 for col in FEATURE_COLUMNS}])
    sample_df["dur"] = 1.0
    sample_df["tot_bytes"] = 5000.0
    sample_df["proto_tcp"] = 1.0

    prob1 = model.predict_proba(sample_df)[0]
    assert 0.0 <= prob1 <= 1.0

    # Deterministic reload test
    model_reload = NetworkThreatModel.load(model_path)
    prob2 = model_reload.predict_proba(sample_df)[0]
    assert prob1 == prob2


def test_anomaly_forest_artifact():
    """Verify loading, type, and decision_function for network_anomaly_forest.joblib."""
    anomaly_path = MODELS_DIR / "network_anomaly_forest.joblib"
    anomaly_detector = joblib.load(anomaly_path)

    assert hasattr(anomaly_detector, "decision_function")
    assert hasattr(anomaly_detector, "predict")

    # Test decision function on sample feature vector
    sample_df = pd.DataFrame([{col: 0.0 for col in FEATURE_COLUMNS}])
    sample_df["dur"] = 1.0
    sample_df["tot_bytes"] = 5000.0

    score1 = float(anomaly_detector.decision_function(sample_df)[0])
    assert not np.isnan(score1)

    # Deterministic reload test
    detector_reload = joblib.load(anomaly_path)
    score2 = float(detector_reload.decision_function(sample_df)[0])
    assert score1 == score2
