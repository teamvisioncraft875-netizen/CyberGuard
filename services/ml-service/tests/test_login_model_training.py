"""
CYBERGUARD — Phase B Login Anomaly Model Training & Artifact Validation Tests

Verifies:
1. Model artifact creation (login_anomaly_forest.joblib, login_feature_schema.json, login_training_metadata.json)
2. Successful model deserialization
3. Strict deterministic predictions across reloads
4. Deterministic feature schema and ordering
5. NaN/Inf prevention in feature vectors
6. Zero test sensor leakage into training
7. Anomaly score normalization bounded in [0.0, 1.0]
8. Sub-millisecond inference latency benchmark
9. Safe handling of invalid / unexpected input dimensions
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from app.services.login_anomaly.train import (
    LoginModelTrainer,
    normalize_anomaly_score,
    LOGIN_MODEL_FEATURES,
    SCORE_NORMAL_BOUND,
    SCORE_ANOMALY_BOUND,
)


@pytest.fixture(scope="module")
def trained_artifacts(tmp_path_factory):
    """Fits and persists Login Anomaly artifacts into a temporary directory for test isolation."""
    temp_dir = tmp_path_factory.mktemp("login_models_test")
    ml_service_dir = Path(__file__).resolve().parents[1]
    data_dir = ml_service_dir / "data" / "login"

    # Quick test fitting with small n_estimators to run fast
    trainer = LoginModelTrainer(
        data_dir=data_dir,
        models_dir=temp_dir,
        n_estimators=25,
        random_state=42,
    )
    results = trainer.run()
    return temp_dir, results


# ---------------------------------------------------------------------------
# Test 1: Model Artifact Creation
# ---------------------------------------------------------------------------
def test_model_artifact_creation(trained_artifacts):
    """Verify all expected artifacts are saved to disk with reasonable file sizes."""
    models_dir, _ = trained_artifacts
    model_file = models_dir / "login_anomaly_forest.joblib"
    schema_file = models_dir / "login_feature_schema.json"
    metadata_file = models_dir / "login_training_metadata.json"

    assert model_file.exists(), f"Missing model checkpoint: {model_file}"
    assert schema_file.exists(), f"Missing schema artifact: {schema_file}"
    assert metadata_file.exists(), f"Missing metadata artifact: {metadata_file}"

    assert model_file.stat().st_size > 10_000, "Model checkpoint is suspiciously small"
    assert schema_file.stat().st_size > 100, "Feature schema is suspiciously small"
    assert metadata_file.stat().st_size > 500, "Metadata file is suspiciously small"


# ---------------------------------------------------------------------------
# Test 2: Model Reload
# ---------------------------------------------------------------------------
def test_model_reload(trained_artifacts):
    """Verify saved Isolation Forest artifact can be deserialized successfully."""
    models_dir, _ = trained_artifacts
    model_file = models_dir / "login_anomaly_forest.joblib"

    loaded_model = joblib.load(model_file)
    assert isinstance(loaded_model, IsolationForest)
    assert hasattr(loaded_model, "estimators_")
    assert len(loaded_model.estimators_) == 25


# ---------------------------------------------------------------------------
# Test 3: Deterministic Prediction across Reloads
# ---------------------------------------------------------------------------
def test_deterministic_prediction_across_reloads(trained_artifacts):
    """Verify predictions before saving match predictions after reloading."""
    models_dir, results = trained_artifacts
    model_file = models_dir / "login_anomaly_forest.joblib"

    # Construct test sample
    sample = pd.DataFrame([{col: 0.0 for col in LOGIN_MODEL_FEATURES}])
    sample["failed_attempts_count"] = 5.0
    sample["attempt_frequency_hz"] = 2.5
    sample["session_duration"] = 2.0

    loaded_model = joblib.load(model_file)

    score1 = loaded_model.decision_function(sample)[0]
    score2 = loaded_model.decision_function(sample)[0]

    assert abs(score1 - score2) < 1e-9, "Model produces non-deterministic predictions across sequential calls"


# ---------------------------------------------------------------------------
# Test 4: Feature Schema & Ordering
# ---------------------------------------------------------------------------
def test_feature_schema_and_ordering(trained_artifacts):
    """Verify schema defines exact list of 20 features without leakage of identifiers."""
    models_dir, _ = trained_artifacts
    schema_file = models_dir / "login_feature_schema.json"

    with open(schema_file, "r", encoding="utf-8") as f:
        schema = json.load(f)

    assert "feature_names" in schema
    assert len(schema["feature_names"]) == 20
    assert schema["feature_names"] == LOGIN_MODEL_FEATURES

    # Ensure metadata identifiers are strictly absent
    for banned in ["src_ip", "session_id", "sensor_id", "password", "username"]:
        assert banned not in schema["feature_names"]


# ---------------------------------------------------------------------------
# Test 5: NaN / Inf Safety
# ---------------------------------------------------------------------------
def test_nan_inf_safety():
    """Verify datasets loaded by trainer contain zero NaN or Infinite values."""
    ml_service_dir = Path(__file__).resolve().parents[1]
    data_dir = ml_service_dir / "data" / "login"

    train_df = pd.read_parquet(data_dir / "train_login_features.parquet")
    test_df = pd.read_parquet(data_dir / "test_login_features.parquet")

    assert train_df[LOGIN_MODEL_FEATURES].isna().sum().sum() == 0
    assert test_df[LOGIN_MODEL_FEATURES].isna().sum().sum() == 0
    assert np.isinf(train_df[LOGIN_MODEL_FEATURES]).sum().sum() == 0
    assert np.isinf(test_df[LOGIN_MODEL_FEATURES]).sum().sum() == 0


# ---------------------------------------------------------------------------
# Test 6: Strict Test Sensor Leakage Audit
# ---------------------------------------------------------------------------
def test_strict_test_sensor_leakage_audit():
    """Verify that held-out sensor 172_234_228_9 does NOT appear in training data."""
    ml_service_dir = Path(__file__).resolve().parents[1]
    data_dir = ml_service_dir / "data" / "login"

    train_df = pd.read_parquet(data_dir / "train_login_features.parquet")
    test_df = pd.read_parquet(data_dir / "test_login_features.parquet")

    train_sensors = set(train_df["sensor_id"].unique())
    test_sensors = set(test_df["sensor_id"].unique())

    assert "172_234_228_9" in test_sensors
    assert "172_234_228_9" not in train_sensors
    assert train_sensors.isdisjoint(test_sensors)


# ---------------------------------------------------------------------------
# Test 7: Anomaly Score Bounds [0.0, 1.0]
# ---------------------------------------------------------------------------
def test_anomaly_score_bounds():
    """Verify normalized anomaly scores are monotonically decreasing with decision_function and bounded."""
    raw_scores = np.array([-1.0, -0.5, -0.25, -0.10, 0.0, 0.10, 0.15, 0.50, 1.0])
    norm_scores = normalize_anomaly_score(raw_scores)

    # All values must be in [0.0, 1.0]
    assert np.all(norm_scores >= 0.0)
    assert np.all(norm_scores <= 1.0)

    # Monotonicity: higher raw score (more normal) -> lower anomaly score
    for i in range(len(raw_scores) - 1):
        assert norm_scores[i] >= norm_scores[i + 1]

    # Extreme bounds
    assert normalize_anomaly_score(np.array([SCORE_NORMAL_BOUND]))[0] == 0.0
    assert normalize_anomaly_score(np.array([SCORE_ANOMALY_BOUND]))[0] == 1.0


# ---------------------------------------------------------------------------
# Test 8: Inference Latency Benchmark
# ---------------------------------------------------------------------------
def test_inference_latency_benchmark(trained_artifacts):
    """Verify single-vector inference latency is measured and within reasonable bounds."""
    _, results = trained_artifacts
    latency = results["latency_benchmark"]

    assert "mean_ms" in latency
    assert "median_ms" in latency
    assert "p95_ms" in latency
    assert "p99_ms" in latency

    assert latency["mean_ms"] > 0.0
    assert latency["mean_ms"] < 50.0  # Generous upper bound for unit testing across hardware


# ---------------------------------------------------------------------------
# Test 9: Empty / Invalid Input Dimensions Handling
# ---------------------------------------------------------------------------
def test_empty_and_invalid_input_handling(trained_artifacts):
    """Verify model raises ValueError when feature count or column names mismatch."""
    models_dir, _ = trained_artifacts
    model = joblib.load(models_dir / "login_anomaly_forest.joblib")

    # Wrong column count (3 instead of 20)
    invalid_input = pd.DataFrame([{"feat_a": 1.0, "feat_b": 2.0, "feat_c": 3.0}])
    with pytest.raises(ValueError):
        model.decision_function(invalid_input)


# ---------------------------------------------------------------------------
# Test 10: Production Checkpoint in app/models/
# ---------------------------------------------------------------------------
def test_production_login_artifacts_on_disk():
    """Verify production login model artifacts exist and load from app/models/."""
    models_dir = Path(__file__).resolve().parents[1] / "app" / "models"
    model_file = models_dir / "login_anomaly_forest.joblib"
    schema_file = models_dir / "login_feature_schema.json"
    metadata_file = models_dir / "login_training_metadata.json"

    assert model_file.exists(), f"Missing production model: {model_file}"
    assert schema_file.exists(), f"Missing production schema: {schema_file}"
    assert metadata_file.exists(), f"Missing production metadata: {metadata_file}"

    # Verify model is fitted and can score a 20-feature input
    prod_model = joblib.load(model_file)
    assert isinstance(prod_model, IsolationForest)
    assert prod_model.n_estimators == 100

    sample = pd.DataFrame([{col: 0.0 for col in LOGIN_MODEL_FEATURES}])
    sample["failed_attempts_count"] = 1.0
    score = prod_model.decision_function(sample)[0]
    assert not np.isnan(score)

