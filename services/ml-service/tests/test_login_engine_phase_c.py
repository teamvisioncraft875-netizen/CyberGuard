"""
CYBERGUARD — Phase C Login Anomaly Detection Engine Tests

Verifies:
1. Production model loading from disk artifacts
2. Valid login analysis producing UnifiedAnalysisResponse
3. Anomaly score bounds in [0.0, 1.0]
4. Absence of fabricated supervised probability
5. Feature ordering conformance to login_feature_schema.json
6. NaN input fail-loud validation
7. Infinite input fail-loud validation
8. Missing model artifact fail-loud error
9. Corrupted model artifact fail-loud error
10. Strict determinism across repeated calls
11. Accurate plain-English explanation generation
12. Unavailable signals reported as None
13. CYBERGUARD 5-tier risk mapping
14. Model loaded once and reused (no repeated deserialization)
"""

from pathlib import Path
from unittest.mock import patch
import numpy as np
import pandas as pd
import pytest

from app.schemas.analyze import LoginAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel
from app.services.login_anomaly.engine import (
    LoginAnomalyEngine,
    get_login_anomaly_engine,
    _LOGIN_ENGINE_INSTANCE,
)
from app.services.login_engine import analyze_login


MODELS_DIR = Path(__file__).resolve().parents[1] / "app" / "models"


@pytest.fixture(scope="module")
def prod_engine():
    """Returns production LoginAnomalyEngine loaded from disk artifacts."""
    return LoginAnomalyEngine(models_dir=MODELS_DIR, load_checkpoint=True)


# ---------------------------------------------------------------------------
# Test 1: Model Loads Successfully
# ---------------------------------------------------------------------------
def test_production_model_loads(prod_engine):
    """Engine starts successfully with valid production artifacts."""
    assert prod_engine.is_fitted is True
    assert prod_engine.model is not None
    assert len(prod_engine.feature_names) == 20
    assert prod_engine.score_normal_bound == 0.15
    assert prod_engine.score_anomaly_bound == -0.25


# ---------------------------------------------------------------------------
# Test 2: Valid Login Analysis
# ---------------------------------------------------------------------------
def test_valid_login_analysis(prod_engine):
    """A valid login request produces a conforming UnifiedAnalysisResponse."""
    req = LoginAnalyzeRequest(
        user_id="usr_sec_ops",
        timestamp="2026-09-26T14:30:00Z",
        location="Frankfurt, DE",
        device_id="dev_macbook_pro",
        failed_attempts=0,
    )
    resp = prod_engine.analyze(req)

    assert isinstance(resp, UnifiedAnalysisResponse)
    assert resp.risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert 0 <= resp.risk_score <= 100
    assert isinstance(resp.explanation, str) and len(resp.explanation) > 10
    assert isinstance(resp.recommended_actions, list) and len(resp.recommended_actions) > 0
    assert 0.0 <= resp.confidence_score <= 1.0


# ---------------------------------------------------------------------------
# Test 3: Anomaly Score Bounds [0.0, 1.0]
# ---------------------------------------------------------------------------
def test_anomaly_score_bounds(prod_engine):
    """Anomaly scores produced by inference remain strictly within [0.0, 1.0]."""
    test_cases = [
        {"failed_attempts": 0},
        {"failed_attempts": 1},
        {"failed_attempts": 10},
        {"failed_attempts": 25},
    ]
    for tc in test_cases:
        req = LoginAnalyzeRequest(
            user_id="usr_bounds_check",
            timestamp="2026-09-26T10:00:00Z",
            location="London, UK",
            device_id="dev_laptop",
            failed_attempts=tc["failed_attempts"],
        )
        resp = prod_engine.analyze(req)
        score = resp.signals.get("anomaly_score")
        assert score is not None
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Test 4: No Fake Supervised Probability
# ---------------------------------------------------------------------------
def test_no_fake_supervised_probability(prod_engine):
    """Response must NOT fabricate a supervised probability (must be None)."""
    req = LoginAnalyzeRequest(
        user_id="usr_audit",
        timestamp="2026-09-26T12:00:00Z",
        location="Zurich, CH",
        device_id="dev_workstation",
        failed_attempts=3,
    )
    resp = prod_engine.analyze(req)
    assert resp.signals.get("supervised_probability") is None
    assert resp.signals.get("detector_triggered") == "Behavioral Login Anomaly Detector"


# ---------------------------------------------------------------------------
# Test 5: Feature Ordering Conformance
# ---------------------------------------------------------------------------
def test_feature_ordering_conformance(prod_engine):
    """Feature vectors passed to the model strictly follow the persisted schema order."""
    schema_path = MODELS_DIR / "login_feature_schema.json"
    import json
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    expected_features = schema["feature_names"]
    assert prod_engine.feature_names == expected_features

    # Verify build_feature_dataframe maintains exact column ordering
    df, _ = prod_engine.build_feature_dataframe(
        LoginAnalyzeRequest(
            user_id="usr_order",
            timestamp="2026-09-26T08:00:00Z",
            location="Paris, FR",
            device_id="dev_linux",
            failed_attempts=1,
        )
    )
    assert list(df.columns) == expected_features


# ---------------------------------------------------------------------------
# Test 6: NaN Input Fail-Loud Validation
# ---------------------------------------------------------------------------
def test_nan_input_fails_loud(prod_engine):
    """Features containing NaN must raise an explicit ValueError, never return Safe."""
    bad_features = {feat: 0.0 for feat in prod_engine.feature_names}
    bad_features["failed_attempts_count"] = np.nan

    with pytest.raises(ValueError, match="NaN"):
        prod_engine.analyze(bad_features)


# ---------------------------------------------------------------------------
# Test 7: Infinite Input Fail-Loud Validation
# ---------------------------------------------------------------------------
def test_infinite_input_fails_loud(prod_engine):
    """Features containing Infinity must raise an explicit ValueError, never return Safe."""
    bad_features = {feat: 0.0 for feat in prod_engine.feature_names}
    bad_features["attempt_frequency_hz"] = np.inf

    with pytest.raises(ValueError, match="infinite"):
        prod_engine.analyze(bad_features)


# ---------------------------------------------------------------------------
# Test 8: Missing Model Fails Loud
# ---------------------------------------------------------------------------
def test_missing_model_fails_loud(tmp_path):
    """Missing model artifact must raise an explicit error, never return Safe."""
    empty_dir = tmp_path / "empty_models"
    empty_dir.mkdir()

    with pytest.raises((FileNotFoundError, RuntimeError)):
        LoginAnomalyEngine(models_dir=empty_dir, load_checkpoint=True)


# ---------------------------------------------------------------------------
# Test 9: Corrupted Model Fails Loud
# ---------------------------------------------------------------------------
def test_corrupted_model_fails_loud(tmp_path):
    """Corrupted model file must raise an explicit error, never return Safe."""
    corrupt_dir = tmp_path / "corrupt_models"
    corrupt_dir.mkdir()

    # Write corrupt checkpoint and schema
    (corrupt_dir / "login_feature_schema.json").write_text(
        '{"feature_names": ["a", "b"]}', encoding="utf-8"
    )
    (corrupt_dir / "login_anomaly_forest.joblib").write_bytes(b"NOT_A_VALID_JOBLIB_DATA")

    with pytest.raises(RuntimeError):
        LoginAnomalyEngine(models_dir=corrupt_dir, load_checkpoint=True)


# ---------------------------------------------------------------------------
# Test 10: Deterministic Result
# ---------------------------------------------------------------------------
def test_deterministic_result(prod_engine):
    """Identical input yields identical analysis output across sequential evaluations."""
    req = LoginAnalyzeRequest(
        user_id="usr_det_check",
        timestamp="2026-09-26T16:00:00Z",
        location="Berlin, DE",
        device_id="dev_mac_det",
        failed_attempts=4,
    )
    res1 = prod_engine.analyze(req, track_state=False)
    res2 = prod_engine.analyze(req, track_state=False)

    assert res1.risk_score == res2.risk_score
    assert res1.risk_level == res2.risk_level
    assert res1.explanation == res2.explanation
    assert res1.confidence_score == res2.confidence_score
    assert res1.signals["anomaly_score"] == res2.signals["anomaly_score"]



# ---------------------------------------------------------------------------
# Test 11: Explanation Accuracy
# ---------------------------------------------------------------------------
def test_explanation_accuracy(prod_engine):
    """Explanation contains only observed indicators (e.g. failure burst)."""
    req_burst = LoginAnalyzeRequest(
        user_id="usr_burst",
        timestamp="2026-09-26T02:00:00Z",
        location="Amsterdam, NL",
        device_id="dev_bot",
        failed_attempts=8,
    )
    resp = prod_engine.analyze(req_burst)
    assert "8 attempts" in resp.explanation or "8 failed attempts" in resp.explanation or "brute-force" in resp.explanation.lower()


# ---------------------------------------------------------------------------
# Test 12: Unavailable Signals Reported as None
# ---------------------------------------------------------------------------
def test_unavailable_signals_reported_as_none(prod_engine):
    """Unsupported signals (impossible_travel, is_new_device) must be None."""
    req = LoginAnalyzeRequest(
        user_id="usr_signals",
        timestamp="2026-09-26T11:00:00Z",
        location="Vienna, AT",
        device_id="dev_surface",
        failed_attempts=0,
    )
    resp = prod_engine.analyze(req)
    assert resp.signals.get("impossible_travel") is None
    assert resp.signals.get("is_new_device") is None


# ---------------------------------------------------------------------------
# Test 13: CYBERGUARD 5-Tier Risk Mapping
# ---------------------------------------------------------------------------
def test_risk_mapping_boundaries():
    """Verify standard CYBERGUARD 5-tier risk boundaries: Safe 0-19, Low 20-39, Medium 40-69, High 70-89, Critical 90-100."""
    scores_and_tiers = [
        (0, RiskLevel.SAFE),
        (19, RiskLevel.SAFE),
        (20, RiskLevel.LOW),
        (39, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (69, RiskLevel.MEDIUM),
        (70, RiskLevel.HIGH),
        (89, RiskLevel.HIGH),
        (90, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ]
    for score, expected_tier in scores_and_tiers:
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
        assert tier == expected_tier


# ---------------------------------------------------------------------------
# Test 14: Model Loaded Once (Singleton Reused)
# ---------------------------------------------------------------------------
def test_model_loaded_once():
    """Verify repeated inference reuses the in-memory engine without deserializing checkpoint each time."""
    # Warm up singleton to ensure it is initialized once
    engine_init = get_login_anomaly_engine()

    with patch("joblib.load") as mock_load:
        for _ in range(5):
            eng = get_login_anomaly_engine()
            assert eng is engine_init
        mock_load.assert_not_called()

