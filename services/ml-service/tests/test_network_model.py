import pytest
import tempfile
from pathlib import Path
import pandas as pd
import numpy as np

# TDD Step 3.1: This will fail until NetworkThreatModel is implemented in Step 3.2
from app.services.network_anomaly.model import NetworkThreatModel
from app.utils.ctu13_preprocessor import FEATURE_COLUMNS
from app.schemas.analyze import UnifiedAnalysisResponse, RiskLevel


# Small representative 4-sample fixture (2 botnet, 2 benign)
FIXTURE_FLOWS = pd.DataFrame(
    [
        # Sample 1: High-volume botnet flood
        {
            "dur": 0.05,
            "tot_pkts": 500.0,
            "tot_bytes": 600000.0,
            "src_bytes": 580000.0,
            "packet_rate": 10000.0,
            "byte_rate": 12000000.0,
            "avg_packet_size": 1200.0,
            "src_byte_ratio": 0.96,
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "proto_other": 0,
            "is_well_known_dport": 0,
            "is_bidirectional": 0,
            "is_threat": 1,
        },
        # Sample 2: Persistent C2 Beacon
        {
            "dur": 120.0,
            "tot_pkts": 60.0,
            "tot_bytes": 4800.0,
            "src_bytes": 2400.0,
            "packet_rate": 0.5,
            "byte_rate": 40.0,
            "avg_packet_size": 80.0,
            "src_byte_ratio": 0.5,
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "proto_other": 0,
            "is_well_known_dport": 0,
            "is_bidirectional": 1,
            "is_threat": 1,
        },
        # Sample 3: Benign standard web browsing (HTTP/HTTPS)
        {
            "dur": 2.5,
            "tot_pkts": 15.0,
            "tot_bytes": 4500.0,
            "src_bytes": 1200.0,
            "packet_rate": 6.0,
            "byte_rate": 1800.0,
            "avg_packet_size": 300.0,
            "src_byte_ratio": 0.26,
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "proto_other": 0,
            "is_well_known_dport": 1,
            "is_bidirectional": 1,
            "is_threat": 0,
        },
        # Sample 4: Benign DNS query/response
        {
            "dur": 0.02,
            "tot_pkts": 2.0,
            "tot_bytes": 150.0,
            "src_bytes": 60.0,
            "packet_rate": 100.0,
            "byte_rate": 7500.0,
            "avg_packet_size": 75.0,
            "src_byte_ratio": 0.4,
            "proto_tcp": 0,
            "proto_udp": 1,
            "proto_icmp": 0,
            "proto_other": 0,
            "is_well_known_dport": 1,
            "is_bidirectional": 1,
            "is_threat": 0,
        },
    ]
)


def test_parquet_datasets_exist_and_contract_valid():
    """Verify train and test parquet datasets generated in Phase 2 exist and conform to schema."""
    ml_service_dir = Path(__file__).resolve().parents[1]
    train_parquet = ml_service_dir / "data" / "ctu13" / "train_features.parquet"
    test_parquet = ml_service_dir / "data" / "ctu13" / "test_features.parquet"

    assert train_parquet.exists(), f"Missing train parquet at {train_parquet}"
    assert test_parquet.exists(), f"Missing test parquet at {test_parquet}"

    df_train = pd.read_parquet(train_parquet)
    df_test = pd.read_parquet(test_parquet)

    # Check required columns
    for col in FEATURE_COLUMNS:
        assert col in df_train.columns
        assert col in df_test.columns

    assert "is_threat" in df_train.columns
    assert "is_threat" in df_test.columns
    assert len(df_train) > 100000
    assert len(df_test) > 10000


def test_network_model_training_on_fixture():
    """Verify model fits cleanly on a feature matrix fixture."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    assert not model.is_fitted
    model.fit(X, y)
    assert model.is_fitted


def test_network_model_deterministic_predictions():
    """Verify deterministic predictions across repeated calls."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    prob1 = model.predict_proba(X)
    prob2 = model.predict_proba(X)
    np.testing.assert_allclose(prob1, prob2)


def test_network_model_probability_and_risk_range():
    """Verify probability is in [0, 1] and calibrated risk score in [0, 100]."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    probs = model.predict_proba(X)
    assert np.all(probs >= 0.0)
    assert np.all(probs <= 1.0)

    for i in range(len(X)):
        score, risk_tier = model.score_flow(X.iloc[i].to_dict())
        assert 0 <= score <= 100
        assert isinstance(risk_tier, RiskLevel)


def test_normal_vs_botnet_differential():
    """Verify threat flow receives higher risk score than benign web traffic."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    botnet_score, botnet_tier = model.score_flow(X.iloc[0].to_dict())
    benign_score, benign_tier = model.score_flow(X.iloc[2].to_dict())

    assert botnet_score > benign_score


def test_network_model_serialization_and_consistency():
    """Verify model can be saved to disk, reloaded, and produces identical predictions."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)
    probs_orig = model.predict_proba(X)

    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        model.save(tmp_path)
        assert tmp_path.exists()
        assert tmp_path.stat().st_size > 0

        reloaded_model = NetworkThreatModel.load(tmp_path)
        assert reloaded_model.is_fitted
        probs_reloaded = reloaded_model.predict_proba(X)

        np.testing.assert_allclose(probs_orig, probs_reloaded)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_missing_features_handled_safely():
    """Verify dict with missing/partial keys defaults gracefully without crashing."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    score, tier = model.score_flow({"dur": 1.0, "tot_bytes": 500})
    assert 0 <= score <= 100
    assert isinstance(tier, RiskLevel)


def test_unified_response_contract_compliance():
    """Verify analyze_flow returns strict UnifiedAnalysisResponse conforming to API contract."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    response = model.analyze_flow(
        user_id="usr_test_network",
        event_type="network_flow",
        flow_details=X.iloc[0].to_dict(),
    )

    assert isinstance(response, UnifiedAnalysisResponse)
    assert response.risk_score >= 0 and response.risk_score <= 100
    assert isinstance(response.risk_level, RiskLevel)
    assert len(response.explanation) > 10
    assert isinstance(response.recommended_actions, list)
    assert 0.0 <= response.confidence_score <= 1.0


def test_network_model_threshold_behavior():
    """Verify deterministic and monotonic threshold behavior across probability spectrum."""
    X = FIXTURE_FLOWS[FEATURE_COLUMNS]
    y = FIXTURE_FLOWS["is_threat"]

    model = NetworkThreatModel(random_state=42)
    model.fit(X, y)

    # 1. Determinism
    pred_a = model.predict(X, threshold=0.4)
    pred_b = model.predict(X, threshold=0.4)
    np.testing.assert_array_equal(pred_a, pred_b)

    # 2. Monotonicity across thresholds
    thresholds = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    pos_counts = [int(np.sum(model.predict(X, threshold=t))) for t in thresholds]
    for i in range(len(pos_counts) - 1):
        assert pos_counts[i] >= pos_counts[i + 1], f"Threshold monotonicity violated at step {i}: {pos_counts}"

    # 3. Boundaries
    all_positive = model.predict(X, threshold=0.0)
    assert np.all(all_positive == 1)

    beyond_max = model.predict(X, threshold=1.01)
    assert np.all(beyond_max == 0)
