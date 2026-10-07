"""
Unit, contract, safety, and integration tests for CYBERGUARD Correlation Engine V1.
Validates model artifact loading, pairwise feature extraction, graph clustering,
Recommendation V1 compatibility, and FastAPI endpoints.
"""

import hashlib
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.correlation import (
    AlertEvent,
    CorrelationRequest,
    CorrelationResponse,
    CorrelatedIncident,
)
from app.services.correlation_engine import (
    CorrelationFeatureExtractor,
    IncidentCorrelationEngine,
    correlate_events,
    MODEL_PATH,
)
from app.services.recommendation_engine import recommend_actions


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_botnet_alerts():
    base_time = datetime(2026, 10, 6, 14, 0, 0)
    return [
        AlertEvent(
            alert_id="alt-001",
            timestamp=(base_time + timedelta(seconds=10)).isoformat(),
            src_ip="147.32.84.165",
            dst_ip="147.32.80.9",
            sport=1045,
            dport=53,
            proto="udp",
            attack_type="dns_query",
            mitre_tactic="TA0011",
            mitre_technique="T1071.004",
            severity="medium",
            risk_score=55.0,
            host="WS-165",
        ),
        AlertEvent(
            alert_id="alt-002",
            timestamp=(base_time + timedelta(seconds=45)).isoformat(),
            src_ip="147.32.84.165",
            dst_ip="194.85.105.17",
            sport=1046,
            dport=80,
            proto="tcp",
            attack_type="c2_beacon",
            mitre_tactic="TA0011",
            mitre_technique="T1071",
            severity="critical",
            risk_score=90.0,
            host="WS-165",
        ),
        AlertEvent(
            alert_id="alt-003",
            timestamp=(base_time + timedelta(seconds=120)).isoformat(),
            src_ip="147.32.84.165",
            dst_ip="193.232.128.6",
            sport=1048,
            dport=25,
            proto="tcp",
            attack_type="spam_propagation",
            mitre_tactic="TA0001",
            mitre_technique="T1566",
            severity="high",
            risk_score=75.0,
            host="WS-165",
        ),
        # Unrelated background alert on separate IP and network
        AlertEvent(
            alert_id="alt-bg-001",
            timestamp=(base_time + timedelta(seconds=200)).isoformat(),
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            sport=54321,
            dport=8080,
            proto="tcp",
            attack_type="benign_dns",
            mitre_tactic="TA0000",
            mitre_technique="T0000",
            severity="low",
            risk_score=15.0,
            host="SRV-BENIGN",
        ),
    ]


# 1. Schema instantiation & defaults
def test_correlation_schema_instantiation():
    req = CorrelationRequest(
        alerts=[
            AlertEvent(alert_id="alt-1", src_ip="192.168.1.5", dst_ip="10.0.0.1")
        ]
    )
    assert len(req.alerts) == 1
    assert req.time_window_seconds == 3600.0
    assert req.correlation_threshold == 0.50
    assert req.false_positive_score is None


# 2. Model loading test
def test_production_correlation_model_loading():
    model = IncidentCorrelationEngine.load_model()
    assert model is not None, "Failed to load correlation model artifact"
    assert "classifier" in model
    assert "feature_names" in model
    assert model["model_version"] == "v1.0.0"


# 3. Production artifact hash test
def test_production_correlation_artifact_hash():
    assert MODEL_PATH.exists(), f"Model artifact not found at {MODEL_PATH}"
    h = hashlib.sha256()
    with open(MODEL_PATH, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    expected_hash = "0967507df831d08bee01649e5ad35a79fcb96d3330a0c2f6e7f58291843af019"
    assert h.hexdigest() == expected_hash, f"Artifact SHA-256 mismatch: {h.hexdigest()}"


# 4. Feature extraction contract
def test_pairwise_feature_extraction(sample_botnet_alerts):
    a1 = sample_botnet_alerts[0]
    a2 = sample_botnet_alerts[1]
    feats = CorrelationFeatureExtractor.extract_pair_features(a1, a2)
    assert len(feats) == 12
    # Same source IP (147.32.84.165)
    assert feats[2] == 1.0  # same_src
    assert feats[4] == 1.0  # shared_ip
    # Temporal decay within 35 seconds
    assert feats[1] > 0.90  # time_decay
    assert feats[8] == 1.0  # both_attack


# 5. Timestamp parsing flexibility
def test_timestamp_parsing_flexibility():
    dt1 = CorrelationFeatureExtractor.parse_datetime("2026-10-06T14:30:00Z")
    assert isinstance(dt1, datetime)
    dt2 = CorrelationFeatureExtractor.parse_datetime("2026/10/06 14:30:00.123456")
    assert isinstance(dt2, datetime)
    dt3 = CorrelationFeatureExtractor.parse_datetime(datetime(2026, 10, 6))
    assert dt3.year == 2026


# 6. Alert grouping / clustering test
def test_alert_grouping_and_clustering(sample_botnet_alerts):
    req = CorrelationRequest(alerts=sample_botnet_alerts)
    resp = IncidentCorrelationEngine.correlate_alerts(req)

    assert isinstance(resp, CorrelationResponse)
    assert resp.status == "CORRELATION_SUCCESS"
    assert resp.model_version == "correlation_v1.0.0"
    assert len(resp.incidents) >= 1

    # Primary incident should cluster the related botnet alerts
    primary = resp.incidents[0]
    assert primary.alert_count >= 2
    assert "alt-001" in primary.correlated_alert_ids or "alt-002" in primary.correlated_alert_ids
    assert "147.32.84.165" in primary.entities["ips"]


# 7. Deterministic behavior test
def test_deterministic_correlation(sample_botnet_alerts):
    req = CorrelationRequest(alerts=sample_botnet_alerts)
    resp1 = IncidentCorrelationEngine.correlate_alerts(req)
    resp2 = IncidentCorrelationEngine.correlate_alerts(req)

    assert resp1.confidence == resp2.confidence
    assert len(resp1.incidents) == len(resp2.incidents)
    assert resp1.incidents[0].correlated_alert_ids == resp2.incidents[0].correlated_alert_ids


# 8. Empty alerts handling test
def test_empty_alerts_handling():
    req = CorrelationRequest(alerts=[])
    resp = IncidentCorrelationEngine.correlate_alerts(req)
    assert resp.status == "NO_ALERTS_PROVIDED"
    assert len(resp.incidents) == 0
    assert resp.timeline["alert_count"] == 0


# 9. Single alert handling test
def test_single_alert_handling(sample_botnet_alerts):
    req = CorrelationRequest(alerts=[sample_botnet_alerts[0]])
    resp = IncidentCorrelationEngine.correlate_alerts(req)
    assert resp.status == "CORRELATION_SUCCESS"
    assert len(resp.incidents) == 1
    assert resp.incidents[0].alert_count == 1


# 10. Unknown fields tolerance test
def test_unknown_fields_tolerance():
    raw_dict = {
        "alert_id": "alt-extra-1",
        "timestamp": "2026-10-06T15:00:00Z",
        "custom_siem_field": "some_value",
        "sensor_id": 9999
    }
    alert = AlertEvent(**raw_dict)
    assert alert.alert_id == "alt-extra-1"


# 11. Recommendation V1 compatibility integration test
def test_recommendation_v1_compatibility(sample_botnet_alerts):
    req = CorrelationRequest(alerts=sample_botnet_alerts)
    corr_resp = IncidentCorrelationEngine.correlate_alerts(req)
    assert len(corr_resp.incidents) > 0

    primary_inc = corr_resp.incidents[0]
    rec_req = IncidentCorrelationEngine.to_recommendation_request(primary_inc)

    # Validate feeding directly into Recommendation V1 engine
    rec_resp = recommend_actions(rec_req)
    assert rec_resp.incident_id == primary_inc.incident_id
    assert rec_resp.model_version == "recommendation_v1.0.0"
    assert len(rec_resp.recommendations) > 0
    assert rec_resp.recommendations[0].requires_approval is True


# 12. Null false_positive_score compatibility
def test_null_false_positive_score_compatibility(sample_botnet_alerts):
    req = CorrelationRequest(alerts=sample_botnet_alerts, false_positive_score=None)
    resp = correlate_events(req)
    assert resp.status == "CORRELATION_SUCCESS"


# 13. Malformed input API rejection
def test_malformed_input_api_rejection(client):
    res = client.post("/analyze/correlation", json={"alerts": "not-a-list"})
    assert res.status_code == 422


# 14. FastAPI endpoint integration across all 3 routes
def test_fastapi_endpoint_integration(client, sample_botnet_alerts):
    endpoints = [
        "/analyze/correlation",
        "/internal/analyze/correlation",
        "/api/v1/analyze/correlation"
    ]
    payload = {
        "alerts": [a.model_dump() for a in sample_botnet_alerts],
        "correlation_threshold": 0.50
    }

    for ep in endpoints:
        res = client.post(ep, json=payload)
        assert res.status_code == 200, f"{ep} failed with {res.status_code}: {res.text}"
        data = res.json()
        assert "correlation_id" in data
        assert "incident_id" in data
        assert data["status"] == "CORRELATION_SUCCESS"
        assert len(data["incidents"]) >= 1
        assert "entities" in data
        assert "timeline" in data
        assert "mitre_tactics" in data
