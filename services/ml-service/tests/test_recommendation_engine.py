"""
Unit, contract, safety, and integration tests for CYBERGUARD Recommendation Engine V1.
Validates model artifact loading, deterministic inference, schema boundaries,
nullable hooks, action safety, and FastAPI endpoint routes.
"""

import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.recommendation import (
    IncidentRecommendationRequest,
    IncidentRecommendationResponse,
    ActionRecommendation,
)
from app.services.recommendation_engine import (
    IncidentFeatureExtractor,
    MLRecommendationRanker,
    ContextualRuleRanker,
    recommend_actions,
    ACTION_CATALOG,
    MODEL_PATH,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_malware_incident():
    return IncidentRecommendationRequest(
        incident_id="inc-malware-001",
        title="Ransomware payload detected on finance workstation",
        severity="critical",
        risk_score=92,
        threat_type="malware",
        entities={
            "hosts": ["FIN-WS-104"],
            "users": ["alice.smith"],
            "ips": ["192.168.10.45", "198.51.100.23"],
            "devices": ["dev-998877"]
        },
        timeline={
            "first_seen": "2026-10-06T12:00:00Z",
            "last_seen": "2026-10-06T12:04:12Z",
            "alert_count": 8,
            "alerts_per_minute": 2.0
        },
        alert_count=8,
        source_engines=["malware", "system_anomaly"],
        alert_types=["pe_suspicious_entropy", "ransomware_canary"],
        mitre_techniques=["T1204", "T1486"],
        mitre_tactics=["TA0002", "TA0040"],
        host_context={"os": "Windows 11", "isolated": False},
        false_positive_score=None  # Nullable by design (Phase 13)
    )


@pytest.fixture
def sample_phishing_incident():
    return IncidentRecommendationRequest(
        incident_id="inc-phish-002",
        title="Executive credential harvesting lure",
        severity="high",
        risk_score=85,
        threat_type="phishing",
        entities={
            "hosts": [],
            "users": ["bob.ceo@enterprise.corp"],
            "ips": ["203.0.113.50"]
        },
        alert_count=3,
        source_engines=["phishing", "url"],
        alert_types=["credential_harvesting_url"],
        mitre_techniques=["T1566", "T1539"],
        mitre_tactics=["TA0001", "TA0006"],
        false_positive_score=None
    )


# 1. Schema instantiation & defaults
def test_schema_instantiation_and_defaults():
    req = IncidentRecommendationRequest(
        incident_id="inc-minimal-001",
        risk_score=50
    )
    assert req.incident_id == "inc-minimal-001"
    assert req.severity == "medium"
    assert req.risk_score == 50
    assert req.false_positive_score is None
    assert req.alert_count == 1
    assert isinstance(req.entities, dict)


# 2. Feature extraction contract
def test_feature_extraction_contract(sample_malware_incident):
    feats = IncidentFeatureExtractor.extract_features(sample_malware_incident)
    assert feats["risk_score_norm"] == 0.92
    assert feats["severity_weight"] == 1.0  # critical
    assert feats["num_hosts"] == 1
    assert feats["num_users"] == 1
    assert feats["num_ips"] == 2
    assert feats["has_malware"] == 1.0
    assert feats["has_phishing"] == 0.0
    assert "T1204" in feats["techniques"]
    assert feats["false_positive_score"] is None


# 3. Model loading test
def test_production_model_loading():
    model = MLRecommendationRanker.load_model()
    assert model is not None, "Failed to load recommendation model artifact"
    assert "vectorizer" in model
    assert "classifier" in model
    assert "action_classes" in model
    assert len(model["action_classes"]) >= 5


# 4. Production artifact hash test
def test_production_artifact_hash():
    assert MODEL_PATH.exists(), f"Model artifact not found at {MODEL_PATH}"
    h = hashlib.sha256()
    with open(MODEL_PATH, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    expected_hash = "ab7344dd10cb62b14358f516ab628dfb5bf57181fe7f3a1119f5c5abe029e01c"
    assert h.hexdigest() == expected_hash, f"Artifact SHA-256 mismatch: {h.hexdigest()}"


# 5. Deterministic inference test
def test_deterministic_inference(sample_malware_incident):
    resp1 = recommend_actions(sample_malware_incident)
    resp2 = recommend_actions(sample_malware_incident)
    assert [r.action for r in resp1.recommendations] == [r.action for r in resp2.recommendations]
    assert [r.score for r in resp1.recommendations] == [r.score for r in resp2.recommendations]


# 6. Null false_positive_score compatibility
def test_null_false_positive_score_compatibility(sample_phishing_incident):
    assert sample_phishing_incident.false_positive_score is None
    resp = recommend_actions(sample_phishing_incident)
    assert isinstance(resp, IncidentRecommendationResponse)
    assert len(resp.recommendations) > 0
    assert resp.status == "PRODUCTION_RECOMMENDATION_ACTIVE"
    assert resp.model_version == "recommendation_v1.0.0"


# 7. False positive discounting on destructive actions
def test_false_positive_discounting_on_destructive_actions(sample_malware_incident):
    resp_base = recommend_actions(sample_malware_incident)
    isolate_base = next(r for r in resp_base.recommendations if r.action == "isolate_device")

    sample_malware_incident.false_positive_score = 0.85
    resp_fp = recommend_actions(sample_malware_incident)
    isolate_fp = next(r for r in resp_fp.recommendations if r.action == "isolate_device")

    assert isolate_fp.score < isolate_base.score


# 8. Action safety and approval enforcement
def test_action_safety_and_approval_enforcement(sample_malware_incident):
    resp = recommend_actions(sample_malware_incident)
    for rec in resp.recommendations:
        assert rec.requires_approval is True
        if rec.action in ["isolate_device", "kill_process", "revoke_session", "force_password_reset", "block_ip", "block_domain"]:
            assert rec.is_destructive is True


# 9. Threat specific rankings
def test_threat_specific_rankings(sample_malware_incident, sample_phishing_incident):
    resp_malware = recommend_actions(sample_malware_incident)
    top_malware_actions = [r.action for r in resp_malware.recommendations[:2]]
    assert "isolate_device" in top_malware_actions or "kill_process" in top_malware_actions

    resp_phish = recommend_actions(sample_phishing_incident)
    top_phish_actions = [r.action for r in resp_phish.recommendations[:2]]
    assert any(a in top_phish_actions for a in ["force_password_reset", "require_mfa", "revoke_session", "block_domain"])


# 10. MITRE mapping and rationale transparency
def test_mitre_mapping_and_rationale_transparency(sample_phishing_incident):
    resp = recommend_actions(sample_phishing_incident)
    top_rec = resp.recommendations[0]
    assert len(top_rec.rationale) > 0
    assert top_rec.confidence >= 0.50


# 11. Pre-filtered candidate actions test
def test_prefiltered_candidate_actions(sample_malware_incident):
    sample_malware_incident.candidate_actions = ["collect_process_tree", "isolate_device"]
    resp = recommend_actions(sample_malware_incident)
    assert len(resp.recommendations) == 2
    actions = [r.action for r in resp.recommendations]
    assert set(actions) == {"collect_process_tree", "isolate_device"}


# 12. Future correlation_id compatibility
def test_future_correlation_id_compatibility(sample_malware_incident):
    sample_malware_incident.correlation_id = "corr-uuid-9988-7766"
    resp = recommend_actions(sample_malware_incident)
    assert isinstance(resp, IncidentRecommendationResponse)
    assert len(resp.recommendations) > 0


# 13. Missing optional fields test
def test_missing_optional_fields():
    req = IncidentRecommendationRequest(
        incident_id="inc-sparse-001",
        risk_score=75,
        threat_type="ddos"
    )
    resp = recommend_actions(req)
    assert resp.incident_id == "inc-sparse-001"
    assert len(resp.recommendations) > 0
    top_actions = [r.action for r in resp.recommendations[:3]]
    assert any(a in top_actions for a in ["block_ip", "isolate_device", "notify_admin"])


# 14. Malformed input API rejection
def test_malformed_input_api_rejection(client):
    res = client.post("/analyze/recommendation", json={"invalid": "payload"})
    assert res.status_code == 422


# 15. FastAPI endpoint integration across all 3 routes
def test_fastapi_endpoint_integration(client, sample_phishing_incident):
    endpoints = [
        "/analyze/recommendation",
        "/internal/analyze/recommendation",
        "/api/v1/analyze/recommendation"
    ]
    payload = sample_phishing_incident.model_dump()

    for ep in endpoints:
        res = client.post(ep, json=payload)
        assert res.status_code == 200, f"{ep} failed with {res.status_code}: {res.text}"
        data = res.json()
        assert data["incident_id"] == "inc-phish-002"
        assert len(data["recommendations"]) > 0
        assert data["status"] == "PRODUCTION_RECOMMENDATION_ACTIVE"
        assert data["model_version"] == "recommendation_v1.0.0"
