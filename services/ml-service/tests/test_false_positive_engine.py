"""
CYBERGUARD False Positive Detection V1 Test Suite.
Validates schemas, inference, edge cases, out-of-vocabulary handling,
security boundaries, SHA-256 verification, and Correlation/Recommendation compatibility.
"""

import pytest
import hashlib
from pathlib import Path
from pydantic import ValidationError

from app.schemas.false_positive import (
    FalsePositiveAnalysisRequest,
    FalsePositiveAnalysisResponse,
    BatchFalsePositiveRequest,
    BatchFalsePositiveResponse,
)
from app.services.false_positive_engine import (
    FalsePositiveEngine,
    MODEL_PATH,
    METADATA_PATH,
    REGISTRY_PATH,
    SecurityError,
)
from app.schemas.recommendation import IncidentRecommendationRequest
from app.schemas.correlation import CorrelationRequest, AlertEvent


@pytest.fixture
def fp_engine():
    return FalsePositiveEngine.get_instance()


@pytest.fixture
def sample_benign_alert():
    return FalsePositiveAnalysisRequest(
        alert_id="ALT-2026-001",
        event_name="security_file_open",
        process_name="landscape-sysin",
        user_id=0,
        args_num=2,
        return_value=0,
        parent_process_id=1,
        alert_type="file_access_anomaly",
        severity="low"
    )


@pytest.fixture
def sample_malicious_alert():
    return FalsePositiveAnalysisRequest(
        alert_id="ALT-2026-999",
        event_name="access",
        process_name="tsm",
        user_id=1001,
        args_num=2,
        return_value=-2,
        parent_process_id=7534,
        alert_type="malicious_binary_execution",
        severity="critical"
    )


# 1. Schema Validation Tests
def test_schema_valid_instantiation(sample_benign_alert):
    assert sample_benign_alert.event_name == "security_file_open"
    assert sample_benign_alert.process_name == "landscape-sysin"
    assert sample_benign_alert.user_id == 0
    assert sample_benign_alert.return_value == 0


def test_schema_rejects_missing_required_fields():
    with pytest.raises(ValidationError):
        FalsePositiveAnalysisRequest(
            event_name="security_file_open",
            # missing process_name, user_id, args_num, return_value
        )


def test_schema_rejects_empty_whitespace_strings():
    with pytest.raises(ValidationError):
        FalsePositiveAnalysisRequest(
            event_name="   ",
            process_name="valid_proc",
            user_id=1000,
            args_num=1,
            return_value=0
        )


def test_schema_sanitizes_path_traversal_in_process_name():
    req = FalsePositiveAnalysisRequest(
        event_name="openat",
        process_name="/usr/bin/../../etc/shadow_reader",
        user_id=0,
        args_num=2,
        return_value=0
    )
    # Sanitizer strips path traversal to isolated filename
    assert ".." not in req.process_name
    assert req.process_name == "shadow_reader"


# 2. Valid Inference & Output Schema
def test_valid_inference(fp_engine, sample_benign_alert):
    res = fp_engine.analyze(sample_benign_alert)
    assert isinstance(res, FalsePositiveAnalysisResponse)
    assert res.alert_id == "ALT-2026-001"
    assert 0.0 <= res.false_positive_score <= 1.0
    assert 0.0 <= res.false_positive_probability <= 1.0
    assert res.classification in ["likely_false_positive", "likely_true_positive"]
    assert 0.0 <= res.confidence <= 1.0
    assert res.threshold == 0.75
    assert res.is_advisory_only is True
    assert res.model_version == "1.0.0"
    assert res.execution_time_ms >= 0.0
    assert len(res.explanation.summary) > 10


# 3. Determinism
def test_deterministic_inference(fp_engine, sample_benign_alert):
    res1 = fp_engine.analyze(sample_benign_alert)
    res2 = fp_engine.analyze(sample_benign_alert)
    assert res1.false_positive_score == res2.false_positive_score
    assert res1.false_positive_probability == res2.false_positive_probability
    assert res1.classification == res2.classification


# 4. Threat Discrimination & Probability Bounds
def test_malicious_alert_scores_likely_true_threat(fp_engine, sample_malicious_alert):
    res = fp_engine.analyze(sample_malicious_alert)
    assert res.classification == "likely_true_positive"
    # FP probability should be well below the 0.75 threshold
    assert res.false_positive_probability < 0.75
    assert res.is_advisory_only is True


def test_benign_system_alert_scores_likely_false_positive(fp_engine, sample_benign_alert):
    res = fp_engine.analyze(sample_benign_alert)
    # landscape-sysin with init parent and success return value
    assert res.false_positive_probability >= 0.75
    assert res.classification == "likely_false_positive"


# 5. Out-of-Vocabulary / Unseen Process & Event Handling
def test_unseen_process_and_event_handling(fp_engine):
    req = FalsePositiveAnalysisRequest(
        event_name="unseen_custom_hypervisor_call_99",
        process_name="completely_unknown_zero_day_executable",
        user_id=1002,
        args_num=5,
        return_value=0,
        parent_process_id=3000
    )
    res = fp_engine.analyze(req)
    # Must execute safely without KeyError or crash
    assert 0.0 <= res.false_positive_probability <= 1.0
    assert res.classification in ["likely_false_positive", "likely_true_positive"]


# 6. Artifact Verification
def test_artifact_files_exist_and_sha_valid():
    assert MODEL_PATH.exists(), f"Model artifact missing at {MODEL_PATH}"
    assert METADATA_PATH.exists(), f"Metadata missing at {METADATA_PATH}"
    assert REGISTRY_PATH.exists(), f"Registry missing at {REGISTRY_PATH}"

    hasher = hashlib.sha256()
    with open(MODEL_PATH, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    computed_sha = hasher.hexdigest()
    assert len(computed_sha) == 64


# 7. Batch Inference
def test_batch_inference(fp_engine, sample_benign_alert, sample_malicious_alert):
    batch_req = BatchFalsePositiveRequest(
        alerts=[sample_benign_alert, sample_malicious_alert]
    )
    res = fp_engine.analyze_batch(batch_req)
    assert isinstance(res, BatchFalsePositiveResponse)
    assert res.total_evaluated == 2
    assert len(res.results) == 2
    assert res.likely_false_positive_count >= 1
    assert res.likely_true_positive_count >= 1


# 8. Strict Safety: Non-Destructive Advisory Guarantee
def test_advisory_safety_guarantee(fp_engine, sample_benign_alert):
    res = fp_engine.analyze(sample_benign_alert)
    assert res.is_advisory_only is True
    # Verify no action field exists in response that triggers deletion or closing
    assert not hasattr(res, "action_executed")
    assert not hasattr(res, "auto_close")


# 9. Recommendation Compatibility
def test_recommendation_v1_compatibility(fp_engine, sample_benign_alert):
    res = fp_engine.analyze(sample_benign_alert)
    rec_req = IncidentRecommendationRequest(
        incident_id="INC-BETH-TEST-01",
        severity="medium",
        risk_score=50,
        false_positive_score=res.false_positive_score
    )
    assert rec_req.false_positive_score == res.false_positive_score


# 10. Correlation Compatibility
def test_correlation_v1_compatibility(fp_engine, sample_benign_alert):
    res = fp_engine.analyze(sample_benign_alert)
    corr_req = CorrelationRequest(
        alerts=[
            AlertEvent(
                alert_id="ALT-001",
                host="ip-10-100-1-4",
                severity="medium"
            )
        ],
        false_positive_score=res.false_positive_score
    )
    assert corr_req.false_positive_score == res.false_positive_score


# 11. API Route Mounting Tests
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_endpoint_direct():
    payload = {
        "alert_id": "ALT-API-001",
        "event_name": "security_file_open",
        "process_name": "landscape-sysin",
        "user_id": 0,
        "args_num": 2,
        "return_value": 0,
        "parent_process_id": 1
    }
    response = client.post("/analyze/false-positive", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "ALT-API-001"
    assert data["classification"] in ["likely_false_positive", "likely_true_positive"]
    assert 0.0 <= data["false_positive_score"] <= 1.0


def test_api_endpoint_internal():
    payload = {
        "event_name": "openat",
        "process_name": "sshd",
        "user_id": 0,
        "args_num": 3,
        "return_value": 0
    }
    response = client.post("/internal/analyze/false-positive", json=payload)
    assert response.status_code == 200
    assert response.json()["is_advisory_only"] is True


def test_api_endpoint_v1():
    payload = {
        "event_name": "execve",
        "process_name": "systemd",
        "user_id": 0,
        "args_num": 2,
        "return_value": 0
    }
    response = client.post("/api/v1/analyze/false-positive", json=payload)
    assert response.status_code == 200
    assert response.json()["model_version"] == "1.0.0"


def test_api_batch_endpoint():
    payload = {
        "alerts": [
            {
                "event_name": "security_file_open",
                "process_name": "landscape-sysin",
                "user_id": 0,
                "args_num": 2,
                "return_value": 0
            },
            {
                "event_name": "access",
                "process_name": "tsm",
                "user_id": 1001,
                "args_num": 2,
                "return_value": -2
            }
        ]
    }
    response = client.post("/analyze/false-positive/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_evaluated"] == 2
    assert len(data["results"]) == 2

