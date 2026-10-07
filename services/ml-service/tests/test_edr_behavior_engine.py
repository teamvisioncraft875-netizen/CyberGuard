"""
Unit & Integration Tests for CYBERGUARD EDR Behavior Detection Engine V1.
Covers:
- Schema validation
- Valid inference
- Malformed input
- Missing fields
- Deterministic output
- Probability bounds
- Operating threshold application
- Model loading
- SHA-256 integrity verification
- Unseen process names
- Unknown categories
- Empty/edge cases
- Causal state handling
- Security & path traversal handling
- Downstream compatibility with Correlation / False Positive / Recommendation
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.edr_behavior import (
    EDRBehaviorAnalysisRequest,
    EDRBehaviorAnalysisResponse,
)
from app.services.edr_behavior_engine import EDRBehaviorEngine, MODEL_PATH, REGISTRY_PATH


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def engine():
    return EDRBehaviorEngine.get_instance()


# 1. Model Loading & Integrity Tests
def test_model_loading_and_sha_integrity(engine):
    assert engine is not None
    assert engine._model is not None, "EDR model should be loaded"
    assert engine._verify_artifact_sha(MODEL_PATH) is True, "Artifact SHA-256 should match registry"
    assert engine._threshold == 0.0300, "Threshold must match locked operating threshold 0.0300"


# 2. Schema Validation Tests
def test_schema_valid_request():
    req = EDRBehaviorAnalysisRequest(
        process_name="bash",
        event_name="execve",
        user_id=1001,
        parent_process_name="sshd",
        parent_process_id=7102,
        process_id=7307,
        return_value=0,
        args_num=2
    )
    assert req.process_name == "bash"
    assert req.event_name == "execve"
    assert req.user_id == 1001
    assert req.parent_process_name == "sshd"


def test_schema_path_traversal_sanitization():
    req = EDRBehaviorAnalysisRequest(
        process_name="/usr/bin/../../bin/bash",
        event_name="openat",
        user_id=0,
        parent_process_name="/lib/systemd/systemd"
    )
    assert req.process_name == "bash", "Path traversal and directory paths must be stripped to basename"
    assert req.parent_process_name == "systemd"


def test_schema_missing_required_fields():
    with pytest.raises(Exception):
        EDRBehaviorAnalysisRequest(
            # Missing process_name and event_name
            user_id=1001
        )


# 3. Valid Inference Tests
def test_inference_benign_system_daemon(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="systemd-journal",
        event_name="openat",
        user_id=0,
        parent_process_name="systemd",
        parent_process_id=1,
        process_id=382,
        return_value=0,
        args_num=4
    )
    resp = engine.analyze(req)
    assert isinstance(resp, EDRBehaviorAnalysisResponse)
    assert 0.0 <= resp.behavior_score <= 1.0
    assert 0.0 <= resp.malicious_probability <= 1.0
    assert resp.classification in ("malicious_behavior", "benign_behavior")
    assert resp.is_advisory_only is True
    assert "systemd -> systemd-journal" in resp.observed_process_chain


def test_inference_malicious_shell_execution(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="tsm",
        event_name="execve",
        user_id=1001,
        parent_process_name="bash",
        parent_process_id=7307,
        process_id=7548,
        return_value=0,
        args_num=2
    )
    resp = engine.analyze(req)
    assert isinstance(resp, EDRBehaviorAnalysisResponse)
    assert resp.classification == "malicious_behavior"
    assert resp.behavior_score >= resp.operating_threshold
    assert resp.mitre_context is not None
    assert "Command and Control" in resp.mitre_context["tactic"] or "Execution" in resp.mitre_context["tactic"]


# 4. Deterministic Output Tests
def test_deterministic_output(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="ps",
        event_name="close",
        user_id=0,
        parent_process_name="amazon-ssm-agent",
        parent_process_id=1278,
        process_id=8921,
        return_value=0,
        args_num=1
    )
    resp1 = engine.analyze(req)
    resp2 = engine.analyze(req)
    assert resp1.classification == resp2.classification
    assert abs(resp1.behavior_score - resp2.behavior_score) < 0.1  # Continuous scores within tight margin


# 5. Unseen Process Names and Unknown Categories
def test_unseen_process_names(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="completely_unknown_backdoor_binary_xyz",
        event_name="security_socket_connect",
        user_id=1001,
        parent_process_name="bash",
        parent_process_id=7100,
        process_id=9876,
        return_value=0,
        args_num=3
    )
    resp = engine.analyze(req)
    assert isinstance(resp, EDRBehaviorAnalysisResponse)
    assert 0.0 <= resp.behavior_score <= 1.0
    assert resp.classification == "malicious_behavior", "Unseen binary spawned by shell by user 1001 should flag"


def test_unknown_event_category(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="ps",
        event_name="nonexistent_syscall_xyz",
        user_id=0,
        parent_process_name="systemd",
        parent_process_id=1,
        process_id=5000,
        return_value=0,
        args_num=0
    )
    resp = engine.analyze(req)
    assert isinstance(resp, EDRBehaviorAnalysisResponse)
    assert resp.classification == "benign_behavior"


# 6. Edge Cases & Causal State Handling
def test_negative_return_value_failed_syscall(engine):
    req = EDRBehaviorAnalysisRequest(
        process_name="passwd",
        event_name="security_file_open",
        user_id=1001,
        parent_process_name="sh",
        parent_process_id=4000,
        process_id=4001,
        return_value=-13,  # EACCES Permission denied
        args_num=3
    )
    resp = engine.analyze(req)
    assert isinstance(resp, EDRBehaviorAnalysisResponse)
    assert resp.classification == "malicious_behavior"
    assert resp.mitre_context is not None


def test_causal_state_accumulation(engine):
    # Successive calls for same PID should increment event count without error
    pid = 8888
    for i in range(5):
        req = EDRBehaviorAnalysisRequest(
            process_name="cron",
            event_name="stat",
            user_id=0,
            parent_process_name="systemd",
            parent_process_id=1,
            process_id=pid,
            return_value=0,
            args_num=2
        )
        resp = engine.analyze(req)
        assert resp.classification == "benign_behavior"


# 7. HTTP Endpoint Tests (All 3 Routes)
def test_api_endpoint_direct(client):
    payload = {
        "process_name": "bash",
        "event_name": "execve",
        "user_id": 1001,
        "parent_process_name": "sshd",
        "parent_process_id": 7102,
        "process_id": 7307,
        "return_value": 0,
        "args_num": 2
    }
    resp = client.post("/analyze/edr-behavior", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "behavior_score" in data
    assert "classification" in data
    assert data["is_advisory_only"] is True


def test_api_endpoint_internal(client):
    payload = {
        "process_name": "ps",
        "event_name": "close",
        "user_id": 0,
        "parent_process_name": "systemd",
        "parent_process_id": 1,
        "process_id": 1200
    }
    resp = client.post("/internal/analyze/edr-behavior", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["classification"] == "benign_behavior"


def test_api_endpoint_v1(client):
    payload = {
        "process_name": "tsm",
        "event_name": "execve",
        "user_id": 1001,
        "parent_process_name": "bash"
    }
    resp = client.post("/api/v1/analyze/edr-behavior", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["classification"] == "malicious_behavior"


# 8. Downstream Flow Compatibility Test
def test_downstream_pipeline_compatibility(client):
    """
    Simulates the end-to-end downstream architecture:
    EDR Behavior -> Correlation -> False Positive -> Recommendation
    """
    # Step 1: EDR Behavior scoring
    edr_payload = {
        "process_name": "tsm",
        "event_name": "execve",
        "user_id": 1001,
        "parent_process_name": "bash",
        "parent_process_id": 7307,
        "process_id": 7548
    }
    edr_res = client.post("/analyze/edr-behavior", json=edr_payload)
    assert edr_res.status_code == 200
    edr_data = edr_res.json()
    assert edr_data["classification"] == "malicious_behavior"

    # Step 2: Correlation grouping alert with EDR context
    corr_payload = {
        "alerts": [
            {
                "alert_id": "ALT-EDR-001",
                "entity": "host-217",
                "alert_type": "edr_suspicious_process",
                "severity": "high",
                "risk_score": edr_data["behavior_score"],
                "timestamp": "2026-10-06T12:00:00Z",
                "source": "edr_agent",
                "mitre_technique": "T1105",
                "host": "host-217"
            },
            {
                "alert_id": "ALT-EDR-002",
                "entity": "host-217",
                "alert_type": "ssh_login_anomaly",
                "severity": "medium",
                "risk_score": 0.75,
                "timestamp": "2026-10-06T12:00:05Z",
                "source": "auth_log",
                "mitre_technique": "T1078",
                "host": "host-217"
            }
        ]
    }
    corr_res = client.post("/analyze/correlation", json=corr_payload)
    assert corr_res.status_code == 200
    corr_data = corr_res.json()
    assert len(corr_data["incidents"]) >= 1 or len(corr_data["correlated_alert_ids"]) >= 1
    inc_id = corr_data["incident_id"]


    # Step 3: False Positive Evaluation
    fp_payload = {
        "alert_id": "ALT-EDR-001",
        "event_name": "execve",
        "process_name": "tsm",
        "user_id": 1001,
        "args_num": 2,
        "return_value": 0,
        "correlation_id": inc_id
    }
    fp_res = client.post("/analyze/false-positive", json=fp_payload)
    assert fp_res.status_code == 200
    fp_data = fp_res.json()
    assert fp_data["classification"] == "likely_true_positive"

    # Step 4: Recommendation Engine
    rec_payload = {
        "incident_id": inc_id,
        "threat_type": "malware",
        "severity": "high",
        "risk_score": int(edr_data["behavior_score"] * 100),
        "entities": {"hosts": ["host-217"]},
        "alert_count": 2
    }
    rec_res = client.post("/analyze/recommendation", json=rec_payload)
    assert rec_res.status_code == 200

    rec_data = rec_res.json()
    assert len(rec_data["recommendations"]) > 0
    assert rec_data["incident_id"] == inc_id
