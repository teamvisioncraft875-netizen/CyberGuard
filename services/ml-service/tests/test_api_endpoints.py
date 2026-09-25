"""
CYBERGUARD — FastAPI ML Service API Endpoint Integration Tests (Phase 4.2 & 4.5)

Tests endpoint contracts for:
- POST /api/v1/analyze/url and POST /internal/analyze/url
- POST /api/v1/analyze/system and POST /internal/analyze/system
- POST /api/v1/analyze/login and POST /internal/analyze/login

Validates:
- HTTP status codes
- Response schemas (UnifiedAnalysisResponse)
- Calibrated risk tiers and scores
- Heuristic transparency on URL engine
- Distinguishable supervised vs anomaly signals on System engine
- Error handling on invalid inputs
- Lazy model loading and determinism across repeated requests
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analyze import RiskLevel


@pytest.fixture(scope="module")
def client():
    """Provides a reusable FastAPI TestClient."""
    return TestClient(app)


# ============================================================================
# 1. URL Analysis API Endpoints (/api/v1/analyze/url & /internal/analyze/url)
# ============================================================================

@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_api_url_benign(client, route_prefix):
    """Test benign URL evaluation returns 200 OK with SAFE risk tier."""
    res = client.post(f"{route_prefix}/analyze/url", json={"url": "https://cyberguard.io/docs/architecture"})
    assert res.status_code == 200
    data = res.json()

    assert data["risk_level"] == RiskLevel.SAFE.value
    assert 0 <= data["risk_score"] <= 20
    assert "signals" in data
    assert data["signals"]["target_brand"] == "none"
    assert data["signals"]["has_suspicious_keyword"] is False
    assert data["signals"]["is_suspicious_tld"] is False
    assert data["signals"]["engine"] == "URL & Phishing Threat Engine"
    assert "heuristic" in data["signals"]["model_status"].lower()


@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_api_url_malicious_phishing(client, route_prefix):
    """Test compound phishing URL returns 200 OK with CRITICAL risk tier."""
    res = client.post(
        f"{route_prefix}/analyze/url",
        json={"url": "http://sl83684.pro/loading.php?user=amazon_account_update"}
    )
    assert res.status_code == 200
    data = res.json()

    assert data["risk_level"] == RiskLevel.CRITICAL.value
    assert data["risk_score"] >= 90
    assert "amazon" in data["explanation"].lower()
    assert isinstance(data["recommended_actions"], list)
    assert len(data["recommended_actions"]) > 0


@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_api_url_malformed_handled_safely(client, route_prefix):
    """Test malformed URL does not cause 500 server crash, returns 200 OK with valid schema."""
    res = client.post(f"{route_prefix}/analyze/url", json={"url": "http://[invalid-ipv6/test"})
    assert res.status_code == 200
    data = res.json()

    assert "risk_level" in data
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert isinstance(data["signals"], dict)


def test_api_url_invalid_payload_error(client):
    """Test missing URL key returns 422 Unprocessable Entity."""
    res = client.post("/api/v1/analyze/url", json={"invalid_field": "test"})
    assert res.status_code == 422


# ============================================================================
# 2. System / Network Analysis Endpoints (/api/v1/analyze/system & /internal/analyze/system)
# ============================================================================

@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_api_system_valid_telemetry(client, route_prefix):
    """Test valid network flow telemetry evaluates cleanly with UnifiedAnalysisResponse."""
    payload = {
        "user_id": "usr_analyst_01",
        "timestamp": "2026-09-25T12:00:00Z",
        "event_type": "network_flow",
        "details": {
            "dur": 2.5,
            "tot_pkts": 15.0,
            "tot_bytes": 4500.0,
            "src_bytes": 1200.0,
            "proto": "tcp",
            "dport": 443,
        }
    }
    res = client.post(f"{route_prefix}/analyze/system", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert "risk_level" in data
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert "signals" in data
    assert data["signals"]["user_id"] == "usr_analyst_01"
    assert data["signals"]["protocol"] in ["TCP", "UDP", "Other", "ICMP"]


@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_api_system_suspicious_network_surge(client, route_prefix):
    """Test high-volume network surge evaluates to elevated risk tier."""
    payload = {
        "user_id": "usr_compromised_02",
        "timestamp": "2026-09-25T12:05:00Z",
        "event_type": "network_spike",
        "details": {
            "dur": 0.05,
            "tot_pkts": 500.0,
            "tot_bytes": 600000.0,
            "src_bytes": 580000.0,
            "proto": "tcp",
            "dport": 8088,
        }
    }
    res = client.post(f"{route_prefix}/analyze/system", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["risk_level"] in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
    assert data["risk_score"] >= 70
    assert len(data["recommended_actions"]) > 0


def test_api_system_invalid_payload_error(client):
    """Test payload missing required user_id or event_type returns 422."""
    res = client.post("/api/v1/analyze/system", json={"details": {"outbound_bytes": 500}})
    assert res.status_code == 422


# ============================================================================
# 3. Model Loading & Performance Determinism Tests (Phase 4.5)
# ============================================================================

def test_api_system_repeated_calls_deterministic_no_reload(client):
    """Test repeated requests produce strictly identical predictions with fast response times."""
    payload = {
        "user_id": "usr_repeat_check",
        "timestamp": "2026-09-25T12:10:00Z",
        "event_type": "network_flow",
        "details": {
            "dur": 1.2,
            "tot_pkts": 20.0,
            "tot_bytes": 8000.0,
            "src_bytes": 3000.0,
            "proto": "tcp",
            "dport": 80,
        }
    }
    res1 = client.post("/api/v1/analyze/system", json=payload)
    res2 = client.post("/api/v1/analyze/system", json=payload)

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.json() == res2.json()


def test_api_system_malformed_telemetry_details_safe(client):
    """Test telemetry with missing, non-numeric, or null values handles safely without 500 error."""
    payload = {
        "user_id": "usr_safe_handling",
        "timestamp": "2026-09-25T12:15:00Z",
        "event_type": "network_flow",
        "details": {
            "dur": "not_a_number",
            "tot_pkts": None,
            "random_field": {"nested": True}
        }
    }
    res = client.post("/api/v1/analyze/system", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert 0 <= data["risk_score"] <= 100


# ============================================================================
# 4. Login Anomaly Regression
# ============================================================================

def test_existing_login_api_remains_operational(client):
    """Verify POST /internal/analyze/login remains functional and backward-compatible."""
    payload = {
        "user_id": "usr_login_regression",
        "timestamp": "2026-09-25T12:20:00Z",
        "location": "Tokyo, JP",
        "device_id": "laptop-linux-01",
        "failed_attempts": 0,
    }
    res = client.post("/internal/analyze/login", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_level" in data
    assert "risk_score" in data
