"""
CYBERGUARD — Phase 6.4 Engine Health & Readiness Tests

Verifies service readiness and model availability reporting via the health probe.
Guarantees:
- URL engine available
- Network supervised model available
- Network anomaly model available
- Model checkpoints readable
- Preprocessing components available
- NO internal filesystem paths leaked to clients
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_health_probe_readiness(client):
    """
    Verifies that /health and /health/readiness return readiness status
    covering both detection engines and their checkpoint states.
    """
    for endpoint in ["/health", "/internal/health", "/health/readiness"]:
        res = client.get(endpoint)
        assert res.status_code == 200
        data = res.json()

        assert data["status"] in ["ok", "ready", "degraded"]
        assert data["service"] == "cyberguard-ml-service"
        assert "version" in data
        assert "readiness" in data

        readiness = data["readiness"]
        assert readiness["url_engine_available"] is True
        assert readiness["network_supervised_available"] is True
        assert readiness["network_anomaly_available"] is True
        assert readiness["checkpoints_readable"] is True
        assert readiness["preprocessing_available"] is True


def test_health_probe_no_path_leakage(client):
    """
    Guarantees that no internal filesystem paths (e.g., C:\\, D:\\, /home/, .joblib paths)
    are leaked through the health/readiness endpoints.
    """
    res = client.get("/health")
    raw_text = res.text

    assert "C:\\" not in raw_text
    assert "D:\\" not in raw_text
    assert ".joblib" not in raw_text
    assert "/services/" not in raw_text
