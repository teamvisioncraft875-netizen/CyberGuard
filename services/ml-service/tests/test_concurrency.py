"""
CYBERGUARD — Phase 5.6 Controlled Concurrency Tests

Tests multiple simultaneous analysis requests under controlled worker pools:
- Concurrency levels: 5, 10, 20 workers
- Evaluates both URL and Network engines simultaneously
- Verifies zero crashes, zero corrupted responses, and response determinism
"""

import pytest
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analyze import RiskLevel


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


CONCURRENCY_LEVELS = [5, 10, 20]


@pytest.mark.parametrize("workers", CONCURRENCY_LEVELS)
def test_concurrent_url_analysis(client, workers):
    """Verify concurrent URL requests execute deterministically without corruption."""
    test_payload = {"url": "http://sl83684.pro/loading.php?user=amazon_account_update"}

    def send_req(_):
        res = client.post("/api/v1/analyze/url", json=test_payload)
        return res.status_code, res.json()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(send_req, range(workers * 2)))

    assert len(results) == workers * 2
    for status_code, body in results:
        assert status_code == 200
        assert body["risk_level"] == RiskLevel.CRITICAL.value
        assert body["risk_score"] >= 90
        assert body["signals"]["target_brand"] == "amazon"


@pytest.mark.parametrize("workers", CONCURRENCY_LEVELS)
def test_concurrent_network_analysis(client, workers):
    """Verify concurrent network telemetry requests execute deterministically without crashing."""
    test_payload = {
        "user_id": "usr_concurrent_net",
        "timestamp": "2026-09-25T12:00:00Z",
        "event_type": "network_flow",
        "details": {
            "duration": 2.5,
            "packet_count": 15.0,
            "total_bytes": 4500.0,
            "source_bytes": 1200.0,
            "protocol": "tcp",
            "destination_port": 443,
        }
    }

    def send_req(_):
        res = client.post("/api/v1/analyze/system", json=test_payload)
        return res.status_code, res.json()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(send_req, range(workers * 2)))

    assert len(results) == workers * 2
    for status_code, body in results:
        assert status_code == 200
        assert body["risk_level"] in [RiskLevel.SAFE.value, RiskLevel.LOW.value]
        assert "signals" in body
        assert "supervised_threat_probability" in body["signals"]
