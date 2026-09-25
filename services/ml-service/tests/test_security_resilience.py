"""
CYBERGUARD — Phase 5.7 FastAPI Service Security & Resilience Tests

Validates:
- Malformed JSON requests return 422 Unprocessable Entity cleanly
- Unexpected/oversized payloads do not crash the service
- No server stack traces or internal absolute filesystem paths leaked in errors
- Safe handling of boundary values and unexpected field types
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_malformed_json_syntax_handled_safely(client):
    """Verify malformed JSON syntax is rejected with 422 without 500 server crash."""
    res = client.post(
        "/api/v1/analyze/url",
        content="{\"url\": \"http://example.com\", invalid_json",
        headers={"Content-Type": "application/json"}
    )
    assert res.status_code in [400, 422]
    # Verify no Python traceback leaked in response
    assert "Traceback" not in res.text
    assert "services/ml-service" not in res.text


def test_oversized_payload_handling(client):
    """Verify oversized string inputs are handled safely without buffer or memory crash."""
    huge_url = "http://phish.example.com/" + ("A" * 10000)
    res = client.post("/api/v1/analyze/url", json={"url": huge_url})
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "risk_level" in data


def test_unexpected_payload_fields_stripped(client):
    """Verify extraneous fields (e.g. injection attempts) do not crash schema parser."""
    res = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "https://cyberguard.io",
            "__admin_override__": True,
            "$where": "1 == 1",
            "nested_injection": {"drop_table": "all"}
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "Safe"
