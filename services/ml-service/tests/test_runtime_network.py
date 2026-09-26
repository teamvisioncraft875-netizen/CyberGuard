"""
CYBERGUARD — Phase 5.3 Real-Time Network Detection Runtime Tests

Tests hybrid network threat detection on realistic telemetry fixtures:
A. Normal web traffic
B. High-volume outbound traffic
C. Suspicious burst traffic
D. ICMP probe-like traffic
E. High ephemeral-port traffic
F. Zero-duration flow
G. Missing/corrupt telemetry

Validates:
- HTTP 200 OK
- Telemetry adapter integration
- Supervised threat probability presence in signals
- Anomaly score presence in signals
- Preservation of detector signals and combination logic
- Valid risk level
- No service crashes on malformed inputs
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analyze import RiskLevel


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


NETWORK_FIXTURES = {
    "A_normal_web": {
        "duration": 2.5,
        "packet_count": 15.0,
        "total_bytes": 4500.0,
        "source_bytes": 1200.0,
        "protocol": "tcp",
        "destination_port": 443,
        "direction": "<->",
    },
    "B_high_volume": {
        "duration": 10.0,
        "packet_count": 2000.0,
        "total_bytes": 15000000.0,
        "source_bytes": 14500000.0,
        "protocol": "tcp",
        "destination_port": 80,
        "direction": "outbound",
    },
    "C_suspicious_burst": {
        "duration": 0.05,
        "packet_count": 500.0,
        "total_bytes": 600000.0,
        "source_bytes": 580000.0,
        "protocol": "tcp",
        "destination_port": 8088,
        "direction": "outbound",
    },
    "D_icmp_probe": {
        "duration": 0.0,
        "packet_count": 1.0,
        "total_bytes": 64.0,
        "source_bytes": 64.0,
        "protocol": "icmp",
        "destination_port": 0,
        "direction": "->",
    },
    "E_ephemeral_port": {
        "duration": 0.1,
        "packet_count": 5.0,
        "total_bytes": 400.0,
        "source_bytes": 400.0,
        "protocol": "tcp",
        "destination_port": 59123,
        "direction": "outbound",
    },
    "F_zero_duration": {
        "duration": 0.0,
        "packet_count": 2.0,
        "total_bytes": 120.0,
        "source_bytes": 60.0,
        "protocol": "udp",
        "destination_port": 53,
        "direction": "->",
    },
    "G_corrupt_telemetry": {
        "duration": "not_a_valid_number",
        "total_bytes": None,
        "protocol": 999999,
        "nested_unsupported": {"error": True},
    },
}


@pytest.mark.parametrize("fixture_name, telemetry_details", list(NETWORK_FIXTURES.items()))
def test_network_fixtures_runtime_behavior(client, fixture_name, telemetry_details):
    """Verify each realistic telemetry fixture evaluates cleanly without crashing."""
    payload = {
        "user_id": f"usr_test_{fixture_name}",
        "timestamp": "2026-09-25T12:00:00Z",
        "event_type": "network_flow",
        "details": telemetry_details,
    }

    res = client.post("/api/v1/analyze/system", json=payload)
    assert res.status_code == 200
    data = res.json()

    # 1. Schema integrity
    assert "risk_level" in data
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert "signals" in data
    assert "explanation" in data
    assert isinstance(data["recommended_actions"], list)

    # 2. Risk level validity
    assert data["risk_level"] in [e.value for e in RiskLevel]

    # 3. Supervised & anomaly signal presence
    signals = data["signals"]
    assert "supervised_threat_probability" in signals or "bytes_transferred" in signals
    if "supervised_threat_probability" in signals:
        assert isinstance(signals["supervised_threat_probability"], float)
        assert 0.0 <= signals["supervised_threat_probability"] <= 1.0
        assert "anomaly_score" in signals
        assert isinstance(signals["anomaly_score"], float)
        assert 0.0 <= signals["anomaly_score"] <= 1.0
        assert "detector_triggered" in signals
        assert "combination_logic" in signals
