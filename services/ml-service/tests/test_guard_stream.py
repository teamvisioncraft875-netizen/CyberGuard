"""
CYBERGUARD — Phase 5.8 Guard-App Simulated Telemetry Stream Tests

Tests a simulated continuous stream of endpoint sensor telemetry through:
Sensor Stream -> Telemetry Adapter -> FastAPI -> Network Threat Engine -> Response

NOTE: Live OS-level kernel packet interception (libpcap/winpcap) is NOT active;
this test validates the contract against a simulated live telemetry stream.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.utils.telemetry_adapter import transform_guard_telemetry


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_simulated_guard_telemetry_stream(client):
    """
    Simulates a time-series stream of 10 telemetry events from an endpoint sensor:
    - 5 standard web sessions
    - 3 ICMP reconnaissance probes
    - 2 high-volume outbound surges
    Verifies that the entire sequence is processed cleanly and deterministically.
    """
    simulated_stream = [
        # Standard web sessions
        {"duration": 1.2, "packet_count": 12, "total_bytes": 3600, "source_bytes": 1000, "protocol": "tcp", "destination_port": 443},
        {"duration": 0.8, "packet_count": 8, "total_bytes": 2400, "source_bytes": 800, "protocol": "tcp", "destination_port": 443},
        {"duration": 2.1, "packet_count": 25, "total_bytes": 12000, "source_bytes": 3000, "protocol": "tcp", "destination_port": 80},
        {"duration": 0.05, "packet_count": 2, "total_bytes": 150, "source_bytes": 60, "protocol": "udp", "destination_port": 53},
        {"duration": 1.5, "packet_count": 18, "total_bytes": 5000, "source_bytes": 1500, "protocol": "tcp", "destination_port": 443},

        # ICMP probes
        {"duration": 0.0, "packet_count": 1, "total_bytes": 64, "source_bytes": 64, "protocol": "icmp", "destination_port": 0},
        {"duration": 0.0, "packet_count": 1, "total_bytes": 64, "source_bytes": 64, "protocol": "icmp", "destination_port": 0},
        {"duration": 0.0, "packet_count": 1, "total_bytes": 64, "source_bytes": 64, "protocol": "icmp", "destination_port": 0},

        # High-volume surges
        {"duration": 0.05, "packet_count": 500, "total_bytes": 600000, "source_bytes": 580000, "protocol": "tcp", "destination_port": 8088},
        {"duration": 0.04, "packet_count": 450, "total_bytes": 540000, "source_bytes": 520000, "protocol": "tcp", "destination_port": 8088},
    ]

    results = []
    for idx, raw_event in enumerate(simulated_stream):
        # 1. Adapter standardization
        adapted = transform_guard_telemetry(raw_event)
        assert len(adapted) == 14

        # 2. Ingestion by engine
        payload = {
            "user_id": "usr_sensor_stream",
            "timestamp": f"2026-09-25T12:00:{idx:02d}Z",
            "event_type": "network_flow",
            "details": adapted
        }
        res = client.post("/api/v1/analyze/system", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "risk_level" in data
        assert "risk_score" in data
        results.append(data)

    assert len(results) == 10
    # First 5 (web) should be Safe or Low
    for i in range(5):
        assert results[i]["risk_level"] in ["Safe", "Low"]

    # Last 2 (surges) should be High or Critical
    for i in [8, 9]:
        assert results[i]["risk_level"] in ["High", "Critical"]
