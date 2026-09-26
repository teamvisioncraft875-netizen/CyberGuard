"""
CYBERGUARD — Guard App Telemetry Transformation Unit Tests (Phase 4.7)

Tests transformation of Guard App sensor telemetry into standardized
14-dimensional feature matrices for system_engine.py.
"""

import pytest
from app.utils.telemetry_adapter import transform_guard_telemetry
from app.utils.ctu13_preprocessor import FEATURE_COLUMNS


@pytest.fixture
def standard_telemetry_fixture():
    return {
        "duration": 2.0,
        "packet_count": 100.0,
        "total_bytes": 150000.0,
        "source_bytes": 140000.0,
        "protocol": "tcp",
        "source_port": 54321,
        "destination_port": 443,
        "direction": "<->",
    }


def test_guard_adapter_standard_telemetry(standard_telemetry_fixture):
    """Verify standard telemetry transforms to all required FEATURE_COLUMNS."""
    features = transform_guard_telemetry(standard_telemetry_fixture)

    for col in FEATURE_COLUMNS:
        assert col in features
        assert isinstance(features[col], float)

    assert features["dur"] == 2.0
    assert features["tot_pkts"] == 100.0
    assert features["tot_bytes"] == 150000.0
    assert features["src_bytes"] == 140000.0
    assert features["packet_rate"] == 50.0  # 100 / 2
    assert features["byte_rate"] == 75000.0  # 150000 / 2
    assert features["proto_tcp"] == 1.0
    assert features["proto_udp"] == 0.0
    assert features["proto_icmp"] == 0.0
    assert features["is_well_known_dport"] == 1.0  # 443
    assert features["is_bidirectional"] == 1.0


def test_guard_adapter_icmp_probe():
    """Verify ICMP zero-duration probe calculates finite rates safely."""
    icmp_fixture = {
        "duration": 0.0,
        "packet_count": 1.0,
        "total_bytes": 64.0,
        "source_bytes": 64.0,
        "protocol": "icmp",
        "destination_port": 0,
        "direction": "->",
    }
    features = transform_guard_telemetry(icmp_fixture)

    assert features["proto_icmp"] == 1.0
    assert features["proto_tcp"] == 0.0
    assert features["dur"] == 0.0
    assert features["packet_rate"] > 0  # Zero-duration safe division
    assert features["is_well_known_dport"] == 0.0
    assert features["is_bidirectional"] == 0.0


def test_guard_adapter_missing_and_corrupt_fields():
    """Verify empty or corrupt telemetry returns safe default numerical features without raising."""
    corrupt_fixtures = [
        {},
        None,
        {"duration": "invalid_num", "total_bytes": None},
        {"protocol": "custom_vpn_tunnel", "destination_port": 65535},
    ]

    for item in corrupt_fixtures:
        feats = transform_guard_telemetry(item)
        assert len(feats) == len(FEATURE_COLUMNS)
        for col in FEATURE_COLUMNS:
            assert isinstance(feats[col], float)
            assert feats[col] == feats[col]  # not NaN
