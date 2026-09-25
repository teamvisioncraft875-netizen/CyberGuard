"""
CYBERGUARD — Phase 6.2 & 6.3 Standalone Engine Tests

Direct callable interface verification for:
1. Standalone URL & Phishing Threat Engine (url_engine.py)
   input -> preprocessing -> detection -> risk -> response
   Validates 7 representative URL cases.
   NOTE: Heuristic + brand-lookalike detection, not supervised ML accuracy.

2. Standalone System & Network Threat Engine (system_engine.py / NetworkThreatModel)
   telemetry -> feature adaptation -> supervised detector -> anomaly detector -> risk -> response
   Validates 7 representative telemetry cases.
   Verifies that supervised and anomaly detector signals remain clearly distinguishable.
"""

import pytest
from app.schemas.analyze import (
    UrlAnalyzeRequest,
    SystemAnalyzeRequest,
    RiskLevel,
    UnifiedAnalysisResponse,
)
from app.services.url_engine import analyze_url
from app.services.system_engine import analyze_system, get_network_model


# ---------------------------------------------------------------------------
# Step 6.2: Standalone URL Engine Tests
# ---------------------------------------------------------------------------

URL_STANDALONE_CASES = [
    (
        "benign",
        "https://cyberguard.io/docs/architecture",
        RiskLevel.SAFE,
        False,
    ),
    (
        "phishing_style",
        "http://sl83684.pro/loading.php?user=amazon_account_update",
        RiskLevel.CRITICAL,
        True,
    ),
    (
        "brand_impersonation",
        "https://paypal-security-verification.com/login",
        RiskLevel.CRITICAL,
        True,
    ),
    (
        "raw_ip",
        "http://192.168.1.105:8080/admin/panel",
        RiskLevel.HIGH,
        True,
    ),
    (
        "suspicious_tld",
        "https://corporate-support-portal.xyz/download",
        RiskLevel.CRITICAL,
        True,
    ),
    (
        "suspicious_keyword",
        "https://secure-auth-gateway.org/verify-credentials/login",
        RiskLevel.HIGH,
        True,
    ),
    (
        "malformed",
        "http://[invalid-ipv6/broken-path",
        None,  # Handled safely without crash
        None,
    ),
]


@pytest.mark.parametrize("case_name, url_str, expected_tier, expected_threat", URL_STANDALONE_CASES)
def test_standalone_url_engine(case_name, url_str, expected_tier, expected_threat):
    """
    Direct callable test of analyze_url().
    Verifies output contract: threat detected, risk score, risk level, explanation/signals, engine name.
    """
    req = UrlAnalyzeRequest(url=url_str)
    response = analyze_url(req)

    assert isinstance(response, UnifiedAnalysisResponse)
    assert response.signals["engine"] == "URL & Phishing Threat Engine"
    assert 0 <= response.risk_score <= 100
    assert response.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(response.explanation) > 0
    assert isinstance(response.recommended_actions, list)

    if expected_tier is not None:
        assert response.risk_level == expected_tier
    if expected_threat is True:
        assert response.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert response.risk_score >= 70
    elif expected_threat is False:
        assert response.risk_level == RiskLevel.SAFE
        assert response.risk_score <= 19


# ---------------------------------------------------------------------------
# Step 6.3: Standalone Network Engine Tests
# ---------------------------------------------------------------------------

NETWORK_STANDALONE_CASES = [
    (
        "1_normal_web",
        {
            "dur": 1.25,
            "proto": "tcp",
            "sport": 54210,
            "dport": 443,
            "tot_pkts": 12,
            "tot_bytes": 1820,
            "src_bytes": 620,
            "dir": "out",
        },
        RiskLevel.LOW,
        "Baseline Normal",
    ),
    (
        "2_high_volume",
        {
            "dur": 45.0,
            "proto": "tcp",
            "sport": 49152,
            "dport": 8080,
            "tot_pkts": 8500,
            "tot_bytes": 10485760,  # 10 MB
            "src_bytes": 9800000,
            "dir": "out",
        },
        RiskLevel.HIGH,
        None,  # Any elevated threat detector
    ),
    (
        "3_suspicious_burst",
        {
            "dur": 0.05,
            "proto": "udp",
            "sport": 61234,
            "dport": 5353,
            "tot_pkts": 1200,
            "tot_bytes": 960000,
            "src_bytes": 960000,
            "dir": "out",
        },
        RiskLevel.HIGH,
        None,
    ),
    (
        "4_icmp_probe",
        {
            "dur": 0.001,
            "proto": "icmp",
            "sport": 0,
            "dport": 0,
            "tot_pkts": 1,
            "tot_bytes": 64,
            "src_bytes": 64,
            "dir": "out",
        },
        None,  # Safe or anomaly; depends on baseline
        None,
    ),
    (
        "5_ephemeral_ports",
        {
            "dur": 2.0,
            "proto": "tcp",
            "sport": 62100,
            "dport": 63450,
            "tot_pkts": 30,
            "tot_bytes": 4500,
            "src_bytes": 2200,
            "dir": "out",
        },
        None,
        None,
    ),
    (
        "6_zero_duration",
        {
            "dur": 0.0,
            "proto": "udp",
            "sport": 51000,
            "dport": 123,
            "tot_pkts": 1,
            "tot_bytes": 48,
            "src_bytes": 48,
            "dir": "out",
        },
        None,
        None,
    ),
    (
        "7_malformed_telemetry",
        {
            "dur": "corrupt_value",
            "tot_bytes": None,
            "protocol": "UNKNOWN_PROTO_XYZ",
            "sport": "invalid_port",
        },
        None,  # Handled safely by adapter without crash
        None,
    ),
]


@pytest.mark.parametrize("case_name, telemetry, expected_tier, expected_detector_substr", NETWORK_STANDALONE_CASES)
def test_standalone_network_engine(case_name, telemetry, expected_tier, expected_detector_substr):
    """
    Direct callable test of analyze_system() and NetworkThreatModel.
    Verifies that:
    - supervised threat probability is present
    - anomaly score is present
    - detector triggered is identified
    - final risk score and level are valid
    - explanation and signals are preserved
    - supervised and anomaly mechanisms remain distinguishable
    """
    req = SystemAnalyzeRequest(
        user_id="user_phase6_standalone",
        timestamp="2026-09-25T12:00:00Z",
        event_type="network_flow_telemetry",
        details=telemetry,
    )
    response = analyze_system(req)

    assert isinstance(response, UnifiedAnalysisResponse)
    assert 0 <= response.risk_score <= 100
    assert response.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    # Verify both detection signals are present and distinguishable in signals dict
    signals = response.signals
    assert "supervised_threat_probability" in signals
    assert "anomaly_score" in signals
    assert "detector_triggered" in signals
    assert "combination_logic" in signals
    assert signals["engine"] == "System & Network Threat Engine"

    supervised_prob = signals["supervised_threat_probability"]
    anomaly_score = signals["anomaly_score"]
    assert 0.0 <= supervised_prob <= 1.0
    assert 0.0 <= anomaly_score <= 1.0

    if expected_tier is not None:
        assert response.risk_level == expected_tier
    if expected_detector_substr is not None:
        assert expected_detector_substr in signals["detector_triggered"]
