"""
CYBERGUARD — Phase 5.2 Real-Time URL Detection Runtime Tests

Tests runtime behavior, stability, and determinism of the URL Threat Engine
across repeated sequential requests. Validates:
1. Benign URL
2. Known phishing-style URL
3. Brand impersonation URL
4. Raw IP URL
5. Suspicious TLD URL
6. Suspicious keyword URL
7. Malformed URL
8. Empty URL

NOTE: These tests validate runtime behavior, stability, and deterministic scoring,
and do NOT represent supervised ML classifier accuracy.
"""

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analyze import RiskLevel


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


URL_TEST_CASES = [
    ("benign", "https://cyberguard.io/documentation/architecture", RiskLevel.SAFE),
    ("phishing_style", "http://sl83684.pro/loading.php?user=amazon_account_update", RiskLevel.CRITICAL),
    ("brand_impersonation", "https://paypal-security-verification.com/login", RiskLevel.CRITICAL),
    ("raw_ip", "http://192.168.1.105:8080/admin/panel", RiskLevel.HIGH),
    ("suspicious_tld", "https://corporate-support-portal.xyz/download", RiskLevel.CRITICAL),
    ("suspicious_keyword", "https://secure-auth-gateway.org/verify-credentials/login", RiskLevel.HIGH),
    ("malformed", "http://[invalid-ipv6/broken-path", None),  # None means any valid response without crash
    ("empty", "", RiskLevel.SAFE),
]


@pytest.mark.parametrize("case_name, url_str, expected_tier", URL_TEST_CASES)
def test_url_single_case_runtime(client, case_name, url_str, expected_tier):
    """Verify single-request runtime contract for each required URL test case."""
    res = client.post("/api/v1/analyze/url", json={"url": url_str})
    assert res.status_code == 200
    data = res.json()

    assert "risk_level" in data
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert "signals" in data
    assert "explanation" in data
    assert isinstance(data["recommended_actions"], list)

    if expected_tier is not None:
        assert data["risk_level"] == expected_tier.value


def test_url_repeated_sequential_determinism(client):
    """
    Test 50 repeated sequential requests per URL case to verify:
    - strict determinism across repeated invocations
    - stable risk score and risk level
    - no error or memory state accumulation
    - average response time remains fast (< 25 ms)
    """
    num_iterations = 50
    latencies = []

    for case_name, url_str, expected_tier in URL_TEST_CASES:
        baseline_res = None

        for i in range(num_iterations):
            start = time.perf_counter()
            res = client.post("/api/v1/analyze/url", json={"url": url_str})
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            latencies.append(elapsed_ms)

            assert res.status_code == 200
            data = res.json()

            if baseline_res is None:
                baseline_res = data
            else:
                # Assert strict determinism
                assert data["risk_level"] == baseline_res["risk_level"], f"Drift in risk_level on run {i} for {case_name}"
                assert data["risk_score"] == baseline_res["risk_score"], f"Drift in risk_score on run {i} for {case_name}"
                assert data["signals"] == baseline_res["signals"], f"Drift in signals on run {i} for {case_name}"

    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 25.0, f"Average URL latency exceeded 25ms: {avg_latency:.2f}ms"
