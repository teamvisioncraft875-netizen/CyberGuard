"""
CYBERGUARD — URL Engine Test Suite (Phase 3B.5)

Strengthens test coverage for url_engine.py across all required heuristic scenarios:
- benign-looking URL
- known phishing URL
- suspicious keyword URL
- IP-based URL
- suspicious TLD
- brand impersonation
- malformed URL
- empty URL
- deterministic scoring
- UnifiedAnalysisResponse contract compliance

NOTE: These tests validate defensive heuristic contracts and domain look-alike detection,
and do NOT represent supervised ML classifier benchmark accuracy (which is BLOCKED due to single-class dataset).
"""

import pytest
from app.services.url_engine import analyze_url
from app.schemas.analyze import UrlAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel


def test_url_engine_benign_url():
    """Verify standard legitimate domain is classified as SAFE with low risk score."""
    req = UrlAnalyzeRequest(url="https://cyberguard.io/docs/architecture/overview")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level == RiskLevel.SAFE
    assert res.risk_score <= 20
    assert res.confidence_score >= 0.8
    assert res.signals["target_brand"] == "none"
    assert res.signals["has_suspicious_keyword"] is False
    assert res.signals["is_suspicious_tld"] is False
    assert res.signals["has_ip_address"] is False


def test_url_engine_known_phishing_url():
    """Verify compound phishing indicators (brand + suspicious TLD + keyword) trigger CRITICAL."""
    req = UrlAnalyzeRequest(url="http://sl83684.pro/loading.php?user=amazon_account_update")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.risk_score >= 90
    assert "Amazon" in res.explanation or "amazon" in res.explanation.lower()
    assert len(res.recommended_actions) >= 2
    assert res.confidence_score >= 0.9


def test_url_engine_suspicious_keyword_url():
    """Verify credential-harvesting keyword URL triggers elevated risk."""
    req = UrlAnalyzeRequest(url="https://secure-auth-gateway.org/verify-credentials/login")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert res.risk_score >= 70
    assert res.signals["has_suspicious_keyword"] is True


def test_url_engine_ip_based_url():
    """Verify raw IP address host triggers elevated threat warning."""
    req = UrlAnalyzeRequest(url="http://192.168.1.105:8080/admin/panel")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert res.risk_score >= 70
    assert res.signals["has_ip_address"] is True


def test_url_engine_suspicious_tld_url():
    """Verify elevated-risk TLD (e.g., .xyz, .pro) triggers HIGH risk."""
    req = UrlAnalyzeRequest(url="https://corporate-support-portal.xyz/download")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert res.risk_score >= 70
    assert res.signals["is_suspicious_tld"] is True


def test_url_engine_brand_impersonation_url():
    """Verify brand lookalike (e.g. PayPal) is detected and flagged."""
    req = UrlAnalyzeRequest(url="https://paypal-security-verification.com/index.html")
    res = analyze_url(req)

    assert isinstance(res, UnifiedAnalysisResponse)
    assert res.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert res.risk_score >= 75
    assert res.signals["target_brand"] == "paypal"


def test_url_engine_malformed_url():
    """Verify malformed or corrupt URL strings are parsed safely without crashing."""
    malformed_inputs = [
        "http://[::1:8080/invalid-ipv6",
        ":///invalid-schema-and-path",
        "https://",
        "ftp:///bad/format?%%$$",
        "http://???nonsense???",
    ]

    for raw_url in malformed_inputs:
        req = UrlAnalyzeRequest(url=raw_url)
        res = analyze_url(req)
        assert isinstance(res, UnifiedAnalysisResponse)
        assert 0 <= res.risk_score <= 100
        assert isinstance(res.risk_level, RiskLevel)
        assert isinstance(res.signals, dict)


def test_url_engine_empty_url():
    """Verify empty or whitespace-only URL is handled gracefully with SAFE tier."""
    empty_inputs = ["", "   ", "\t\n"]

    for empty_val in empty_inputs:
        req = UrlAnalyzeRequest(url=empty_val)
        res = analyze_url(req)
        assert isinstance(res, UnifiedAnalysisResponse)
        assert res.risk_level == RiskLevel.SAFE
        assert res.risk_score == 0
        assert "empty" in res.explanation.lower()


def test_url_engine_deterministic_scoring():
    """Verify repeated evaluations of identical URL produce strictly deterministic responses."""
    test_url = "http://amazon-account-verify.pro/login.php?client=123"
    req1 = UrlAnalyzeRequest(url=test_url)
    req2 = UrlAnalyzeRequest(url=test_url)

    res1 = analyze_url(req1)
    res2 = analyze_url(req2)

    assert res1.risk_level == res2.risk_level
    assert res1.risk_score == res2.risk_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.explanation == res2.explanation
    assert res1.signals == res2.signals
    assert res1.recommended_actions == res2.recommended_actions


def test_url_engine_unified_analysis_response_contract():
    """Verify complete schema compliance with docs/API_CONTRACT.md UnifiedAnalysisResponse."""
    req = UrlAnalyzeRequest(url="https://example.com")
    res = analyze_url(req)

    # Contract Assertions
    assert hasattr(res, "risk_level")
    assert hasattr(res, "risk_score")
    assert hasattr(res, "explanation")
    assert hasattr(res, "signals")
    assert hasattr(res, "recommended_actions")
    assert hasattr(res, "confidence_score")

    assert isinstance(res.risk_level, RiskLevel)
    assert isinstance(res.risk_score, int)
    assert 0 <= res.risk_score <= 100
    assert isinstance(res.explanation, str)
    assert len(res.explanation) > 0
    assert isinstance(res.signals, dict)
    assert isinstance(res.recommended_actions, list)
    assert isinstance(res.confidence_score, float)
    assert 0.0 <= res.confidence_score <= 1.0
