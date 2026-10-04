import json
from pathlib import Path
import pytest
import joblib

from app.schemas.analyze import UrlAnalyzeRequest, RiskLevel
from app.services.url_engine import analyze_url, _get_url_model
from app.utils.url_preprocessor import URL_FEATURE_COLUMNS, extract_url_features


def test_url_model_artifact_integrity():
    """Verify that Malicious URL classifier v1.0.0 artifacts exist and are consistent."""
    model_dir = Path(__file__).resolve().parents[1] / "app" / "models" / "url"
    classifier_path = model_dir / "malicious_url_classifier_v1.0.0.joblib"
    meta_path = model_dir / "malicious_url_metadata_v1.0.0.json"
    schema_path = model_dir / "malicious_url_schema_v1.0.0.json"

    assert classifier_path.exists(), "URL classifier artifact missing"
    assert meta_path.exists(), "URL metadata artifact missing"
    assert schema_path.exists(), "URL schema artifact missing"

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["model_version"] == "v1.0.0"
    assert meta["algorithm"] == "HistGradientBoosting"
    assert meta["operating_threshold"] == 0.74
    assert "test_benchmark_metrics" in meta

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    assert schema["feature_count"] == 16
    assert schema["features"] == URL_FEATURE_COLUMNS

    model = joblib.load(classifier_path)
    assert hasattr(model, "predict_proba"), "Loaded classifier must support predict_proba"


def test_benign_urls_supervised_inference():
    """Verify that known benign legitimate URLs receive benign ML decision and low probability."""
    benign_samples = [
        "https://www.google.com/search?q=cybersecurity+defense",
        "https://docs.python.org/3/library/json.html",
        "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
        "https://www.paypal.com/us/home",
        "https://www.python.org/about/",
    ]

    for url in benign_samples:
        req = UrlAnalyzeRequest(url=url)
        resp = analyze_url(req)

        assert resp.risk_level == RiskLevel.SAFE, f"Expected SAFE for {url}, got {resp.risk_level}"
        assert resp.risk_score <= 25, f"Expected risk_score <= 25 for {url}, got {resp.risk_score}"
        assert resp.signals["model_status"] == "supervised_hist_gradient_boosting_active"
        assert resp.signals["ml_decision"] == "benign"
        assert resp.signals["ml_malicious_probability"] < 0.74


def test_benign_complex_urls_low_risk():
    """Verify complex enterprise and documentation URLs do not get flagged as threats."""
    complex_benign = [
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://cyberguard.io/documentation/architecture",
        "https://www.microsoft.com/en-us/security",
    ]

    for url in complex_benign:
        req = UrlAnalyzeRequest(url=url)
        resp = analyze_url(req)

        assert resp.risk_level in (RiskLevel.SAFE, RiskLevel.MEDIUM)
        assert resp.risk_score <= 45
        assert resp.signals["ml_decision"] == "benign"
        assert resp.signals["ml_malicious_probability"] < 0.74


def test_malicious_urls_supervised_inference():
    """Verify that phishing and deceptive URLs receive HIGH/CRITICAL risk scores and are flagged."""
    ml_flagged_samples = [
        "http://secure-paypal-login-account-update.xyz/verify.html",
        "http://chase-security-alert-verification.com/login.php",
        "http://netflix-billing-recovery-account.top/update",
        "http://apple-id-verify-locked-account.support/auth",
    ]

    for url in ml_flagged_samples:
        req = UrlAnalyzeRequest(url=url)
        resp = analyze_url(req)

        assert resp.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL), (
            f"Expected HIGH or CRITICAL for {url}, got {resp.risk_level}"
        )
        assert resp.risk_score >= 70, f"Expected risk_score >= 70 for {url}, got {resp.risk_score}"
        assert resp.signals["model_status"] == "supervised_hist_gradient_boosting_active"
        assert resp.signals["ml_decision"] == "malicious"
        assert resp.signals["ml_malicious_probability"] >= 0.74


def test_hybrid_phishing_url_detection():
    """Verify hybrid heuristic + ML catches raw IP spoofing and brand impersonation."""
    raw_ip_spoof = "http://192.168.1.1/paypal/login.php?cmd=verify"
    resp = analyze_url(UrlAnalyzeRequest(url=raw_ip_spoof))

    assert resp.risk_level == RiskLevel.CRITICAL
    assert resp.risk_score >= 90
    assert resp.signals["has_ip_address"] is True
    assert resp.signals["target_brand"] == "paypal"


def test_url_engine_empty_and_edge_inputs():
    """Verify safe handling of empty and edge case inputs."""
    # Empty URL
    req_empty = UrlAnalyzeRequest(url="")
    resp_empty = analyze_url(req_empty)
    assert resp_empty.risk_level == RiskLevel.SAFE
    assert resp_empty.risk_score == 0
    assert resp_empty.signals["model_status"] == "empty_input"

    # Whitespace URL
    req_space = UrlAnalyzeRequest(url="   ")
    resp_space = analyze_url(req_space)
    assert resp_space.risk_level == RiskLevel.SAFE
    assert resp_space.risk_score == 0

    # Very long URL
    long_url = "https://example.com/" + "a" * 500
    req_long = UrlAnalyzeRequest(url=long_url)
    resp_long = analyze_url(req_long)
    assert resp_long.signals["model_status"] == "supervised_hist_gradient_boosting_active"
    assert resp_long.signals["url_length"] > 500


def test_feature_extractor_column_alignment():
    """Verify extracted features match exactly the 16 model schema columns."""
    sample_url = "http://login.appleid.apple.com.suspicious-domain.tk/account"
    feats = extract_url_features(sample_url)
    for col in URL_FEATURE_COLUMNS:
        assert col in feats, f"Missing feature column: {col}"
        assert isinstance(feats[col], (int, float)), f"Feature {col} must be numeric"
