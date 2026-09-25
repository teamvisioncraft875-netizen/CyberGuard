import pytest
import pandas as pd
import numpy as np

# TDD Step 2.4: This import will fail initially until url_preprocessor is implemented
from app.utils.url_preprocessor import (
    URLPreprocessor,
    extract_url_features,
    extract_brand_target,
    calculate_entropy,
    URL_FEATURE_COLUMNS,
)


SAMPLE_URLS = [
    # 1. Obvious Phishing URL with keyword, ip/subdomain, high entropy
    "https://espacesecu-tehna.com/index.php?login=verify&token=9823f4",
    # 2. Short, clean benign URL
    "https://google.com/",
    # 3. Phishing targeting Amazon with suspicious TLD and keywords
    "http://sl83684.pro/loading.php?user=amazon_account_update",
    # 4. Raw IP address URL
    "http://192.168.1.50/secure/banking/login",
    # 5. Invalid / Empty / Corrupt URL
    "",
    None,
]


def test_url_feature_columns_defined():
    """Verify that expected URL feature columns are explicitly defined."""
    assert isinstance(URL_FEATURE_COLUMNS, list)
    expected_subset = {
        "url_length",
        "hostname_length",
        "path_length",
        "num_subdomains",
        "digit_count",
        "special_char_count",
        "entropy",
        "is_https",
        "has_ip_address",
        "has_suspicious_keyword",
        "is_suspicious_tld",
    }
    assert expected_subset.issubset(set(URL_FEATURE_COLUMNS))


def test_url_parsing_and_lengths():
    """Verify URL length, hostname length, and path length calculation."""
    url = "https://espacesecu-tehna.com/index.php"
    feats = extract_url_features(url)
    assert feats["url_length"] == len(url)
    assert feats["hostname_length"] == len("espacesecu-tehna.com")
    assert feats["path_length"] == len("/index.php")
    assert feats["is_https"] == 1


def test_subdomains_and_special_chars():
    """Verify subdomains, digits, and special characters counting."""
    url = "http://sub.domain.secure-login.pro/test?a=1&b=2"
    feats = extract_url_features(url)
    assert feats["num_subdomains"] >= 2
    assert feats["special_char_count"] >= 3  # contains '?', '=', '&', '-'
    assert feats["digit_count"] >= 2  # '1', '2'
    assert feats["is_suspicious_tld"] == 1  # .pro is in suspicious TLD list


def test_suspicious_keyword_detection():
    """Verify suspicious security/phishing keywords are detected."""
    url_threat = "http://sl83684.pro/loading.php?user=amazon_account_update"
    feats_threat = extract_url_features(url_threat)
    assert feats_threat["has_suspicious_keyword"] == 1

    url_benign = "https://example.com/about/team"
    feats_benign = extract_url_features(url_benign)
    assert feats_benign["has_suspicious_keyword"] == 0


def test_ip_address_detection():
    """Verify numeric IP address hostnames are flagged."""
    url_ip = "http://192.168.1.50/secure/banking/login"
    feats = extract_url_features(url_ip)
    assert feats["has_ip_address"] == 1

    url_normal = "https://cyberguard.io/dashboard"
    feats_normal = extract_url_features(url_normal)
    assert feats_normal["has_ip_address"] == 0


def test_entropy_calculation():
    """Verify Shannon entropy calculation returns expected non-negative values."""
    entropy_random = calculate_entropy("x8f02j2kd9sl20kdf")
    entropy_simple = calculate_entropy("aaaaaaa")
    assert entropy_random > entropy_simple
    assert calculate_entropy("") == 0.0


def test_missing_and_corrupt_urls_handled_safely():
    """Verify None, empty string, and malformed inputs do not raise unhandled exceptions."""
    feats_empty = extract_url_features("")
    assert feats_empty["url_length"] == 0
    assert feats_empty["entropy"] == 0.0
    assert np.isfinite(list(feats_empty.values())).all()

    feats_none = extract_url_features(None)
    assert feats_none["url_length"] == 0
    assert np.isfinite(list(feats_none.values())).all()


def test_brand_target_extraction():
    """Verify target brand detection operates separately from generic lexical extraction."""
    known_brands = ["amazon", "paypal", "microsoft", "apple", "google"]
    
    brand_hit = extract_brand_target("http://sl83684.pro/amazon-login", candidate_brands=known_brands)
    assert brand_hit == "amazon"

    brand_none = extract_brand_target("https://random-weather-app.org/forecast", candidate_brands=known_brands)
    assert brand_none is None


def test_url_preprocessor_dataframe_deterministic():
    """Verify URLPreprocessor processes DataFrame batches deterministically without NaNs."""
    df_raw = pd.DataFrame({"url": SAMPLE_URLS})
    preprocessor = URLPreprocessor()

    feats1 = preprocessor.transform(df_raw)
    feats2 = preprocessor.transform(df_raw)

    pd.testing.assert_frame_equal(feats1, feats2)
    assert not feats1.isnull().values.any()
    assert list(feats1.columns) == URL_FEATURE_COLUMNS
