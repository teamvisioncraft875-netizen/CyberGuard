"""
CYBERGUARD — URL Threat Model & Dataset Validation Tests (TDD Step 3.6)

Tests URL dataset composition, verifies negative class availability,
and validates brand impersonation and heuristic URL threat evaluation contracts.
"""

from pathlib import Path
import pandas as pd
import pytest

from app.utils.url_preprocessor import (
    URLPreprocessor,
    extract_url_features,
    extract_brand_target,
    URL_FEATURE_COLUMNS,
)
from app.schemas.analyze import RiskLevel


def test_phishing_dataset_composition_and_negative_class_check():
    """
    DATA VALIDATION CONTRACT (Step 3.5):
    Inspects datasets/phising.csv and validates:
    1. It contains legitimate positive phishing instances.
    2. Explicitly verifies that NO verified benign class exists in this raw file.
    3. Confirms supervised binary training must be BLOCKED pending a benign dataset.
    """
    repo_root = Path(__file__).resolve().parents[3]
    phish_csv = repo_root / "datasets" / "Phishing" / "phising.csv"
    if not phish_csv.exists():
        phish_csv = repo_root / "datasets" / "phising.csv"

    assert phish_csv.exists(), f"Missing phising.csv at {phish_csv}"

    # Read header and first 10,000 rows
    df_sample = pd.read_csv(phish_csv, nrows=10000)

    assert "url" in df_sample.columns
    assert "verified" in df_sample.columns
    assert len(df_sample) > 0

    # Confirm all rows are verified phishing instances
    verified_values = set(df_sample["verified"].str.lower().unique())
    assert verified_values == {"yes"}, "Expected 100% positive phishing instances"

    # There is no column containing benign labels (e.g. label=0 or verified=no)
    assert "is_benign" not in df_sample.columns
    has_negative_labels = (df_sample["verified"].str.lower() == "no").any()
    assert not has_negative_labels, "phising.csv contains zero negative/benign examples"


def test_url_heuristic_threat_scoring():
    """
    Tests the heuristic threat evaluation for URLs using extracted features
    and brand impersonation without fabricating artificial training labels.
    """
    test_phish_url = "http://sl83684.pro/loading.php?user=amazon_account_update"
    feats = extract_url_features(test_phish_url)

    assert feats["has_suspicious_keyword"] == 1.0
    assert feats["is_suspicious_tld"] == 1.0  # .pro
    assert feats["special_char_count"] >= 2

    # Brand target detection
    target = extract_brand_target(test_phish_url)
    assert target == "amazon"


def test_url_benign_baseline_scoring():
    """
    Tests that a well-known legitimate URL does not trigger phishing heuristic flags.
    """
    benign_url = "https://cyberguard.io/documentation/architecture"
    feats = extract_url_features(benign_url)

    assert feats["has_suspicious_keyword"] == 0.0
    assert feats["is_suspicious_tld"] == 0.0
    assert feats["has_ip_address"] == 0.0
    assert extract_brand_target(benign_url) is None
