"""
CYBERGUARD — URL & Phishing Preprocessor & Feature Extraction

Extracts structural, lexical, and brand-impersonation features from URLs.
Designed for use by url_engine.py, message_engine.py, and offline batch evaluators.
Guarantees deterministic, finite outputs and graceful handling of empty/corrupt URLs.
"""

import math
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import numpy as np


URL_FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_subdomains",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "entropy",
    "is_https",
    "has_ip_address",
    "has_suspicious_keyword",
    "is_suspicious_tld",
]

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "banking",
    "secure",
    "update",
    "signin",
    "confirm",
    "billing",
    "abonnements",
    "loading",
    "password",
    "credential",
    "auth",
    "wallet",
    "support",
    "alert",
}

SUSPICIOUS_TLDS = {
    ".pro",
    ".top",
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".fit",
    ".work",
    ".click",
    ".link",
    ".info",
    ".club",
}

DEFAULT_CANDIDATE_BRANDS = [
    "amazon",
    "paypal",
    "microsoft",
    "apple",
    "google",
    "facebook",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "dhl",
    "fedex",
]

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SPECIAL_CHARS = set("-@?=_&%#+/:")


def calculate_entropy(text: Optional[str]) -> float:
    """Calculates Shannon entropy of string characters."""
    if not text:
        return 0.0
    text_len = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / text_len
        entropy -= prob * math.log2(prob)
    return float(entropy)


def extract_url_features(url: Optional[str]) -> Dict[str, float]:
    """
    Extracts numerical lexical features from a single URL string.
    Guarantees no NaNs and returns exact URL_FEATURE_COLUMNS.
    """
    if not url or not isinstance(url, str):
        return {col: 0.0 for col in URL_FEATURE_COLUMNS}

    url_str = url.strip()
    url_len = float(len(url_str))
    if url_len == 0:
        return {col: 0.0 for col in URL_FEATURE_COLUMNS}

    # Normalize schema for urllib parsing
    norm_url = url_str if (url_str.startswith("http://") or url_str.startswith("https://")) else f"http://{url_str}"

    try:
        parsed = urlparse(norm_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""

    hostname_len = float(len(hostname))
    path_len = float(len(path))
    is_https = 1.0 if url_str.lower().startswith("https://") else 0.0

    # Subdomain count
    if hostname:
        subdomains = [p for p in hostname.split(".") if p]
        num_subdomains = float(max(0, len(subdomains) - 2))
    else:
        num_subdomains = 0.0

    # Digit counts & ratio
    digit_count = float(sum(1 for c in url_str if c.isdigit()))
    digit_ratio = digit_count / max(url_len, 1.0)

    # Special characters
    special_char_count = float(sum(1 for c in url_str if c in SPECIAL_CHARS))

    # IP address check in hostname
    has_ip_address = 1.0 if IP_REGEX.match(hostname) else 0.0

    # Suspicious keywords in URL string
    url_lower = url_str.lower()
    has_suspicious_keyword = 1.0 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0.0

    # Suspicious TLD check
    is_suspicious_tld = 0.0
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            is_suspicious_tld = 1.0
            break

    # Shannon Entropy of URL
    entropy = calculate_entropy(url_str)

    return {
        "url_length": url_len,
        "hostname_length": hostname_len,
        "path_length": path_len,
        "num_subdomains": num_subdomains,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_count": special_char_count,
        "entropy": entropy,
        "is_https": is_https,
        "has_ip_address": has_ip_address,
        "has_suspicious_keyword": has_suspicious_keyword,
        "is_suspicious_tld": is_suspicious_tld,
    }


def extract_brand_target(url: Optional[str], candidate_brands: Optional[List[str]] = None) -> Optional[str]:
    """
    Identifies which well-known brand is potentially targeted/impersonated by this URL.
    Kept separate from generic numerical features per modular architecture.
    """
    if not url or not isinstance(url, str):
        return None
    url_lower = url.lower()
    brands = candidate_brands or DEFAULT_CANDIDATE_BRANDS
    for brand in brands:
        if brand.lower() in url_lower:
            return brand.lower()
    return None


class URLPreprocessor:
    """
    Batch preprocessor for transforming raw URL datasets into numerical matrices.
    """

    def __init__(self, feature_columns: Optional[List[str]] = None):
        self.feature_columns = feature_columns or URL_FEATURE_COLUMNS

    def transform(self, df: Any, url_column: str = "url") -> Any:
        """Transforms a DataFrame containing a URL column into numerical features."""
        try:
            import pandas as pd
        except ImportError:
            raise RuntimeError("pandas is required for URLPreprocessor.transform")

        if df.empty or url_column not in df.columns:
            return pd.DataFrame(columns=self.feature_columns, dtype=np.float64)

        feature_dicts = [extract_url_features(u) for u in df[url_column]]
        result_df = pd.DataFrame(feature_dicts, index=df.index)[self.feature_columns]
        return result_df
