"""
CYBERGUARD — URL & Phishing Preprocessor & Feature Extraction

Extracts structural, lexical, and brand-impersonation features from URLs.
Designed for use by url_engine.py, message_engine.py, and offline batch evaluators.
Guarantees deterministic, finite outputs and graceful handling of empty/corrupt URLs.
"""

import math
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
import numpy as np


URL_FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_subdomains",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "entropy",
    "is_https",
    "has_ip_address",
    "has_suspicious_keyword",
    "is_suspicious_tld",
    "is_brand_impersonated",
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
        query = parsed.query or ""
    except Exception:
        hostname = ""
        path = ""
        query = ""

    hostname_len = float(len(hostname))
    path_len = float(len(path))
    query_len = float(len(query))
    is_https = 1.0 if url_str.lower().startswith("https://") else 0.0

    # Subdomain, dot, and hyphen counts
    dot_count = float(url_str.count("."))
    hyphen_count = float(url_str.count("-"))
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

    # Brand target detection
    target_brand = extract_brand_target(url_str)
    is_brand_impersonated = 1.0 if target_brand is not None else 0.0

    # Shannon Entropy of URL
    entropy = calculate_entropy(url_str)

    return {
        "url_length": url_len,
        "hostname_length": hostname_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_subdomains": num_subdomains,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_count": special_char_count,
        "entropy": entropy,
        "is_https": is_https,
        "has_ip_address": has_ip_address,
        "has_suspicious_keyword": has_suspicious_keyword,
        "is_suspicious_tld": is_suspicious_tld,
        "is_brand_impersonated": is_brand_impersonated,
    }


AUTHENTIC_BRAND_DOMAINS: Dict[str, Set[str]] = {
    "amazon": {
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp",
        "amazon.ca", "amazon.in", "amazon.it", "amazon.es", "amazon.com.au",
        "amazon.com.mx", "aws.amazon.com", "media-amazon.com", "primevideo.com",
    },
    "paypal": {
        "paypal.com", "paypal.me", "paypal-community.com",
    },
    "microsoft": {
        "microsoft.com", "live.com", "office.com", "office365.com", "azure.com",
        "outlook.com", "microsoftonline.com", "windows.com", "visualstudio.com",
        "msn.com", "bing.com",
    },
    "apple": {
        "apple.com", "icloud.com", "appleid.apple.com", "cdn-apple.com", "mzstatic.com",
    },
    "google": {
        "google.com", "google.co.uk", "google.ca", "google.de", "google.co.in",
        "google.co.jp", "google.fr", "google.it", "google.es", "google.com.br",
        "google.com.au", "youtube.com", "blogger.com", "gmail.com",
        "googleusercontent.com", "gstatic.com", "googlesource.com",
    },
    "facebook": {
        "facebook.com", "fb.com", "meta.com", "messenger.com", "instagram.com", "whatsapp.com",
    },
    "netflix": {
        "netflix.com", "nflxext.com", "nflxvideo.net",
    },
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

TOP_LEGITIMATE_DOMAINS: Set[str] = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "linkedin.com", "apple.com", "icloud.com",
    "microsoft.com", "microsoftonline.com", "office.com", "live.com", "azure.com", "bing.com",
    "amazon.com", "aws.amazon.com", "wikipedia.org", "wikimedia.org",
    "github.com", "gitlab.com", "reddit.com", "stackoverflow.com", "netflix.com",
    "yahoo.com", "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "dhl.com", "fedex.com", "cloudflare.com", "wordpress.org", "wordpress.com",
    "medium.com", "nytimes.com", "cnn.com", "bbc.com", "bbc.co.uk", "reuters.com",
    "bloomberg.com", "mozilla.org", "adobe.com", "dropbox.com", "slack.com",
    "zoom.us", "spotify.com", "ebay.com", "walmart.com", "cyberguard.io",
}


def is_legitimate_domain(hostname: Optional[str]) -> bool:
    """
    Checks if a hostname belongs to an authentic, verified top-reputation domain
    or an authentic registered domain of a major service.
    """
    if not hostname:
        return False
    h = hostname.lower()

    # 1. Check top legitimate domains
    for d in TOP_LEGITIMATE_DOMAINS:
        if h == d or h.endswith("." + d):
            return True

    # 2. Check authentic brand ecosystems
    for brand, domains in AUTHENTIC_BRAND_DOMAINS.items():
        for ad in domains:
            if h == ad or h.endswith("." + ad):
                return True

    return False


def extract_brand_target(url: Optional[str], candidate_brands: Optional[List[str]] = None) -> Optional[str]:
    """
    Identifies which well-known brand is potentially targeted/impersonated by this URL.
    Returns the brand name only if:
    1. The URL is NOT hosted on an authentic domain of that brand, AND
    2. The URL is NOT hosted on a verified top legitimate domain, AND
    3. Either the hostname itself mentions or mimics the brand (e.g. 'paypal-security.com'),
       OR the URL mentions the brand while hosted on an untrusted / non-authentic host (e.g. 'sl83684.pro/amazon-login').
    """
    if not url or not isinstance(url, str):
        return None
    url_lower = url.lower()
    norm_url = url_lower if (url_lower.startswith("http://") or url_lower.startswith("https://")) else f"http://{url_lower}"
    try:
        parsed = urlparse(norm_url)
        hostname = (parsed.hostname or "").lower()
        path_and_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    except Exception:
        hostname = ""
        path_and_query = ""

    if not hostname:
        return None

    # Verified authentic top legitimate domains are not impersonation lures
    if is_legitimate_domain(hostname):
        return None

    brands = candidate_brands or DEFAULT_CANDIDATE_BRANDS
    for brand in brands:
        b_lower = brand.lower()
        auth_domains = AUTHENTIC_BRAND_DOMAINS.get(b_lower, {f"{b_lower}.com"})
        is_authentic = any(hostname == ad or hostname.endswith("." + ad) for ad in auth_domains)
        if is_authentic:
            continue

        # Check if brand appears in hostname (e.g. paypal-update.com, login.amazon.security.net)
        if b_lower in hostname:
            return b_lower

        # Check if brand appears in path/query on an untrusted host (e.g. sl83684.pro/loading.php?user=amazon_account_update)
        if b_lower in path_and_query:
            return b_lower

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
