import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import warnings
import joblib
import numpy as np

from urllib.parse import urlparse
from app.schemas.analyze import UrlAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel
from app.utils.url_preprocessor import (
    extract_url_features,
    extract_brand_target,
    URL_FEATURE_COLUMNS,
    is_legitimate_domain,
)

logger = logging.getLogger("cyberguard.url_engine")

_MODEL_DIR = Path(__file__).resolve().parents[1] / "models" / "url"
_CLASSIFIER_PATH = _MODEL_DIR / "malicious_url_classifier_v1.0.0.joblib"
_METADATA_PATH = _MODEL_DIR / "malicious_url_metadata_v1.0.0.json"

_CACHED_URL_MODEL = None
_CACHED_URL_METADATA = None


def _get_url_model() -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """Lazy loader for trained HistGradientBoosting URL classifier."""
    global _CACHED_URL_MODEL, _CACHED_URL_METADATA
    if _CACHED_URL_MODEL is None and _CLASSIFIER_PATH.exists():
        try:
            _CACHED_URL_MODEL = joblib.load(_CLASSIFIER_PATH)
            if _METADATA_PATH.exists():
                with open(_METADATA_PATH, "r", encoding="utf-8") as f:
                    _CACHED_URL_METADATA = json.load(f)
            logger.info("Successfully loaded supervised Malicious URL classifier v1.0.0")
        except Exception as e:
            logger.warning(f"Failed to load URL model: {e}")
            _CACHED_URL_MODEL = None
            _CACHED_URL_METADATA = None
    return _CACHED_URL_MODEL, _CACHED_URL_METADATA


def analyze_url(request: UrlAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates website URL using supervised ML classification combined with
    brand impersonation, domain structure, and lexical threat indicators.
    """
    url_str = (request.url or "").strip()
    if not url_str:
        return UnifiedAnalysisResponse(
            risk_level=RiskLevel.SAFE,
            risk_score=0,
            explanation="Empty URL provided; no threat indicators present.",
            signals={
                "url": "",
                "target_brand": "none",
                "url_length": 0,
                "num_subdomains": 0,
                "entropy": 0.0,
                "has_suspicious_keyword": False,
                "is_suspicious_tld": False,
                "has_ip_address": False,
                "engine": "URL & Phishing Threat Engine",
                "model_status": "empty_input",
            },
            recommended_actions=["No action required; empty target"],
            confidence_score=1.0,
        )

    # Extract hostname and verify domain legitimacy
    norm_url = url_str if (url_str.startswith("http://") or url_str.startswith("https://")) else f"http://{url_str}"
    try:
        parsed = urlparse(norm_url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = ""

    is_trusted = is_legitimate_domain(hostname)

    features = extract_url_features(url_str)
    target_brand = extract_brand_target(url_str) if not is_trusted else None

    # Compound heuristic pattern detection for untrusted hosts
    is_critical_phishing = (
        not is_trusted and (
            (target_brand is not None and features["is_suspicious_tld"] == 1.0)
            or (target_brand is not None and features["has_suspicious_keyword"] == 1.0)
            or (features["has_suspicious_keyword"] == 1.0 and features["is_suspicious_tld"] == 1.0)
            or (features["has_ip_address"] == 1.0 and features["has_suspicious_keyword"] == 1.0)
            or (features["has_ip_address"] == 1.0 and target_brand is not None)
            or (target_brand is not None and features["entropy"] >= 3.8 and features["num_subdomains"] >= 2)
        )
    )

    # Supervised ML inference
    model, meta = _get_url_model()
    ml_prob = None
    threshold = 0.48

    if model is not None:
        try:
            vec = np.array([[features.get(col, 0.0) for col in URL_FEATURE_COLUMNS]], dtype=np.float64)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                ml_prob = float(model.predict_proba(vec)[0, 1])
            threshold = float(meta.get("operating_threshold", 0.72)) if meta else 0.72
        except Exception as e:
            logger.warning(f"Supervised URL inference failed: {e}. Falling back to heuristics.")
            ml_prob = None

    if is_trusted:
        # Verified authentic legitimate infrastructure (Google, Apple, Microsoft, GitHub, Wikipedia, etc.)
        risk_level = RiskLevel.SAFE
        risk_score = 5
        explanation = "URL hosted on verified authentic and legitimate domain infrastructure."
        recommended_actions = ["No action required; safe to browse"]
        confidence = 0.99

    elif ml_prob is not None:
        is_threat = ml_prob >= threshold
        if is_critical_phishing:
            risk_level = RiskLevel.CRITICAL
            brand_name = target_brand.title() if target_brand else "major enterprise"
            risk_score = min(100, max(90, int(ml_prob * 100))) if is_threat else 95
            explanation = (
                f"Critical Threat: Domain mimics {brand_name} brand patterns, utilizes high-risk TLD or raw IP, "
                f"and matches active phishing structural signatures (Probability: {ml_prob:.1%})."
            )
            recommended_actions = [
                "Block domain network-wide on gateway and DNS",
                "Revoke active sessions for credentials entered on this site",
            ]
            confidence = max(0.95, round(ml_prob, 4))
        elif is_threat or target_brand or (features["has_suspicious_keyword"] == 1.0 and features["is_suspicious_tld"] == 1.0) or features["has_ip_address"] == 1.0:
            risk_level = RiskLevel.HIGH
            risk_score = min(89, max(70, int(70 + (ml_prob - threshold) / max(0.01, 1.0 - threshold) * 19))) if is_threat else 75
            matched_indicators = []
            if target_brand:
                matched_indicators.append(f"brand reference '{target_brand}'")
            if features["has_suspicious_keyword"]:
                matched_indicators.append("credential-harvesting keyword")
            if features["is_suspicious_tld"]:
                matched_indicators.append("elevated-risk TLD")
            if features["has_ip_address"]:
                matched_indicators.append("raw host IP address")
            explanation = f"Suspicious URL detected by supervised classifier (Probability: {ml_prob:.1%}): contains {', '.join(matched_indicators) if matched_indicators else 'anomalous lexical signatures'}."
            recommended_actions = [
                "Warn user against submitting credentials",
                "Isolate URL in sandbox browser",
            ]
            confidence = max(0.85, round(ml_prob, 4))
        elif features["has_suspicious_keyword"] == 1.0 or features["is_suspicious_tld"] == 1.0:
            risk_level = RiskLevel.MEDIUM
            risk_score = 45
            explanation = "Moderate Risk: URL contains sensitive keywords or non-standard domain structure on an unverified host."
            recommended_actions = [
                "Exercise caution before submitting credentials",
                "Verify domain authenticity before logging in",
            ]
            confidence = 0.80
        else:
            risk_level = RiskLevel.SAFE
            risk_score = max(5, min(19, int(ml_prob * 19)))
            explanation = "URL structure conforms to standard legitimate domain patterns."
            recommended_actions = ["No action required; safe to browse"]
            confidence = max(0.85, round(1.0 - ml_prob, 4))

    else:
        # Fallback heuristic logic if model unreadable
        if is_trusted:
            risk_level = RiskLevel.SAFE
            risk_score = 5
            explanation = "URL hosted on verified authentic and legitimate domain infrastructure."
            recommended_actions = ["No action required; safe to browse"]
            confidence = 0.99
        elif is_critical_phishing:
            risk_level = RiskLevel.CRITICAL
            risk_score = 95
            brand_name = target_brand.title() if target_brand else "major enterprise"
            explanation = (
                f"Domain mimics {brand_name} brand patterns, utilizes high-risk TLD or raw IP, "
                f"and matches active phishing structural signatures."
            )
            recommended_actions = [
                "Block domain network-wide on gateway and DNS",
                "Revoke active sessions for credentials entered on this site",
            ]
            confidence = 0.98
        elif target_brand is not None or (features["has_suspicious_keyword"] == 1.0 and features["is_suspicious_tld"] == 1.0) or features["has_ip_address"] == 1.0:
            risk_level = RiskLevel.HIGH
            risk_score = 75
            matched_indicators = []
            if target_brand:
                matched_indicators.append(f"brand reference '{target_brand}'")
            if features["has_suspicious_keyword"]:
                matched_indicators.append("credential-harvesting keyword")
            if features["is_suspicious_tld"]:
                matched_indicators.append("elevated-risk TLD")
            if features["has_ip_address"]:
                matched_indicators.append("raw host IP address")
            explanation = f"Suspicious URL detected: contains {', '.join(matched_indicators)}."
            recommended_actions = [
                "Warn user against submitting credentials",
                "Isolate URL in sandbox browser",
            ]
            confidence = 0.85
        elif features["has_suspicious_keyword"] == 1.0 or features["is_suspicious_tld"] == 1.0:
            risk_level = RiskLevel.MEDIUM
            risk_score = 45
            explanation = "Moderate Risk: URL contains sensitive keywords or non-standard domain structure on an unverified host."
            recommended_actions = [
                "Exercise caution before submitting credentials",
                "Verify domain authenticity before logging in",
            ]
            confidence = 0.80
        else:
            risk_level = RiskLevel.SAFE
            risk_score = 10
            explanation = "URL structure conforms to standard legitimate domain patterns."
            recommended_actions = ["No action required; safe to browse"]
            confidence = 0.90

    return UnifiedAnalysisResponse(
        risk_level=risk_level,
        risk_score=risk_score,
        explanation=explanation,
        signals={
            "url": url_str,
            "target_brand": target_brand or "none",
            "url_length": int(features["url_length"]),
            "num_subdomains": int(features["num_subdomains"]),
            "entropy": float(round(features["entropy"], 3)),
            "has_suspicious_keyword": bool(features["has_suspicious_keyword"]),
            "is_suspicious_tld": bool(features["is_suspicious_tld"]),
            "has_ip_address": bool(features["has_ip_address"]),
            "ml_malicious_probability": round(ml_prob, 4) if ml_prob is not None else None,
            "ml_decision": "malicious" if (ml_prob is not None and ml_prob >= threshold) else "benign",
            "operating_threshold": threshold,
            "engine": "URL & Phishing Threat Engine",
            "model_status": "supervised_hist_gradient_boosting_active" if ml_prob is not None else "heuristic_fallback_active",
        },
        recommended_actions=recommended_actions,
        confidence_score=confidence,
    )

