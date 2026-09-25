from app.schemas.analyze import UrlAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel
from app.utils.url_preprocessor import extract_url_features, extract_brand_target


def analyze_url(request: UrlAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates website URL for brand impersonation, domain structure, and lexical threat indicators.
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
                "model_status": "heuristic_and_brand_matcher_active",
            },
            recommended_actions=["No action required; empty target"],
            confidence_score=1.0,
        )

    features = extract_url_features(url_str)
    target_brand = extract_brand_target(url_str)

    # Heuristic threat assessment based on lexical features and brand impersonation
    is_critical_phishing = (
        (target_brand is not None and features["is_suspicious_tld"] == 1.0)
        or (target_brand is not None and features["has_suspicious_keyword"] == 1.0)
        or (features["has_suspicious_keyword"] == 1.0 and features["is_suspicious_tld"] == 1.0)
        or (features["has_ip_address"] == 1.0 and features["has_suspicious_keyword"] == 1.0)
        or (features["has_ip_address"] == 1.0 and target_brand is not None)
    )

    if is_critical_phishing:
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
    elif (
        target_brand is not None
        or features["has_suspicious_keyword"] == 1.0
        or features["is_suspicious_tld"] == 1.0
        or features["has_ip_address"] == 1.0
    ):
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
            "engine": "URL & Phishing Threat Engine",
            "model_status": "heuristic_and_brand_matcher_active",
        },
        recommended_actions=recommended_actions,
        confidence_score=confidence,
    )
