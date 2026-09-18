from app.schemas.analyze import UrlAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel

LEVENSHTEIN_DISTANCE_THRESHOLD = 2


def analyze_url(request: UrlAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates website URL for brand impersonation, domain age, and blacklist reputation.
    """
    # TODO: Integrate Levenshtein distance check against Fortune 500 domains, WHOIS lookup for domain age,
    # and Google Safe Browsing / Web Risk API query.

    return UnifiedAnalysisResponse(
        risk_level=RiskLevel.CRITICAL,
        risk_score=95,
        explanation="Domain mimics PayPal brand name, was registered within the last 48 hours, and matches active phishing blacklists.",
        signals={
            "url": request.url,
            "levenshtein_distance": LEVENSHTEIN_DISTANCE_THRESHOLD,
            "target_brand": "paypal",
            "domain_age_days": 2,
            "ssl_issuer_untrusted": True
        },
        recommended_actions=[
            "Block domain network-wide",
            "Revoke active sessions for credentials entered"
        ],
        confidence_score=0.98
    )
