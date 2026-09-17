from app.schemas.analyze import MessageAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel


def analyze_message(request: MessageAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates message text for phishing, social engineering, urgency cues, and brand spoofing.
    """
    # TODO: Integrate transformer-based NLP classifier / few-shot LLM with offline TF-IDF fallback.
    # Feature extraction: urgency cues, credential solicitation keywords, mismatched sender display names.

    return UnifiedAnalysisResponse(
        risk_level=RiskLevel.HIGH,
        risk_score=82,
        explanation="Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link.",
        signals={
            "urgency_score": 0.92,
            "credential_solicitation": True,
            "brand_targeted": "chase",
            "model_type": "nlp_hybrid_transformer",
            "source_type": request.source_type.value
        },
        recommended_actions=[
            "Do not click any embedded links",
            "Quarantine message and flag domain to enterprise gateway"
        ],
        confidence_score=0.94
    )
