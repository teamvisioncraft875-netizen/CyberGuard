from app.schemas.analyze import SystemAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel


def analyze_system(request: SystemAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates host system process metrics and network traffic outbound spikes.
    """
    # TODO: Evaluate process name against threat signatures, check destination IP reputation,
    # and compare outbound byte volume against rolling z-score baseline.

    return UnifiedAnalysisResponse(
        risk_level=RiskLevel.MEDIUM,
        risk_score=58,
        explanation="Sudden outbound traffic surge to an unknown external IP address unaccompanied by recognized application processes.",
        signals={
            "user_id": request.user_id,
            "event_type": request.event_type,
            "bytes_transferred": request.details.get("outbound_bytes", 104857600),
            "ip_reputation_score": 45,
            "unrecognized_process": True
        },
        recommended_actions=[
            "Inspect host process tree",
            "Temporarily isolate endpoint connection"
        ],
        confidence_score=0.82
    )
