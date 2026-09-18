from app.schemas.analyze import SystemAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel

DEFAULT_OUTBOUND_BYTES = 104857600
DEFAULT_IP_REPUTATION_SCORE = 45


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
            "bytes_transferred": request.details.get("outbound_bytes", DEFAULT_OUTBOUND_BYTES),
            "ip_reputation_score": DEFAULT_IP_REPUTATION_SCORE,
            "unrecognized_process": True
        },
        recommended_actions=[
            "Inspect host process tree",
            "Temporarily isolate endpoint connection"
        ],
        confidence_score=0.82
    )
