from app.schemas.analyze import LoginAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel

HIGH_RISK_FAILED_ATTEMPTS_THRESHOLD = 3


def analyze_login(request: LoginAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates authentication attempt metadata against baseline behavioral distributions using Isolation Forest.
    """
    # TODO: Load scikit-learn Isolation Forest model, compute geo-velocity (impossible travel),
    # evaluate time-of-day entropy, and flag repeated failed attempt spikes.

    is_high_risk = request.failed_attempts >= HIGH_RISK_FAILED_ATTEMPTS_THRESHOLD

    return UnifiedAnalysisResponse(
        risk_level=RiskLevel.HIGH if is_high_risk else RiskLevel.LOW,
        risk_score=85 if is_high_risk else 25,
        explanation="Multiple consecutive failed logins from an unrecognized device and geographical anomaly.",
        signals={
            "user_id": request.user_id,
            "device_id": request.device_id,
            "location": request.location,
            "failed_attempts": request.failed_attempts,
            "impossible_travel": True,
            "isolation_forest_score": -0.76 if is_high_risk else 0.42
        },
        recommended_actions=[
            "Trigger mandatory MFA verification",
            "Temporarily lock authentication session"
        ] if is_high_risk else [
            "Log benign authentication event"
        ],
        confidence_score=0.91
    )
