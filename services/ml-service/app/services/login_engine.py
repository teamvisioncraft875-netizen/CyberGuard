from app.schemas.analyze import LoginAnalyzeRequest, UnifiedAnalysisResponse
from app.services.login_anomaly.engine import get_login_anomaly_engine


def analyze_login(request: LoginAnalyzeRequest) -> UnifiedAnalysisResponse:
    """
    Evaluates authentication attempt metadata against baseline behavioral distributions
    using the production trained Cowrie Isolation Forest anomaly engine.
    Fails loud on missing model or corrupted feature schema.
    """
    engine = get_login_anomaly_engine()
    return engine.analyze(request)

