from fastapi import APIRouter, status
from app.schemas.analyze import (
    MessageAnalyzeRequest,
    UrlAnalyzeRequest,
    MediaAnalyzeRequest,
    LoginAnalyzeRequest,
    SystemAnalyzeRequest,
    UnifiedAnalysisResponse
)
from app.services.message_engine import analyze_message
from app.services.url_engine import analyze_url
from app.services.media_engine import analyze_media
from app.services.login_engine import analyze_login
from app.services.system_engine import analyze_system

router = APIRouter(prefix="/analyze", tags=["Threat Analysis Engines"])


@router.post("/message", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_message_endpoint(payload: MessageAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze message text for phishing, social engineering, and urgent credential lures."""
    return analyze_message(payload)


@router.post("/url", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_url_endpoint(payload: UrlAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze domain URL for typosquatting, look-alike patterns, and reputation anomalies."""
    return analyze_url(payload)


@router.post("/media", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_media_endpoint(payload: MediaAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze uploaded images or audio recordings for synthetic manipulation or voice cloning."""
    return analyze_media(payload)


@router.post("/login", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_login_endpoint(payload: LoginAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze login metadata for credential stuffing, geographical velocity, and device anomalies."""
    return analyze_login(payload)


@router.post("/system", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_system_endpoint(payload: SystemAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze workstation telemetry for process anomalies, network surges, and host deviations."""
    return analyze_system(payload)
