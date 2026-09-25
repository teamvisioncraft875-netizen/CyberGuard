"""
Re-export analyzeSchema for backwards compatibility and standard naming.
"""
from app.schemas.analyzeSchema import (
    RiskLevel,
    MessageSourceType,
    MediaType,
    MessageAnalyzeRequest,
    UrlAnalyzeRequest,
    MediaAnalyzeRequest,
    LoginAnalyzeRequest,
    SystemAnalyzeRequest,
    UnifiedAnalysisResponse,
)

__all__ = [
    "RiskLevel",
    "MessageSourceType",
    "MediaType",
    "MessageAnalyzeRequest",
    "UrlAnalyzeRequest",
    "MediaAnalyzeRequest",
    "LoginAnalyzeRequest",
    "SystemAnalyzeRequest",
    "UnifiedAnalysisResponse",
]
