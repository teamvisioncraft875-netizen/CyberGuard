from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class MessageSourceType(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    SOCIAL = "social"


class MediaType(str, Enum):
    IMAGE = "image"
    AUDIO = "audio"


# Request Schemas
class MessageAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Message text content to evaluate")
    source_type: MessageSourceType = Field(..., description="Communication channel origin")


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=4, description="Target URL to inspect for look-alike or phishing indicators")


class MediaAnalyzeRequest(BaseModel):
    file_url: str = Field(..., min_length=4, description="Accessible URL of media file")
    media_type: MediaType = Field(..., description="Type of multimedia payload")


class LoginAnalyzeRequest(BaseModel):
    user_id: str = Field(..., description="Identifier of the authenticating user")
    timestamp: str = Field(..., description="ISO 8601 timestamp of login attempt")
    location: str = Field(..., description="Geographical or IP-derived location")
    device_id: str = Field(..., description="Device fingerprint or hardware identifier")
    failed_attempts: int = Field(0, ge=0, description="Consecutive failed attempt count")


class SystemAnalyzeRequest(BaseModel):
    user_id: str = Field(..., description="Identifier of the workstation user")
    timestamp: str = Field(..., description="ISO 8601 timestamp of event observation")
    event_type: str = Field(..., description="Category of system event e.g. network_spike")
    details: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event metrics and telemetry data")


# Unified Detection Response Schema
class UnifiedAnalysisResponse(BaseModel):
    risk_level: RiskLevel = Field(..., description="5-tier calibrated risk level")
    risk_score: int = Field(..., ge=0, le=100, description="Normalized risk score between 0 and 100")
    explanation: str = Field(..., description="Plain-English explanation of why this was flagged")
    signals: Dict[str, Any] = Field(default_factory=dict, description="Key extracted indicators and model features")
    recommended_actions: List[str] = Field(default_factory=list, description="Prescriptive remediation steps")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence score between 0.0 and 1.0")
