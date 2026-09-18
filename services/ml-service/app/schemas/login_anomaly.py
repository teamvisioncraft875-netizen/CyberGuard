"""
CyberGuard ML Service - Login Anomaly Detection Schemas
Unified threat response and telemetry input models.
"""

from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

RiskLevel = Literal["Safe", "Low", "Medium", "High", "Critical"]


class AnomalySignal(BaseModel):
    """Signal indicating a specific behavioral anomaly dimension and its relative weight."""
    name: str = Field(..., description="Machine-readable name of the telemetry signal")
    weight: float = Field(..., ge=0.0, le=1.0, description="Normalized signal contribution between 0.0 and 1.0")


class UnifiedAnomalyResult(BaseModel):
    """
    Standard CyberGuard unified detection contract.
    Must be returned by all threat engines.
    """
    risk_level: RiskLevel = Field(..., description="5-tier calibrated risk level")
    risk_score: int = Field(..., ge=0, le=100, description="Calibrated risk score between 0 and 100")
    explanation: str = Field(..., description="Human-readable plain-English explanation")
    recommended_action: str = Field(..., description="Concrete prescriptive remediation recommendation")
    signals: List[AnomalySignal] = Field(default_factory=list, description="List of individual behavioral anomaly signals")


class LoginEventInput(BaseModel):
    """Input representation of a login event for anomaly scoring."""
    user_id: Optional[str] = Field(None, description="Unique identifier for the user account")
    login_hour: Optional[int] = Field(None, ge=0, le=23, description="Hour of login event (0-23)")
    timestamp: Optional[str] = Field(None, description="ISO-8601 timestamp of login attempt")
    is_new_device: bool = Field(False, description="True if hardware/browser fingerprint is unrecognized")
    is_new_location: bool = Field(False, description="True if IP/geographic location is unrecognized")
    failed_attempts: int = Field(0, ge=0, description="Number of consecutive failed logins in recent window")
    impossible_travel: bool = Field(False, description="True if travel velocity from last login exceeds physical limits")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context metadata")
