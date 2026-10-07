"""
CYBERGUARD False Positive Detection & Alert Scoring Engine — Data Contracts & Schemas.
Defines input/output schemas for scoring security alerts, estimating false-positive probability,
providing explainability evidence, and guaranteeing advisory-only SOC workflow execution.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class FalsePositiveAnalysisRequest(BaseModel):
    alert_id: Optional[str] = Field(None, description="Optional upstream alert identifier")
    event_name: str = Field(..., min_length=1, max_length=128, description="Kernel syscall name or alert trigger action")
    process_name: str = Field(..., min_length=1, max_length=256, description="Executable process name generating the event")
    user_id: int = Field(..., ge=-1, le=2147483647, description="Linux User ID (0 for root, >=1000 for standard user)")
    args_num: int = Field(..., ge=0, le=1000, description="Count of syscall arguments")
    return_value: int = Field(..., ge=-2147483648, le=2147483647, description="Syscall exit code / return status")
    parent_process_id: Optional[int] = Field(-1, ge=-1, le=2147483647, description="Parent process PID (optional, defaults to -1)")
    
    # Optional operational context
    host: Optional[str] = Field(None, max_length=256, description="Host identifier (for logging/context, not used in model feature vector)")
    alert_type: Optional[str] = Field(None, max_length=128, description="Upstream alert classification")
    severity: Optional[str] = Field("medium", max_length=32, description="Severity: low, medium, high, critical")
    correlation_id: Optional[str] = Field(None, max_length=128, description="Optional Correlation V1 incident ID")

    @field_validator("event_name", "process_name")
    @classmethod
    def sanitize_strings(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("String field cannot be empty or whitespace only.")
        # Prevent path traversal strings in categorical fields
        if ".." in clean or clean.startswith("/"):
            # Strip path prefix to isolate binary name (e.g. /usr/bin/ps -> ps)
            clean = clean.split("/")[-1].split("\\")[-1]
        return clean or "unknown"


class FeatureExplanation(BaseModel):
    feature_name: str = Field(..., description="Feature evaluated")
    feature_value: Any = Field(..., description="Observed input value")
    contribution_direction: str = Field(..., description="'supports_false_positive' or 'supports_true_threat'")
    detail: str = Field(..., description="Human-readable explanation of impact")


class FalsePositiveExplanation(BaseModel):
    primary_factors: List[FeatureExplanation] = Field(default_factory=list, description="Key features influencing the score")
    summary: str = Field(..., description="Analyst summary of the assessment")
    model_version: str = Field(..., description="Model version generating this assessment")
    operating_threshold: float = Field(..., description="Classification threshold applied")


class FalsePositiveAnalysisResponse(BaseModel):
    alert_id: Optional[str] = Field(None, description="Original alert identifier if supplied")
    false_positive_score: float = Field(..., ge=0.0, le=1.0, description="Advisory false-positive score (0.0 to 1.0)")
    false_positive_probability: float = Field(..., ge=0.0, le=1.0, description="Calibrated probability that alert is a benign false alarm")
    classification: str = Field(..., description="'likely_false_positive' or 'likely_true_positive'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence of the decision")
    threshold: float = Field(..., description="Operating threshold used for binary classification")
    is_advisory_only: bool = Field(True, description="Strict safety guarantee: alerts are never automatically closed or suppressed")
    explanation: FalsePositiveExplanation = Field(..., description="Explainable AI reasoning for SOC analysts")
    model_version: str = Field("1.0.0", description="Authoritative registered model version")
    execution_time_ms: float = Field(..., ge=0.0, description="Inference latency in milliseconds")


class BatchFalsePositiveRequest(BaseModel):
    alerts: List[FalsePositiveAnalysisRequest] = Field(..., min_length=1, max_length=500, description="Batch of alerts to evaluate")


class BatchFalsePositiveResponse(BaseModel):
    results: List[FalsePositiveAnalysisResponse] = Field(..., description="Batch analysis results")
    total_evaluated: int = Field(..., ge=1, description="Total count of evaluated alerts")
    likely_false_positive_count: int = Field(..., ge=0, description="Count of alerts classified as likely false positives")
    likely_true_positive_count: int = Field(..., ge=0, description="Count of alerts classified as likely genuine threats")
    mean_execution_time_ms: float = Field(..., ge=0.0, description="Average inference latency per alert")
