"""
CYBERGUARD EDR Behavior Detection V1 — Data Contracts & Schemas.
Defines input/output schemas for endpoint behavioral classification,
process-tree lineage evaluation, and advisory-only SOC workflow execution.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class EDRBehaviorAnalysisRequest(BaseModel):
    process_name: str = Field(..., min_length=1, max_length=256, description="Executable binary/process name")
    event_name: str = Field(..., min_length=1, max_length=128, description="Kernel syscall or execution event name")
    user_id: int = Field(..., ge=-1, le=2147483647, description="Linux User ID (0 for root, >=1000 for standard user)")
    
    # Process Lineage context
    parent_process_name: Optional[str] = Field("UNKNOWN_PARENT", max_length=256, description="Spawning parent process name")
    parent_process_id: Optional[int] = Field(-1, ge=-1, le=2147483647, description="Parent PID (used solely for lineage graph)")
    process_id: Optional[int] = Field(-1, ge=-1, le=2147483647, description="Process PID (used solely for stateful tracking)")
    
    # Execution telemetry
    return_value: Optional[int] = Field(0, ge=-2147483648, le=2147483647, description="Syscall return status code")
    args_num: Optional[int] = Field(0, ge=0, le=1000, description="Syscall argument count")
    timestamp: Optional[float] = Field(None, description="Event timestamp in seconds")
    
    # Optional operational identifiers
    host: Optional[str] = Field(None, max_length=256, description="Host identifier (for logging/context, not used in model feature vector)")
    correlation_id: Optional[str] = Field(None, max_length=128, description="Optional incident correlation ID")
    alert_id: Optional[str] = Field(None, max_length=128, description="Optional alert identifier")

    @field_validator("process_name", "parent_process_name", "event_name")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> str:
        if v is None:
            return "unknown"
        clean = v.strip()
        if not clean:
            return "unknown"
        # Sanitize path prefixes to isolate binary name (e.g. /usr/bin/ps -> ps)
        if ".." in clean or clean.startswith("/"):
            clean = clean.split("/")[-1].split("\\")[-1]
        return clean or "unknown"


class EDRBehaviorAnalysisResponse(BaseModel):
    behavior_score: float = Field(..., ge=0.0, le=1.0, description="Continuous behavioral threat score (0.0 benign to 1.0 malicious)")
    malicious_probability: float = Field(..., ge=0.0, le=1.0, description="Estimated probability that execution represents active attack")
    classification: str = Field(..., description="'malicious_behavior' or 'benign_behavior'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence of the classification decision")
    behavior_summary: str = Field(..., description="Advisory summary describing the observed behavioral threat profile")
    observed_process_chain: str = Field(..., description="Reconstructed process execution chain (e.g., 'sshd -> bash -> tsm')")
    operating_threshold: float = Field(0.0300, description="Locked operational decision threshold")
    is_advisory_only: bool = Field(True, description="Strict safety guarantee: no automatic killing, quarantining, blocking, or deletion")
    mitre_context: Optional[Dict[str, Any]] = Field(None, description="Advisory MITRE ATT&CK tactic/technique mapping if applicable")
