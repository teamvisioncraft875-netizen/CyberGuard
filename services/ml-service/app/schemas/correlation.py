"""
CYBERGUARD Incident Correlation Engine — Data Contracts & Schemas.
Defines input/output schemas for multi-source alert clustering, entity aggregation,
timeline construction, MITRE ATT&CK progression, and Recommendation V1 integration.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class AlertEvent(BaseModel):
    alert_id: str = Field(..., description="Unique alert tracking ID")
    timestamp: Optional[Any] = Field(None, description="ISO timestamp or datetime of alert detection")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    sport: Optional[Any] = Field(None, description="Source port")
    dport: Optional[Any] = Field(None, description="Destination port")
    proto: Optional[str] = Field(None, description="Transport protocol (e.g. tcp, udp, icmp)")
    attack_type: Optional[str] = Field(None, description="Attack classification: c2_beacon, port_scan, spam, etc.")
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic ID (e.g. TA0011)")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID (e.g. T1071)")
    severity: Optional[str] = Field("medium", description="Alert severity: low, medium, high, critical")
    risk_score: Optional[float] = Field(50.0, ge=0.0, le=100.0, description="Risk score 0-100")
    source_engine: Optional[str] = Field("network", description="Originating detection engine")
    host: Optional[str] = Field(None, description="Affected host identifier")
    user: Optional[str] = Field(None, description="Associated user identity")
    raw_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary raw telemetry fields")


class CorrelationRequest(BaseModel):
    alerts: List[AlertEvent] = Field(default_factory=list, description="Batch of security alerts to correlate")
    time_window_seconds: Optional[float] = Field(3600.0, ge=1.0, description="Temporal window for pair candidate evaluation")
    correlation_threshold: Optional[float] = Field(0.50, ge=0.0, le=1.0, description="Pairwise similarity clustering threshold")
    
    # Future Model Compatibility Hooks (nullable by design):
    false_positive_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Nullable hook for future False Positive Engine integration. When null, engine operates normally."
    )


class CorrelatedIncident(BaseModel):
    incident_id: str = Field(..., description="Correlated incident UUID")
    correlation_id: str = Field(..., description="Correlation session identifier")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall cluster correlation confidence")
    alert_count: int = Field(..., ge=1, description="Number of correlated alerts in this incident")
    correlated_alert_ids: List[str] = Field(default_factory=list, description="IDs of alerts in this cluster")
    alerts: List[AlertEvent] = Field(default_factory=list, description="Full alerts forming this incident")
    entities: Dict[str, List[str]] = Field(default_factory=dict, description="Aggregated entities: hosts, users, ips, ports")
    timeline: Dict[str, Any] = Field(default_factory=dict, description="Temporal statistics: first_seen, last_seen, duration_seconds")
    mitre_tactics: List[str] = Field(default_factory=list, description="Observed MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="Observed MITRE ATT&CK techniques")
    threat_type: str = Field("unknown", description="Synthesized attack category")
    severity: str = Field("medium", description="Synthesized incident severity")
    risk_score: int = Field(50, ge=0, le=100, description="Synthesized incident risk score")
    incident_summary: str = Field(..., description="Analyst-readable incident narrative")


class CorrelationResponse(BaseModel):
    correlation_id: str = Field(..., description="Correlation session ID")
    incident_id: str = Field(..., description="Primary incident ID")
    status: str = Field("CORRELATION_SUCCESS", description="Engine execution status")
    model_version: str = Field("correlation_v1.0.0", description="Trained model version")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Primary cluster confidence")
    alerts: List[AlertEvent] = Field(default_factory=list, description="Alerts in primary incident")
    correlated_alert_ids: List[str] = Field(default_factory=list, description="IDs of correlated alerts in primary incident")
    entities: Dict[str, List[str]] = Field(default_factory=dict, description="Primary incident entities")
    timeline: Dict[str, Any] = Field(default_factory=dict, description="Primary incident timeline")
    mitre_tactics: List[str] = Field(default_factory=list, description="Primary incident tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="Primary incident techniques")
    incident_summary: str = Field(..., description="Primary incident narrative")
    incidents: List[CorrelatedIncident] = Field(default_factory=list, description="All clustered incidents found in batch")
