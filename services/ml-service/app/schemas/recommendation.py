"""
CYBERGUARD Incident Response Recommendation Engine — Data Contracts & Schemas.
Defines input/output contracts for incident contextualization, candidate response ranking,
safety guardrails, and future correlation/false-positive model compatibility.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class CandidateAction(BaseModel):
    action_id: str = Field(..., description="Unique action identifier e.g. 'isolate_device'")
    action_type: str = Field(..., description="Action category: containment, remediation, investigation, threat_hunt")
    title: str = Field(..., description="Human-readable title")
    description: Optional[str] = Field(None, description="Detailed action description")
    target: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Target host/user/IP/process")
    is_destructive: bool = Field(False, description="Flag for high-impact containment actions requiring approval")


class ActionRecommendation(BaseModel):
    rank: int = Field(..., ge=1, description="Ordinal priority ranking (1 = highest priority)")
    action_id: str = Field(..., description="Action identifier")
    action: str = Field(..., description="Standardized action code (e.g. isolate_device, revoke_session)")
    title: str = Field(..., description="Human-readable title")
    score: float = Field(..., ge=0.0, le=1.0, description="Ranking relevance score (0.0 - 1.0)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence (0.0 - 1.0)")
    rationale: str = Field(..., description="Analyst-readable rationale explaining why this action was ranked here")
    required_evidence: List[str] = Field(default_factory=list, description="Key telemetry markers triggering this action")
    risk_level: str = Field("medium", description="Risk level associated with incident context: low, medium, high, critical")
    mitre_mapping: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs")
    estimated_priority: str = Field("P2", description="Priority tier: P1, P2, P3, P4")
    is_destructive: bool = Field(False, description="Whether this action sever connectivity, terminates processes, or alters credentials")
    requires_approval: bool = Field(True, description="Strict safety gate: whether action requires human SOC analyst approval")


class IncidentRecommendationRequest(BaseModel):
    incident_id: str = Field(..., min_length=1, description="Unique incident UUID or tracking identifier")
    title: Optional[str] = Field(None, description="Incident summary title")
    description: Optional[str] = Field(None, description="Detailed incident narrative or alert description")
    severity: str = Field("medium", description="Incident severity: P1, P2, P3, P4, low, medium, high, critical")
    risk_score: int = Field(50, ge=0, le=100, description="Aggregated risk score between 0 and 100")
    threat_type: Optional[str] = Field(None, description="Primary attack category (phishing, malware, ddos, credential_stuffing, etc.)")
    entities: Dict[str, List[str]] = Field(default_factory=dict, description="Affected entities e.g. {'hosts': [], 'users': [], 'ips': []}")
    timeline: Dict[str, Any] = Field(default_factory=dict, description="Temporal statistics: first_seen, last_seen, alert_count, alerts_per_minute")
    alert_count: int = Field(1, ge=0, description="Total raw detection alerts grouped into this incident")
    source_engines: List[str] = Field(default_factory=list, description="Contributing CYBERGUARD engines (e.g. phishing, malware, media)")
    alert_types: List[str] = Field(default_factory=list, description="Detection types included in incident")
    mitre_techniques: List[str] = Field(default_factory=list, description="Observed MITRE ATT&CK technique IDs (e.g. T1566, T1204)")
    mitre_tactics: List[str] = Field(default_factory=list, description="Observed MITRE ATT&CK tactic IDs (e.g. TA0001, TA0002)")
    host_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Endpoint OS, agent status, isolation state")
    user_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="User department, privilege level, MFA status")
    network_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Egress IPs, port activity, protocol metadata")
    process_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Process GUID, parent process, command line arguments")
    current_incident_state: Optional[str] = Field("open", description="Workflow state: open, investigating, contained, resolved")
    
    # Future Model Compatibility Hooks (nullable by design):
    false_positive_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Nullable hook for future False Positive Engine integration. When null, engine operates normally."
    )
    correlation_id: Optional[str] = Field(
        None,
        description="Nullable hook for future Incident Correlation Engine integration."
    )
    candidate_actions: Optional[List[str]] = Field(
        None,
        description="Optional pre-filtered candidate action codes to rank. If None, engine evaluates full action catalog."
    )
    historical_context: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional historical actions previously tried on this incident"
    )


class IncidentRecommendationResponse(BaseModel):
    incident_id: str = Field(..., description="Target incident identifier")
    model_version: str = Field("v1.0.0-contract", description="Recommendation engine version")
    status: str = Field(..., description="Engine state: e.g. PROVISIONAL_RULES_RANKING_FALLBACK or MODEL_INFERENCE")
    recommendations: List[ActionRecommendation] = Field(default_factory=list, description="Ranked response and remediation actions")
    explanation: str = Field(..., description="Global synthesis of the ranked response strategy")
    data_gate_notice: Optional[str] = Field(
        None,
        description="Notice regarding training data availability and empirical learning status"
    )
