"""
CYBERGUARD Incident Response Recommendation Engine V1.
Provides machine-learning driven and contextual ranking of containment, remediation,
investigation, and threat-hunting actions for incoming security incidents.

Model Architecture:
- Calibrated Random Forest Classifier trained on real SOC incident response playbook data.
- Textual and categorical feature extraction (threat type, severity, assets, MITRE ATT&CK techniques/tactics).
- Preserves action safety guardrails: destructive actions always require approval.
- Preserves future compatibility with nullable false_positive_score and correlation_id.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import math
import logging
import joblib

from app.schemas.recommendation import (
    IncidentRecommendationRequest,
    IncidentRecommendationResponse,
    ActionRecommendation,
)

logger = logging.getLogger(__name__)

# Canonical action catalog aligned with services/backend response policies and SOC workflow
ACTION_CATALOG = {
    "isolate_device": {
        "title": "Isolate Host Endpoint",
        "description": "Sever network connectivity from infected workstation while keeping security telemetry link alive.",
        "category": "containment",
        "is_destructive": True,
        "default_priority": "P1",
        "relevant_threats": ["malware", "ransomware", "lateral_movement", "technical_threat"],
        "mitre_tactics": ["TA0002", "TA0008", "TA0040"],  # Execution, Lateral Movement, Impact
        "mitre_techniques": ["T1204", "T1021", "T1486"],
    },
    "kill_process": {
        "title": "Terminate Malicious Process Tree",
        "description": "Kill active executable payloads and child processes identified in detection telemetry.",
        "category": "containment",
        "is_destructive": True,
        "default_priority": "P1",
        "relevant_threats": ["malware", "crypto_miner", "technical_threat"],
        "mitre_tactics": ["TA0002", "TA0003"],  # Execution, Persistence
        "mitre_techniques": ["T1204", "T1059"],
    },
    "revoke_session": {
        "title": "Revoke User Active Sessions",
        "description": "Immediately terminate all active access and refresh tokens for compromised identity to halt session hijacking.",
        "category": "containment",
        "is_destructive": True,
        "default_priority": "P1",
        "relevant_threats": ["phishing", "credential_stuffing", "unauthorized_access", "account_takeover"],
        "mitre_tactics": ["TA0001", "TA0006"],  # Initial Access, Credential Access
        "mitre_techniques": ["T1566", "T1539", "T1110"],
    },
    "force_password_reset": {
        "title": "Force Password Reset",
        "description": "Invalidate existing password and prompt user for mandatory credential rotation on next authentication attempt.",
        "category": "remediation",
        "is_destructive": True,
        "default_priority": "P2",
        "relevant_threats": ["phishing", "credential_stuffing", "unauthorized_access"],
        "mitre_tactics": ["TA0001", "TA0006"],
        "mitre_techniques": ["T1566", "T1110"],
    },
    "block_ip": {
        "title": "Block Malicious IP at Perimeter Firewall",
        "description": "Deploy real-time firewall drop rule for malicious source or C2 IP addresses.",
        "category": "containment",
        "is_destructive": True,
        "default_priority": "P1",
        "relevant_threats": ["ddos", "c2_beacon", "malicious_url", "brute_force"],
        "mitre_tactics": ["TA0011", "TA0040"],  # Command and Control, Impact
        "mitre_techniques": ["T1071", "T1498"],
    },
    "block_domain": {
        "title": "Block Malicious Domain across Edge DNS/Proxy",
        "description": "Blacklist destination domain across web security proxy and DNS resolvers.",
        "category": "containment",
        "is_destructive": True,
        "default_priority": "P2",
        "relevant_threats": ["phishing", "malicious_url", "c2_beacon"],
        "mitre_tactics": ["TA0001", "TA0011"],
        "mitre_techniques": ["T1566", "T1071"],
    },
    "collect_process_tree": {
        "title": "Collect Endpoint Process Hierarchy & Memory Dump",
        "description": "Acquire forensic snapshot of running process ancestry and execution arguments for triage.",
        "category": "investigation",
        "is_destructive": False,
        "default_priority": "P2",
        "relevant_threats": ["malware", "technical_threat", "unauthorized_access"],
        "mitre_tactics": ["TA0002", "TA0007"],  # Discovery
        "mitre_techniques": ["T1057", "T1082"],
    },
    "run_antivirus_scan": {
        "title": "Trigger Deep Host Antivirus / Rootkit Scan",
        "description": "Dispatch agent scan across all local storage partitions to detect dormant secondary droppers.",
        "category": "investigation",
        "is_destructive": False,
        "default_priority": "P3",
        "relevant_threats": ["malware", "technical_threat"],
        "mitre_tactics": ["TA0002", "TA0003"],
        "mitre_techniques": ["T1204"],
    },
    "require_mfa": {
        "title": "Enforce Mandatory Multi-Factor Authentication",
        "description": "Elevate authentication policy requiring hardware or app-based MFA for target identity.",
        "category": "remediation",
        "is_destructive": False,
        "default_priority": "P2",
        "relevant_threats": ["credential_stuffing", "unauthorized_access", "phishing"],
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110"],
    },
    "hunt_historical_telemetry": {
        "title": "Threat Hunt: Scan Historical SIEM Logs for IOC Matches",
        "description": "Execute cross-workstation retrospective query over past 30 days for matched artifact hashes or IPs.",
        "category": "threat_hunt",
        "is_destructive": False,
        "default_priority": "P3",
        "relevant_threats": ["malware", "phishing", "c2_beacon", "deepfake"],
        "mitre_tactics": ["TA0007", "TA0009"],  # Collection
        "mitre_techniques": ["T1082", "T1005"],
    },
    "notify_admin": {
        "title": "Notify SOC Duty Officer & Escalation Team",
        "description": "Dispatch priority webhook and incident notification to security operations center lead.",
        "category": "investigation",
        "is_destructive": False,
        "default_priority": "P3",
        "relevant_threats": ["phishing", "malware", "ddos", "deepfake", "credential_stuffing"],
        "mitre_tactics": [],
        "mitre_techniques": [],
    },
}

# Production model path
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "recommendation" / "recommendation_classifier_v1.0.0.joblib"


class IncidentFeatureExtractor:
    """
    Extracts normalized quantitative and contextual feature representations from raw incident requests.
    Designed for zero-leakage training and deterministic inference.
    """
    SEVERITY_WEIGHTS = {
        "p1": 1.0, "critical": 1.0,
        "p2": 0.75, "high": 0.75,
        "p3": 0.50, "medium": 0.50,
        "p4": 0.25, "low": 0.25
    }

    @classmethod
    def extract_features(cls, req: IncidentRecommendationRequest) -> Dict[str, Any]:
        sev_key = (req.severity or "medium").lower()
        sev_weight = cls.SEVERITY_WEIGHTS.get(sev_key, 0.50)
        
        entities = req.entities or {}
        num_hosts = len(entities.get("hosts", []))
        num_users = len(entities.get("users", []))
        num_ips = len(entities.get("ips", []))
        num_devices = len(entities.get("devices", []))
        total_entities = num_hosts + num_users + num_ips + num_devices

        sources = set(s.lower() for s in (req.source_engines or []))
        techniques = set(t.upper() for t in (req.mitre_techniques or []))
        tactics = set(t.upper() for t in (req.mitre_tactics or []))

        fp_score = float(req.false_positive_score) if req.false_positive_score is not None else None

        # Build text string matching training representation
        threat_str = (req.threat_type or "").lower()
        asset_str = " ".join(entities.get("hosts", []) + entities.get("devices", []))
        source_str = " ".join(req.source_engines or [])
        vector_str = " ".join(req.alert_types or [])
        tactics_str = " ".join(req.mitre_tactics or []).lower()
        techniques_str = " ".join(req.mitre_techniques or []).lower()
        combined_text = f"{threat_str} {sev_key} {asset_str} {source_str} {vector_str} {tactics_str} {techniques_str}"

        return {
            "combined_text": combined_text,
            "risk_score_norm": req.risk_score / 100.0,
            "severity_weight": sev_weight,
            "alert_count_log": math.log1p(max(0, req.alert_count)),
            "num_hosts": num_hosts,
            "num_users": num_users,
            "num_ips": num_ips,
            "total_entities": total_entities,
            "has_phishing": 1.0 if "phishing" in sources else 0.0,
            "has_malware": 1.0 if "malware" in sources else 0.0,
            "has_url": 1.0 if any("url" in s for s in sources) else 0.0,
            "has_media": 1.0 if any("media" in s or "deepfake" in s for s in sources) else 0.0,
            "has_ddos": 1.0 if "ddos" in sources else 0.0,
            "num_mitre_techniques": len(techniques),
            "num_mitre_tactics": len(tactics),
            "false_positive_score": fp_score,
            "threat_type": threat_str,
            "techniques": list(techniques),
            "tactics": list(tactics),
        }


class MLRecommendationRanker:
    """
    Production recommendation ranking engine utilizing the trained Random Forest
    model artifact and contextual alignment.
    """
    _artifact = None

    @classmethod
    def load_model(cls) -> Optional[Dict[str, Any]]:
        if cls._artifact is None:
            if MODEL_PATH.exists():
                try:
                    cls._artifact = joblib.load(MODEL_PATH)
                    logger.info("Loaded recommendation model v1.0.0 artifact successfully.")
                except Exception as e:
                    logger.error(f"Error loading recommendation model artifact: {e}")
                    cls._artifact = None
        return cls._artifact

    @classmethod
    def rank_actions(cls, req: IncidentRecommendationRequest) -> List[ActionRecommendation]:
        model = cls.load_model()
        features = IncidentFeatureExtractor.extract_features(req)
        threat_type = features["threat_type"]
        techniques = set(features["techniques"])
        tactics = set(features["tactics"])
        risk_norm = features["risk_score_norm"]
        sev_weight = features["severity_weight"]
        fp_discount = (1.0 - features["false_positive_score"]) if features["false_positive_score"] is not None else 1.0

        candidate_keys = req.candidate_actions if req.candidate_actions else list(ACTION_CATALOG.keys())

        # If model is loaded, obtain classifier class probabilities
        ml_probs = {}
        if model is not None:
            try:
                vec = model["vectorizer"].transform([features["combined_text"]])
                probs = model["classifier"].predict_proba(vec)[0]
                classes = model["classifier"].classes_
                for cls_name, prob in zip(classes, probs):
                    ml_probs[str(cls_name)] = float(prob)
            except Exception as e:
                logger.warning(f"Error during ML inference, falling back to contextual rules: {e}")

        scored_actions = []

        for action_key in candidate_keys:
            if action_key not in ACTION_CATALOG:
                continue

            spec = ACTION_CATALOG[action_key]
            
            # Base contextual scoring
            base_score = 0.10
            category = spec.get("category", "")
            if category == "containment":
                base_score += 0.20
            elif category == "remediation":
                base_score += 0.10

            threat_match = any(t in threat_type for t in spec["relevant_threats"])
            if threat_match:
                base_score += 0.35

            technique_match = any(t in techniques for t in spec["mitre_techniques"])
            tactic_match = any(tac in tactics for tac in spec["mitre_tactics"])
            if technique_match:
                base_score += 0.25
            elif tactic_match:
                base_score += 0.15

            base_score += 0.15 * risk_norm + 0.10 * sev_weight

            # Blend with ML model probability if available
            ml_prob = ml_probs.get(action_key)
            if ml_prob is not None:
                # 65% empirical ML model probability + 35% incident context
                combined_score = 0.65 * ml_prob + 0.35 * base_score
                confidence = round(max(0.60, min(0.98, 0.50 + 0.50 * ml_prob)), 4)
            else:
                combined_score = base_score
                confidence = round(max(0.40, min(0.95, 0.50 + 0.30 * risk_norm + 0.15 * (1.0 if technique_match else 0.0))), 4)

            # Destructive action safety discounting when false positive probability is present
            if spec["is_destructive"] and features["false_positive_score"] is not None:
                combined_score *= fp_discount

            final_score = round(max(0.05, min(0.98, combined_score)), 4)

            # Synthesize analyst-readable rationale based on actual features
            rationale_parts = []
            if ml_prob is not None and ml_prob > 0.20:
                rationale_parts.append(f"Ranked by ML Recommendation Model V1 ({ml_prob*100:.1f}% action probability)")
            if threat_type:
                rationale_parts.append(f"Threat context matches '{threat_type}'")
            if technique_match:
                matched_t = [t for t in spec['mitre_techniques'] if t in techniques]
                rationale_parts.append(f"Observed ATT&CK technique {', '.join(matched_t)}")
            elif tactic_match:
                matched_tac = [t for t in spec['mitre_tactics'] if t in tactics]
                rationale_parts.append(f"Observed ATT&CK tactic {', '.join(matched_tac)}")
            if req.risk_score >= 70:
                rationale_parts.append(f"High risk score ({req.risk_score}/100) warrants intervention")

            rationale = "; ".join(rationale_parts) if rationale_parts else f"Recommended default {spec['category']} step"

            # Required evidence
            evidence = []
            if spec["category"] == "containment":
                evidence.append("Active malicious command or abnormal network egress")
            if technique_match:
                evidence.append(f"MITRE mapping: {spec['mitre_techniques']}")
            if req.alert_count > 1:
                evidence.append(f"Cluster of {req.alert_count} detection alerts")

            scored_actions.append({
                "action_id": action_key,
                "action": action_key,
                "title": spec["title"],
                "score": final_score,
                "confidence": confidence,
                "rationale": rationale,
                "required_evidence": evidence,
                "risk_level": "critical" if req.risk_score >= 80 else ("high" if req.risk_score >= 60 else "medium"),
                "mitre_mapping": spec["mitre_techniques"],
                "estimated_priority": spec["default_priority"],
                "is_destructive": spec["is_destructive"],
                "requires_approval": True,  # Phase 14 Action Safety: All recommended actions require approval
            })

        # Sort descending by score
        scored_actions.sort(key=lambda x: x["score"], reverse=True)

        recommendations = []
        for rank_idx, act in enumerate(scored_actions, start=1):
            recommendations.append(ActionRecommendation(
                rank=rank_idx,
                action_id=act["action_id"],
                action=act["action"],
                title=act["title"],
                score=act["score"],
                confidence=act["confidence"],
                rationale=act["rationale"],
                required_evidence=act["required_evidence"],
                risk_level=act["risk_level"],
                mitre_mapping=act["mitre_mapping"],
                estimated_priority=act["estimated_priority"],
                is_destructive=act["is_destructive"],
                requires_approval=act["requires_approval"]
            ))

        return recommendations


class ContextualRuleRanker:
    """
    Fallback deterministic ranking engine operating when model artifact is unavailable.
    """
    @classmethod
    def rank_actions(cls, req: IncidentRecommendationRequest) -> List[ActionRecommendation]:
        return MLRecommendationRanker.rank_actions(req)


def recommend_actions(request: IncidentRecommendationRequest) -> IncidentRecommendationResponse:
    """
    Main entrypoint for generating ranked incident response recommendations.
    Enforces strict safety, validated contracts, and audit logging.
    """
    ranked = MLRecommendationRanker.rank_actions(request)

    top_title = ranked[0].title if ranked else "No specific action"
    explanation = (
        f"Generated {len(ranked)} ranked remediation actions for incident {request.incident_id}. "
        f"Primary recommended response is '{top_title}'. All containment and destructive actions "
        f"require human SOC analyst approval."
    )

    model_loaded = MLRecommendationRanker.load_model() is not None
    model_version = "recommendation_v1.0.0" if model_loaded else "v1.0.0-baseline-rules"
    status = "PRODUCTION_RECOMMENDATION_ACTIVE" if model_loaded else "BLOCKED_BY_MISSING_REAL_RECOMMENDATION_DATA"

    return IncidentRecommendationResponse(
        incident_id=request.incident_id,
        model_version=model_version,
        status=status,
        recommendations=ranked,
        explanation=explanation,
        data_gate_notice=None
    )
