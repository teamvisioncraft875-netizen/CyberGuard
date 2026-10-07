"""
CYBERGUARD Incident Correlation Engine V1.
Performs machine-learning driven alert clustering and attack progression correlation
using the trained Random Forest model artifact.

Outputs unified incidents compatible with Recommendation V1 and SOC investigation feeds.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import uuid
import logging
import numpy as np
import joblib

from app.schemas.correlation import (
    AlertEvent,
    CorrelationRequest,
    CorrelatedIncident,
    CorrelationResponse,
)
from app.schemas.recommendation import IncidentRecommendationRequest

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "correlation" / "correlation_classifier_v1.0.0.joblib"


class CorrelationFeatureExtractor:
    """
    Extracts normalized pairwise contextual and temporal features between security alerts.
    """
    @staticmethod
    def parse_datetime(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S"
            ):
                try:
                    return datetime.strptime(val.strip(), fmt)
                except ValueError:
                    pass
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass
        return datetime.now(timezone.utc).replace(tzinfo=None)

    @classmethod
    def extract_pair_features(cls, a1: AlertEvent, a2: AlertEvent) -> np.ndarray:
        t1 = cls.parse_datetime(a1.timestamp)
        t2 = cls.parse_datetime(a2.timestamp)
        dt = abs((t1 - t2).total_seconds())
        dt_log = float(np.log1p(dt))
        time_decay = float(np.exp(-dt / 1800.0))

        src1 = str(a1.src_ip or "").strip()
        src2 = str(a2.src_ip or "").strip()
        dst1 = str(a1.dst_ip or "").strip()
        dst2 = str(a2.dst_ip or "").strip()

        same_src = 1.0 if (src1 and src2 and src1 == src2) else 0.0
        same_dst = 1.0 if (dst1 and dst2 and dst1 == dst2) else 0.0

        ips1 = {ip for ip in (src1, dst1) if ip}
        ips2 = {ip for ip in (src2, dst2) if ip}
        shared_ip = 1.0 if (ips1 and ips2 and len(ips1.intersection(ips2)) > 0) else 0.0

        p1 = str(a1.proto or "").lower().strip()
        p2 = str(a2.proto or "").lower().strip()
        same_proto = 1.0 if (p1 and p2 and p1 == p2) else 0.0

        dp1 = str(a1.dport or "").strip()
        dp2 = str(a2.dport or "").strip()
        same_dport = 1.0 if (dp1 and dp2 and dp1 == dp2) else 0.0

        at1 = str(a1.attack_type or "").lower().strip()
        at2 = str(a2.attack_type or "").lower().strip()
        same_attack = 1.0 if (at1 and at2 and at1 == at2) else 0.0

        # Non-benign attack indicator
        is_att1 = bool(a1.mitre_tactic and a1.mitre_tactic != "TA0000") or (at1 and "benign" not in at1 and "background" not in at1)
        is_att2 = bool(a2.mitre_tactic and a2.mitre_tactic != "TA0000") or (at2 and "benign" not in at2 and "background" not in at2)
        both_attack = 1.0 if (is_att1 and is_att2) else 0.0

        tac1 = str(a1.mitre_tactic or "").upper().strip()
        tac2 = str(a2.mitre_tactic or "").upper().strip()
        same_tactic = 1.0 if (tac1 and tac2 and tac1 == tac2 and tac1 != "TA0000") else 0.0

        tec1 = str(a1.mitre_technique or "").upper().strip()
        tec2 = str(a2.mitre_technique or "").upper().strip()
        same_technique = 1.0 if (tec1 and tec2 and tec1 == tec2 and tec1 != "T0000") else 0.0

        tactics = {tac1, tac2} - {"", "TA0000"}
        tactic_affinity = 1.0 if len(tactics) == 2 and (
            ("TA0011" in tactics and "TA0007" in tactics) or
            ("TA0001" in tactics and "TA0011" in tactics) or
            ("TA0011" in tactics and "TA0040" in tactics)
        ) else 0.0

        return np.array([
            dt_log,
            time_decay,
            same_src,
            same_dst,
            shared_ip,
            same_proto,
            same_dport,
            same_attack,
            both_attack,
            same_tactic,
            same_technique,
            tactic_affinity,
        ], dtype=np.float32)


class IncidentCorrelationEngine:
    """
    Production alert correlation service engine.
    """
    _artifact = None

    @classmethod
    def load_model(cls) -> Optional[Dict[str, Any]]:
        if cls._artifact is None and MODEL_PATH.exists():
            try:
                cls._artifact = joblib.load(MODEL_PATH)
                logger.info("Loaded correlation model v1.0.0 artifact successfully.")
            except Exception as e:
                logger.error(f"Failed to load correlation model: {e}")
                cls._artifact = None
        return cls._artifact

    @classmethod
    def correlate_alerts(cls, request: CorrelationRequest) -> CorrelationResponse:
        corr_id = f"corr-{uuid.uuid4().hex[:12]}"
        alerts = request.alerts or []

        # Edge case: No alerts provided
        if not alerts:
            inc_id = f"inc-{uuid.uuid4().hex[:8]}"
            return CorrelationResponse(
                correlation_id=corr_id,
                incident_id=inc_id,
                status="NO_ALERTS_PROVIDED",
                model_version="correlation_v1.0.0",
                confidence=1.0,
                alerts=[],
                correlated_alert_ids=[],
                entities={"hosts": [], "users": [], "ips": [], "ports": []},
                timeline={"first_seen": None, "last_seen": None, "duration_seconds": 0, "alert_count": 0},
                mitre_tactics=[],
                mitre_techniques=[],
                incident_summary="Zero alerts provided for correlation.",
                incidents=[]
            )

        model = cls.load_model()
        clf = model["classifier"] if model else None
        threshold = request.correlation_threshold if request.correlation_threshold is not None else 0.50
        time_window = request.time_window_seconds or 3600.0

        n = len(alerts)
        adj = defaultdict(set)
        pair_confidences = defaultdict(float)

        # Build pairwise adjacency graph
        for i in range(n):
            for j in range(i + 1, n):
                a1 = alerts[i]
                a2 = alerts[j]
                
                # Check candidate time window
                t1 = CorrelationFeatureExtractor.parse_datetime(a1.timestamp)
                t2 = CorrelationFeatureExtractor.parse_datetime(a2.timestamp)
                if abs((t1 - t2).total_seconds()) > time_window:
                    continue

                feats = CorrelationFeatureExtractor.extract_pair_features(a1, a2)

                if clf is not None:
                    try:
                        prob = float(clf.predict_proba(feats.reshape(1, -1))[0, 1])
                    except Exception:
                        prob = float(0.70 * feats[4] + 0.30 * feats[1])
                else:
                    # Baseline heuristic: shared_ip + time_decay
                    prob = float(0.70 * feats[4] + 0.30 * feats[1])

                if prob >= threshold:
                    adj[i].add(j)
                    adj[j].add(i)
                    pair_confidences[(i, j)] = prob
                    pair_confidences[(j, i)] = prob

        # Connected-component incident clustering
        visited = set()
        clusters = []

        for i in range(n):
            if i not in visited:
                comp = []
                queue = [i]
                visited.add(i)
                while queue:
                    curr = queue.pop(0)
                    comp.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                clusters.append(comp)

        # Sort clusters by size (largest first)
        clusters.sort(key=len, reverse=True)

        built_incidents = []
        for c_idx, member_indices in enumerate(clusters, start=1):
            inc_id = f"inc-{corr_id[5:]}-{c_idx}"
            cluster_alerts = [alerts[idx] for idx in member_indices]

            # Collect confidence
            c_probs = [
                pair_confidences[(i, j)]
                for i in member_indices
                for j in member_indices
                if i < j and (i, j) in pair_confidences
            ]
            confidence = round(float(np.mean(c_probs)), 4) if c_probs else 0.85

            # Entities
            hosts = sorted(list({a.host for a in cluster_alerts if a.host}))
            users = sorted(list({a.user for a in cluster_alerts if a.user}))
            ips = sorted(list({ip for a in cluster_alerts for ip in (a.src_ip, a.dst_ip) if ip}))
            ports = sorted(list({str(p) for a in cluster_alerts for p in (a.sport, a.dport) if p}))

            # Timeline
            times = [CorrelationFeatureExtractor.parse_datetime(a.timestamp) for a in cluster_alerts]
            t_first = min(times)
            t_last = max(times)
            duration_s = max(0, int((t_last - t_first).total_seconds()))

            # ATT&CK progression
            tactics = sorted(list({a.mitre_tactic for a in cluster_alerts if a.mitre_tactic and a.mitre_tactic != "TA0000"}))
            techniques = sorted(list({a.mitre_technique for a in cluster_alerts if a.mitre_technique and a.mitre_technique != "T0000"}))

            # Threat type synthesis
            attack_types = [a.attack_type for a in cluster_alerts if a.attack_type]
            if any("c2" in at or "irc" in at for at in attack_types):
                synth_threat = "c2_beacon"
            elif any("scan" in at or "attempt" in at for at in attack_types):
                synth_threat = "reconnaissance"
            elif any("spam" in at or "phish" in at for at in attack_types):
                synth_threat = "phishing"
            elif any("dos" in at or "icmp" in at for at in attack_types):
                synth_threat = "ddos"
            else:
                synth_threat = "network_anomaly"

            # Severity and risk score
            severities = [a.severity.lower() for a in cluster_alerts if a.severity]
            sev_order = ["low", "medium", "high", "critical"]
            max_sev = "medium"
            if severities:
                max_sev = max(severities, key=lambda s: sev_order.index(s) if s in sev_order else 1)

            scores = [a.risk_score for a in cluster_alerts if a.risk_score is not None]
            synth_risk = int(max(scores)) if scores else 65

            summary = (
                f"Correlated incident {inc_id} containing {len(cluster_alerts)} alerts across {len(ips)} IP(s). "
                f"Observed threat profile '{synth_threat}' with ATT&CK tactics [{', '.join(tactics)}] "
                f"over {duration_s}s active duration."
            )

            built_incidents.append(CorrelatedIncident(
                incident_id=inc_id,
                correlation_id=corr_id,
                confidence=confidence,
                alert_count=len(cluster_alerts),
                correlated_alert_ids=[a.alert_id for a in cluster_alerts],
                alerts=cluster_alerts,
                entities={"hosts": hosts, "users": users, "ips": ips, "ports": ports},
                timeline={
                    "first_seen": t_first.isoformat() + "Z",
                    "last_seen": t_last.isoformat() + "Z",
                    "duration_seconds": duration_s,
                    "alert_count": len(cluster_alerts),
                },
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                threat_type=synth_threat,
                severity=max_sev,
                risk_score=synth_risk,
                incident_summary=summary,
            ))

        primary = built_incidents[0]

        return CorrelationResponse(
            correlation_id=corr_id,
            incident_id=primary.incident_id,
            status="CORRELATION_SUCCESS",
            model_version="correlation_v1.0.0",
            confidence=primary.confidence,
            alerts=primary.alerts,
            correlated_alert_ids=primary.correlated_alert_ids,
            entities=primary.entities,
            timeline=primary.timeline,
            mitre_tactics=primary.mitre_tactics,
            mitre_techniques=primary.mitre_techniques,
            incident_summary=primary.incident_summary,
            incidents=built_incidents,
        )

    @staticmethod
    def to_recommendation_request(incident: CorrelatedIncident, false_positive_score: Optional[float] = None) -> IncidentRecommendationRequest:
        """
        Translates a correlated incident directly into an IncidentRecommendationRequest for Recommendation V1.
        """
        return IncidentRecommendationRequest(
            incident_id=incident.incident_id,
            title=f"Correlated Incident: {incident.threat_type} on {len(incident.entities.get('ips', []))} endpoints",
            description=incident.incident_summary,
            severity=incident.severity,
            risk_score=incident.risk_score,
            threat_type=incident.threat_type,
            entities=incident.entities,
            timeline=incident.timeline,
            alert_count=incident.alert_count,
            source_engines=["correlation_engine", "network"],
            alert_types=[a.attack_type for a in incident.alerts if a.attack_type],
            mitre_techniques=incident.mitre_techniques,
            mitre_tactics=incident.mitre_tactics,
            correlation_id=incident.correlation_id,
            false_positive_score=false_positive_score,
        )


def correlate_events(request: CorrelationRequest) -> CorrelationResponse:
    """
    Main entrypoint function for incident correlation.
    """
    return IncidentCorrelationEngine.correlate_alerts(request)
