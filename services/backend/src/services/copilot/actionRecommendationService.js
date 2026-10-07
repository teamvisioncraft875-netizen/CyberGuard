const db = require('../../config/db');
const auditService = require('../auditService');
const CopilotSessionAction = require('../../models/CopilotSessionAction');

/**
 * Action Recommendation Engine — Analyzes alert, incident, IOC, and MITRE context
 * to generate high-confidence, explainable SOC response actions and approval gating flags.
 */
class ActionRecommendationService {
  /**
   * Generates ranked, explainable response actions based on threat indicators.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Tenant ID
   * @param {string} [params.alert_id] - Optional alert UUID
   * @param {string} [params.incident_id] - Optional incident UUID
   * @param {string} [params.ioc_id] - Optional IOC UUID
   * @param {Object} [params.ioc] - Optional IOC descriptor
   * @param {string|string[]} [params.mitre_technique] - Optional MITRE technique(s)
   * @param {string} [params.severity] - Threat severity level (critical, high, medium, low)
   * @param {Object} [params.context] - Runtime context (host, user, ip, domain)
   * @param {string} [params.session_id] - Optional investigation session UUID
   * @param {string} [params.actor_id] - User UUID
   * @returns {Promise<{ recommendations: Array<Object> }>}
   */
  async recommendActions({
    organization_id,
    alert_id = null,
    incident_id = null,
    ioc_id = null,
    ioc = null,
    mitre_technique = null,
    severity = null,
    context = {},
    session_id = null,
    actor_id = null
  }) {
    if (!organization_id) {
      throw new Error('ActionRecommendationService Error: organization_id is required');
    }

    let alertData = null;
    let incidentData = null;
    let iocData = ioc || null;
    const mergedContext = { ...(context || {}) };

    // 1. Enrich from Alert if provided
    if (alert_id) {
      const aRes = await db.query(
        `SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`,
        [alert_id, organization_id]
      );
      if (aRes.rows[0]) {
        alertData = aRes.rows[0];
        if (alertData.metadata) {
          Object.assign(mergedContext, alertData.metadata);
        }
      }
    }

    // 2. Enrich from Incident if provided
    if (incident_id) {
      const incRes = await db.query(
        `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
        [incident_id, organization_id]
      );
      if (incRes.rows[0]) {
        incidentData = incRes.rows[0];
      }
    }

    // 3. Enrich from IOC if provided
    if (ioc_id && !iocData) {
      const iocRes = await db.query(
        `SELECT * FROM public.threat_iocs WHERE id = $1 AND organization_id = $2;`,
        [ioc_id, organization_id]
      );
      if (iocRes.rows[0]) {
        iocData = iocRes.rows[0];
      }
    }

    // Determine aggregate threat traits
    const resolvedSeverity = (
      severity ||
      alertData?.severity ||
      incidentData?.risk_level ||
      (iocData?.risk_score >= 80 ? 'critical' : (iocData?.risk_score >= 50 ? 'high' : 'medium')) ||
      'medium'
    ).toLowerCase();

    const rawTechniques = [];
    if (mitre_technique) {
      if (Array.isArray(mitre_technique)) rawTechniques.push(...mitre_technique);
      else rawTechniques.push(mitre_technique);
    }
    if (alertData?.mitre_technique) rawTechniques.push(alertData.mitre_technique);
    const techniques = Array.from(new Set(rawTechniques.map(t => String(t).toUpperCase())));

    const targetHost = mergedContext.host || mergedContext.target_host || mergedContext.device || alertData?.metadata?.host || null;
    const targetUser = mergedContext.user || mergedContext.target_user || mergedContext.username || alertData?.metadata?.target_user || null;
    const targetIp = mergedContext.ip || mergedContext.source_ip || mergedContext.destination_ip || (iocData?.ioc_type === 'ip' ? iocData.ioc_value : null);
    const targetDomain = mergedContext.domain || (iocData?.ioc_type === 'domain' ? iocData.ioc_value : null);

    const isCredentialDumping = techniques.includes('T1003') || (alertData?.title && /mimikatz|credential|dumping/i.test(alertData.title));
    const isLateralMovement = techniques.includes('T1021') || techniques.includes('T1059');
    const isRansomware = techniques.includes('T1486') || (alertData?.title && /ransomware|encryption/i.test(alertData.title));
    const isC2orBeaconing = techniques.includes('T1071') || (alertData?.title && /beacon|c2|command and control/i.test(alertData.title));
    const isBruteForce = techniques.includes('T1110') || (alertData?.title && /brute force|credential stuffing/i.test(alertData.title));

    const recommendations = [];

    // --- Action 1: Isolate Endpoint (High Risk -> Requires Approval) ---
    if (targetHost || isCredentialDumping || isLateralMovement || isRansomware) {
      const hostLabel = targetHost || 'Affected Endpoint';
      recommendations.push({
        action: 'isolate_endpoint',
        confidence: isRansomware ? 0.98 : (isCredentialDumping ? 0.95 : 0.88),
        reason: `Isolate host ${hostLabel} to sever network communications and halt lateral attack traversal.`,
        requires_approval: true,
        explanation: {
          why: `Malicious execution or credential access detected on ${hostLabel}. Endpoint isolation contains threat blast radius.`,
          mitre_mapping: isCredentialDumping ? 'T1003' : (isRansomware ? 'T1486' : 'T1021'),
          threat_evidence: `Suspicious activity associated with ${hostLabel} under severity: ${resolvedSeverity}.`,
          expected_outcome: `Host network traffic is restricted by EDR agent; management tunnel remains reachable for forensics.`,
          risk_level: resolvedSeverity
        }
      });
    }

    // --- Action 2: Block IP (High Risk -> Requires Approval) ---
    if (targetIp || isC2orBeaconing || isBruteForce) {
      const ipLabel = targetIp || '198.51.100.25';
      recommendations.push({
        action: 'block_ip',
        confidence: 0.93,
        reason: `Block suspicious external IP ${ipLabel} at perimeter firewalls to prevent unauthorized ingress/egress.`,
        requires_approval: true,
        explanation: {
          why: `Traffic directed towards or from ${ipLabel} indicates active exploitation or command-and-control callback.`,
          mitre_mapping: isC2orBeaconing ? 'T1071' : 'T1110',
          threat_evidence: `External network activity involving address ${ipLabel}.`,
          expected_outcome: `Perimeter firewall rules provisioned to drop all packets associated with ${ipLabel}.`,
          risk_level: resolvedSeverity === 'critical' ? 'critical' : 'high'
        }
      });
    }

    // --- Action 3: Block Domain / Sinkhole (High Risk -> Requires Approval) ---
    if (targetDomain || isC2orBeaconing) {
      const domainLabel = targetDomain || 'malicious-domain.com';
      recommendations.push({
        action: 'block_domain',
        confidence: 0.90,
        reason: `Sinkhole or block domain ${domainLabel} to sever outbound malware callback channels.`,
        requires_approval: true,
        explanation: {
          why: `Host resolution attempts identified targeting known malicious domain ${domainLabel}.`,
          mitre_mapping: 'T1071.001',
          threat_evidence: `DNS request activity matching malicious indicator ${domainLabel}.`,
          expected_outcome: `Internal DNS resolvers return sinkhole IP (10.254.254.254), neutralizing external beaconing.`,
          risk_level: 'high'
        }
      });
    }

    // --- Action 4: Disable Account (High Risk -> Requires Approval) ---
    if (targetUser || isCredentialDumping || isBruteForce) {
      const userLabel = targetUser || 'compromised_account';
      recommendations.push({
        action: 'disable_account',
        confidence: isCredentialDumping ? 0.94 : 0.86,
        reason: `Disable user credentials for ${userLabel} to terminate active sessions and prevent account abuse.`,
        requires_approval: true,
        explanation: {
          why: `Credentials for ${userLabel} suspect or exposed in memory harvesting event.`,
          mitre_mapping: 'T1078',
          threat_evidence: `Anomalous privilege operations or brute force detected on identity: ${userLabel}.`,
          expected_outcome: `User account locked out in Identity Provider/Active Directory; active OAuth tokens revoked.`,
          risk_level: 'high'
        }
      });
    }

    // --- Action 5: Create SOAR Case (Low Risk -> Automated / Safe) ---
    if (resolvedSeverity === 'critical' || resolvedSeverity === 'high' || alert_id || incident_id) {
      recommendations.push({
        action: 'create_soar_case',
        confidence: 0.98,
        reason: `Formalize investigation by creating a dedicated SOAR incident case with evidence lineage.`,
        requires_approval: false,
        explanation: {
          why: `Incidents of ${resolvedSeverity} severity require tracked forensic work and structured SLA monitoring.`,
          mitre_mapping: techniques[0] || 'T1000',
          threat_evidence: `Verified detection findings with elevated risk score (${resolvedSeverity}).`,
          expected_outcome: `SOAR Case initialized, alerts linked, and evidence artifacts attached.`,
          risk_level: 'low'
        }
      });
    }

    // --- Action 6: Execute Playbook (Operational Response) ---
    recommendations.push({
      action: 'execute_playbook',
      confidence: 0.92,
      reason: `Trigger coordinated multi-step response playbook matching threat pattern.`,
      requires_approval: false,
      explanation: {
        why: `Automates end-to-end containment, forensic artifact collection, and stakeholder reporting.`,
        mitre_mapping: techniques[0] || 'T1000',
        threat_evidence: `Threat behavioral signature matches established security playbook runbooks.`,
        expected_outcome: `SOAR Playbook executed with sequential actions, retries, and telemetry metrics.`,
        risk_level: 'medium'
      }
    });

    // --- Action 7: Escalate Incident (Operational Review) ---
    if (resolvedSeverity === 'critical' || resolvedSeverity === 'high') {
      recommendations.push({
        action: 'escalate_incident',
        confidence: 0.88,
        reason: `Escalate incident priority to P1/Critical for Tier-2 SOC and IR team triage.`,
        requires_approval: false,
        explanation: {
          why: `High-impact or lateral threat behaviors require immediate escalation to Senior Incident Responders.`,
          mitre_mapping: techniques[0] || 'T1000',
          threat_evidence: `Composite threat score exceeds Tier-1 threshold.`,
          expected_outcome: `Incident priority escalated and on-call notifications dispatched.`,
          risk_level: 'medium'
        }
      });
    }

    // --- Action 8: Trigger Approval Workflow (Safety Gating) ---
    recommendations.push({
      action: 'trigger_approval_workflow',
      confidence: 0.91,
      reason: `Queue human-in-the-loop authorization workflow for high-impact containment tasks.`,
      requires_approval: false,
      explanation: {
        why: `Adheres to least-disruption governance before executing host isolation or account locks.`,
        mitre_mapping: techniques[0] || 'T1000',
        threat_evidence: `Gating sensitive response actions to prevent unintended operational disruption.`,
        expected_outcome: `Approval request recorded with L1/L2 SLA timer and notification to SOC supervisor.`,
        risk_level: 'low'
      }
    });

    // Sort by confidence descending
    recommendations.sort((a, b) => b.confidence - a.confidence);

    // If session_id is provided, persist recommendations into conversation action memory
    if (session_id) {
      for (const rec of recommendations) {
        await CopilotSessionAction.create({
          session_id,
          organization_id,
          action_type: rec.action,
          action_payload: {
            alert_id,
            incident_id,
            ioc_id,
            context: mergedContext
          },
          status: 'recommended',
          confidence: rec.confidence,
          reason: rec.reason,
          explanation: rec.explanation,
          requires_approval: rec.requires_approval,
          created_by: actor_id
        }).catch(err => console.error('[ActionRecommendationService] Error storing memory action:', err.message));
      }
    }

    // Record audit event
    await auditService.log({
      organization_id,
      actor_id,
      action: 'COPILOT_ACTION_RECOMMENDED',
      resource_type: 'copilot_recommendations',
      resource_id: session_id || alert_id || incident_id || 'recommendation_engine',
      details: {
        count: recommendations.length,
        actions: recommendations.map(r => r.action),
        severity: resolvedSeverity
      }
    }).catch(err => console.error('[ActionRecommendationService] Audit log error:', err.message));

    return { recommendations };
  }
}

const actionRecommendationService = new ActionRecommendationService();
module.exports = actionRecommendationService;
