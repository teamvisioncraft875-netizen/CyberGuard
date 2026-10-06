const db = require('../config/db');
const IncidentRecommendation = require('../models/IncidentRecommendation');
const AttackChainSnapshot = require('../models/AttackChainSnapshot');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Automated Response Recommendation Engine
 *
 * Generates tailored remediation actions based on:
 * - Threat Type (phishing, malware, ddos, credential_stuffing, etc.)
 * - MITRE ATT&CK Techniques & Tactics
 * - Risk Score & Risk Level
 * - Attack Chain Progression Stage
 */
class RecommendationEngine {
  /**
   * Generates response recommendations based on incident telemetry and rules
   */
  generateRulesRecommendations(incident, { mitreMappings = [], attackChain = null, iocMatches = [] } = {}) {
    const recommendations = [];
    const threatType = (incident.threat_type || '').toLowerCase();
    const riskScore = incident.risk_score || 0;
    const chainLength = attackChain?.chain_length || 0;

    const mitreIds = mitreMappings.map(m => (m.technique_id || '').toUpperCase());

    // 1. Phishing / Initial Access
    if (threatType.includes('phishing') || mitreIds.some(id => id.includes('1566') || id === 'TA0001')) {
      recommendations.push({
        title: 'Revoke User Active Sessions',
        description: 'Immediately terminate all active access and refresh tokens for the compromised identity to halt session hijacking.',
        priority: 'P1',
        automatable: true,
        action_type: 'revoke_session',
        metadata: { target_user_id: incident.user_id }
      });

      recommendations.push({
        title: 'Force Password Reset',
        description: 'Invalidate existing password and prompt user for mandatory credential rotation on next authentication attempt.',
        priority: 'P2',
        automatable: true,
        action_type: 'force_password_reset',
        metadata: { target_user_id: incident.user_id }
      });

      recommendations.push({
        title: 'Block Malicious Sender & Inbound Domain',
        description: 'Blacklist the originating sender domain and mail relay IP across enterprise mail gateways.',
        priority: 'P2',
        automatable: true,
        action_type: 'block_domain',
        metadata: { threat_type: 'phishing' }
      });
    }

    // 2. Malware / Execution / Endpoint Attacks
    if (threatType.includes('malware') || threatType.includes('technical_threat') || mitreIds.some(id => id.includes('1204') || id === 'TA0002')) {
      recommendations.push({
        title: 'Isolate Host Endpoint',
        description: 'Sever network connectivity from infected workstation while keeping security agent telemetry link alive.',
        priority: 'P1',
        automatable: true,
        action_type: 'suspend_device',
        metadata: { device_id: incident.device_id }
      });

      recommendations.push({
        title: 'Terminate Malicious Process Tree',
        description: 'Kill active executable payloads and child processes identified in detection telemetry.',
        priority: 'P1',
        automatable: true,
        action_type: 'kill_process',
        metadata: { threat_type: 'malware' }
      });

      recommendations.push({
        title: 'Run Full Endpoint Antivirus Scan',
        description: 'Trigger an automated deep rootkit and filesystem scan on target host to detect secondary droppers.',
        priority: 'P3',
        automatable: true,
        action_type: 'run_scan',
        metadata: { device_id: incident.device_id }
      });
    }

    // 3. Threat Intel & IOC Matches
    if (threatType.includes('threat_intel') || iocMatches.length > 0) {
      recommendations.push({
        title: 'Block Malicious IOC at Edge Firewall',
        description: 'Deploy real-time IP and domain blocklists to boundary firewalls and proxy egress filters.',
        priority: 'P1',
        automatable: true,
        action_type: 'block_ip',
        metadata: { matched_iocs: iocMatches.map(m => m.matched_value) }
      });

      recommendations.push({
        title: 'Deploy Perimeter Firewall Drop Rule',
        description: 'Blackhole traffic matching threat intelligence adversary infrastructure signatures.',
        priority: 'P2',
        automatable: true,
        action_type: 'firewall_rule',
        metadata: { ioc_count: iocMatches.length }
      });
    }

    // 4. DDoS / High-Volume Traffic
    if (threatType.includes('ddos') || incident.source_type === 'ddos_detection') {
      recommendations.push({
        title: 'Apply Dynamic Ingress Rate Limiting',
        description: 'Throttle high-packet-rate source ASNs and drop UDP/SYN flood traffic matching attack vectors.',
        priority: 'P1',
        automatable: true,
        action_type: 'rate_limit',
        metadata: { source_type: 'ddos_detection' }
      });
    }

    // 5. Critical Risk / Multi-Stage Attack Chain Escalation
    if (riskScore >= 76 || chainLength >= 3) {
      recommendations.push({
        title: 'Escalate to Tier-3 SOC Threat Hunter',
        description: 'Multi-stage lateral progression detected. Engage dedicated incident command team for forensic investigation.',
        priority: 'P1',
        automatable: false,
        action_type: 'escalate_incident',
        metadata: { chain_length: chainLength, risk_score: riskScore }
      });
    }

    // Fallback baseline recommendation if none matched
    if (recommendations.length === 0) {
      recommendations.push({
        title: 'Investigate Security Alert Signals',
        description: 'Perform triage of detection signals and verify authentication logs for anomalous activity.',
        priority: 'P3',
        automatable: false,
        action_type: 'manual_triage',
        metadata: {}
      });
    }

    return recommendations;
  }

  /**
   * Get or generate recommendations for an incident
   *
   * @param {string} incidentId
   * @param {string} organizationId
   * @param {Object} [options]
   * @param {boolean} [options.refresh=false]
   * @param {string} [options.actorUserId]
   * @returns {Promise<Array<Object>>}
   */
  async getRecommendations(incidentId, organizationId, { refresh = false, actorUserId = null } = {}) {
    // 1. If not refreshing, check if recommendations already exist
    if (!refresh) {
      const existing = await IncidentRecommendation.findByIncident(incidentId, organizationId);
      if (existing && existing.length > 0) {
        return existing;
      }
    }

    // 2. Fetch incident with tenant isolation
    const incRes = await db.query(
      `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      throw new Error(`Incident ${incidentId} not found in organization ${organizationId}`);
    }

    const incident = incRes.rows[0];

    // 3. Fetch MITRE mappings, attack chain, and IOC matches
    const [mitreRes, chainSnapshot, iocRes] = await Promise.all([
      db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1;`, [incidentId]),
      AttackChainSnapshot.findByIncident(incidentId).catch(() => null),
      db.query(`SELECT * FROM public.incident_ioc_matches WHERE incident_id = $1 AND organization_id = $2;`, [incidentId, organizationId])
    ]);

    // 4. Generate recommendations
    const rawRecommendations = this.generateRulesRecommendations(incident, {
      mitreMappings: mitreRes.rows,
      attackChain: chainSnapshot,
      iocMatches: iocRes.rows
    });

    // 5. If refresh was requested, remove old recommendations first
    if (refresh) {
      await IncidentRecommendation.deleteByIncident(incidentId, organizationId);
    }

    // 6. Persist generated recommendations
    const recordsToInsert = rawRecommendations.map(r => ({
      organization_id: organizationId,
      incident_id: incidentId,
      title: r.title,
      description: r.description,
      priority: r.priority,
      automatable: r.automatable,
      action_type: r.action_type,
      metadata: r.metadata
    }));

    const persisted = await IncidentRecommendation.createMany(recordsToInsert);

    // 7. Audit log recommendation generation
    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.RECOMMENDATION_GENERATED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        count: persisted.length,
        actions: persisted.map(p => p.title)
      }
    });

    return persisted;
  }
}

module.exports = new RecommendationEngine();
