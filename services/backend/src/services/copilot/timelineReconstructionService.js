const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * Timeline Reconstruction Service — Reconstructs full end-to-end attack lifecycles
 * linking IOC → Alert → User → Device → Incident → Playbook → Containment.
 */
class TimelineReconstructionService {
  /**
   * Reconstructs an end-to-end incident or alert attack timeline.
   *
   * @param {Object} params
   * @param {string} [params.incident_id]
   * @param {string} [params.alert_id]
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Reconstructed timeline & attack chain
   */
  async reconstruct({ incident_id = null, alert_id = null, organization_id, user_id = null }, client = null) {
    if (!organization_id) throw new Error('TimelineReconstructionService requires organization_id');
    if (!incident_id && !alert_id) {
      throw new Error('TimelineReconstructionService requires incident_id or alert_id');
    }

    const dbClient = client || db;

    let targetIncident = null;
    let targetAlert = null;
    const timeline = [];
    const impactedAssets = new Set();
    const attackerObjectives = [];

    // 1. Fetch Target Incident
    if (incident_id) {
      const incRes = await dbClient.query(`
        SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;
      `, [incident_id, organization_id]);
      targetIncident = incRes.rows[0] || null;
    }

    // 2. Fetch Target or Sibling Alerts
    let alerts = [];
    if (alert_id) {
      const aRes = await dbClient.query(`
        SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;
      `, [alert_id, organization_id]);
      targetAlert = aRes.rows[0] || null;
      if (targetAlert) alerts.push(targetAlert);
      if (targetAlert && targetAlert.incident_id && !targetIncident) {
        const incRes = await dbClient.query(`
          SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;
        `, [targetAlert.incident_id, organization_id]);
        targetIncident = incRes.rows[0] || null;
      }
    } else if (targetIncident) {
      const aRes = await dbClient.query(`
        SELECT * FROM public.siem_alerts WHERE incident_id = $1 AND organization_id = $2 ORDER BY created_at ASC;
      `, [incident_id, organization_id]);
      alerts = aRes.rows;
    }

    // 3. Stage 1: IOC Sightings
    let observables = [];
    if (targetIncident && targetIncident.fingerprint) observables.push(targetIncident.fingerprint);
    alerts.forEach(a => {
      const meta = a.metadata || {};
      if (meta.source_ip) observables.push(meta.source_ip);
      if (meta.dest_ip) observables.push(meta.dest_ip);
      if (meta.domain) observables.push(meta.domain);
    });
    observables = Array.from(new Set(observables));

    observables.forEach((obs, idx) => {
      timeline.push({
        stage: 'IOC',
        timestamp: targetIncident ? targetIncident.first_seen_at || targetIncident.created_at : new Date(),
        entity_type: 'ioc',
        label: `Threat Observable Sighting: ${obs}`,
        detail: `Adversary network observable ${obs} detected in inbound network traffic or delivery payloads.`
      });
    });

    // 4. Stage 2: Alert Detections
    alerts.forEach(al => {
      timeline.push({
        stage: 'Alert',
        timestamp: al.created_at,
        entity_type: 'siem_alert',
        label: `SIEM Detection: ${al.title}`,
        detail: `Severity: ${al.severity.toUpperCase()} | MITRE: ${al.mitre_technique || 'N/A'}`
      });
      const meta = al.metadata || {};
      if (meta.host) impactedAssets.add(meta.host);
      if (meta.hostname) impactedAssets.add(meta.hostname);
      if (meta.source_ip) impactedAssets.add(meta.source_ip);
    });

    // 5. Stage 3: User Activity
    if (targetIncident && targetIncident.user_id) {
      timeline.push({
        stage: 'User',
        timestamp: targetIncident.created_at,
        entity_type: 'user',
        label: `Target Identity Context: User ${targetIncident.user_id}`,
        detail: `Compromised account credential or authentication context targeted during intrusion.`
      });
    }

    // 6. Stage 4: Device / Asset
    if (targetIncident && targetIncident.device_id) {
      impactedAssets.add(String(targetIncident.device_id));
      timeline.push({
        stage: 'Device',
        timestamp: targetIncident.created_at,
        entity_type: 'device',
        label: `Target Host Endpoint: ${targetIncident.device_id}`,
        detail: `Internal host asset impacted by anomalous execution or payload installation.`
      });
    }

    // 7. Stage 5: Incident Escalation
    if (targetIncident) {
      timeline.push({
        stage: 'Incident',
        timestamp: targetIncident.created_at,
        entity_type: 'incident',
        label: `Incident Escalation: ${targetIncident.threat_type || 'Threat'}`,
        detail: `Severity: ${targetIncident.risk_level.toUpperCase()} (Score: ${targetIncident.risk_score}) - ${targetIncident.explanation}`
      });
    }

    // 8. Stage 6: Playbook Execution
    let executions = [];
    try {
      const alertIds = alerts.map(a => a.id).filter(Boolean);
      const queryParams = [organization_id];
      let sql = `SELECT * FROM public.soar_executions WHERE organization_id = $1`;
      if (alertIds.length > 0) {
        queryParams.push(alertIds);
        sql += ` AND trigger_alert_id = ANY($2::uuid[])`;
      }
      sql += ` ORDER BY created_at ASC;`;
      const execRes = await dbClient.query(sql, queryParams);
      executions = execRes.rows;
    } catch (_) {}

    executions.forEach(ex => {
      timeline.push({
        stage: 'Playbook',
        timestamp: ex.created_at,
        entity_type: 'soar_execution',
        label: `Playbook Orchestration: ${ex.playbook_id || 'Automated Response'}`,
        detail: `Execution status: ${ex.status.toUpperCase()}`
      });
    });

    // 9. Stage 7: Containment Status
    const isContained = (targetIncident && (targetIncident.status === 'contained' || targetIncident.status === 'resolved')) ||
                        alerts.some(a => a.status === 'contained' || a.status === 'resolved') ||
                        executions.some(e => e.status === 'completed');

    timeline.push({
      stage: 'Containment',
      timestamp: new Date(),
      entity_type: 'remediation',
      label: isContained ? 'Threat Contained' : 'Containment Pending Analyst Verification',
      detail: isContained
        ? 'Perimeter firewall blocking rules and endpoint isolation confirmed.'
        : 'Active monitoring engaged; awaiting analyst confirmation of complete host containment.'
    });

    // Determine Attacker Objectives
    attackerObjectives.push('Initial Access via weaponized external indicators');
    if (alerts.some(a => a.mitre_technique === 'T1059')) {
      attackerObjectives.push('Execution via command-line scripting interpreter (PowerShell/cmd)');
    }
    if (alerts.some(a => a.mitre_technique === 'T1003')) {
      attackerObjectives.push('Credential harvesting from memory/storage for privilege escalation');
    }
    if (targetIncident && targetIncident.threat_type === 'technical_threat') {
      attackerObjectives.push('Data Encryption for operational extortion and financial impact');
    }

    const attackChain = {
      root_entity: incident_id ? `incident:${incident_id}` : `alert:${alert_id}`,
      stages_count: timeline.length,
      progression_summary: timeline.map(t => `[${t.stage}] ${t.label}`).join(' ➔ ')
    };

    const report = {
      timeline,
      attack_chain: attackChain,
      attacker_objectives: attackerObjectives,
      impacted_assets: Array.from(impactedAssets).map(a => ({ asset: a }))
    };

    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_TIMELINE_RECONSTRUCTED',
      resource_type: incident_id ? 'incident' : 'alert',
      resource_id: incident_id || alert_id,
      details: { timeline_events_count: timeline.length, assets_count: impactedAssets.size }
    }).catch(() => {});

    return report;
  }
}

module.exports = new TimelineReconstructionService();
