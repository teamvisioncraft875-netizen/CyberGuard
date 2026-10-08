const db = require('../../config/db');
const { log: auditLog } = require('../auditService');
const CopilotInvestigation = require('../../models/CopilotInvestigation');
const CopilotMessage = require('../../models/CopilotMessage');

class IncidentCorrelationService {
  /**
   * Correlates an incident or alert with broader telemetry, identifying common actors,
   * infrastructure, techniques, and campaigns.
   *
   * @param {Object} params
   * @param {string} [params.incident_id] - Target incident ID
   * @param {string} [params.alert_id] - Target alert ID
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.session_id]
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Correlation report
   */
  async correlate({ incident_id = null, alert_id = null, organization_id, session_id = null, user_id = null }, client = null) {
    if (!organization_id) throw new Error('IncidentCorrelationService requires organization_id');
    if (!incident_id && !alert_id) {
      throw new Error('IncidentCorrelationService requires incident_id or alert_id');
    }

    const dbClient = client || db;

    let targetIncident = null;
    let targetAlert = null;
    let extractedIndicators = [];
    let extractedTechniques = [];

    // 1. Fetch Target Entity
    if (incident_id) {
      const incRes = await dbClient.query(
        `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
        [incident_id, organization_id]
      );
      targetIncident = incRes.rows[0] || null;
      if (targetIncident) {
        if (targetIncident.fingerprint) extractedIndicators.push(targetIncident.fingerprint);
      }
    }

    if (alert_id) {
      const alertRes = await dbClient.query(
        `SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`,
        [alert_id, organization_id]
      );
      targetAlert = alertRes.rows[0] || null;
      if (targetAlert) {
        if (targetAlert.mitre_technique) extractedTechniques.push(targetAlert.mitre_technique);
        const meta = targetAlert.metadata || {};
        if (meta.source_ip) extractedIndicators.push(meta.source_ip);
        if (meta.dest_ip) extractedIndicators.push(meta.dest_ip);
        if (meta.domain) extractedIndicators.push(meta.domain);
        if (meta.ioc) extractedIndicators.push(meta.ioc);
      }
    }

    // Extract IOCs from explanation text if any IP regex matches
    const textToSearch = [
      targetIncident ? targetIncident.explanation : '',
      targetAlert ? (targetAlert.title + ' ' + JSON.stringify(targetAlert.metadata || {})) : ''
    ].join(' ');

    const ipMatches = textToSearch.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    ipMatches.forEach(ip => extractedIndicators.push(ip));

    const domainMatches = textToSearch.match(/\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g) || [];
    domainMatches.forEach(d => extractedIndicators.push(d));

    // Deduplicate
    extractedIndicators = Array.from(new Set(extractedIndicators));
    extractedTechniques = Array.from(new Set(extractedTechniques));

    // 2. Query correlated Threat IOCs
    const correlatedIocs = [];
    const commonActors = new Set();
    const commonCampaigns = new Set();
    const commonInfrastructure = new Set(extractedIndicators);

    if (extractedIndicators.length > 0) {
      const iocQuery = `
        SELECT * FROM public.threat_iocs
        WHERE organization_id = $1 AND ioc_value = ANY($2::text[]);
      `;
      const iocRes = await dbClient.query(iocQuery, [organization_id, extractedIndicators]);
      iocRes.rows.forEach(r => {
        correlatedIocs.push(r);
        if (r.threat_actor) commonActors.add(r.threat_actor);
        if (r.campaign_name) commonCampaigns.add(r.campaign_name);
        if (r.tags && Array.isArray(r.tags)) {
          r.tags.forEach(t => {
            if (/^T\d{4}/i.test(t)) extractedTechniques.push(t.toUpperCase());
          });
        }
      });
    }

    // 3. Query correlated Incidents in tenant
    const incConditions = ['organization_id = $1'];
    const incParams = [organization_id];
    if (incident_id) {
      incParams.push(incident_id);
      incConditions.push(`id != $${incParams.length}`);
    }

    const orClauses = [];
    if (extractedIndicators.length > 0) {
      incParams.push(extractedIndicators);
      orClauses.push(`fingerprint = ANY($${incParams.length}::text[])`);
      for (const ind of extractedIndicators) {
        incParams.push(`%${ind}%`);
        orClauses.push(`explanation ILIKE $${incParams.length}`);
      }
    }
    if (targetIncident && targetIncident.threat_type) {
      incParams.push(targetIncident.threat_type);
      orClauses.push(`threat_type = $${incParams.length}`);
    }

    let correlatedIncidents = [];
    if (orClauses.length > 0) {
      const incSql = `
        SELECT id, threat_type, risk_level, risk_score, explanation, fingerprint, created_at
        FROM public.incidents
        WHERE ${incConditions.join(' AND ')} AND (${orClauses.join(' OR ')})
        ORDER BY created_at DESC
        LIMIT 10;
      `;
      const cIncRes = await dbClient.query(incSql, incParams);
      correlatedIncidents = cIncRes.rows;
    }

    // 4. Query correlated SIEM Alerts in tenant
    let correlatedAlerts = [];
    const alertConditions = ['organization_id = $1'];
    const alertParams = [organization_id];
    if (alert_id) {
      alertParams.push(alert_id);
      alertConditions.push(`id != $${alertParams.length}`);
    }

    const alertOr = [];
    for (const tech of extractedTechniques) {
      alertParams.push(`%${tech}%`);
      alertOr.push(`mitre_technique ILIKE $${alertParams.length}`);
    }
    for (const ind of extractedIndicators) {
      alertParams.push(`%${ind}%`);
      alertOr.push(`(metadata::text ILIKE $${alertParams.length} OR title ILIKE $${alertParams.length})`);
    }

    if (alertOr.length > 0) {
      const alertSql = `
        SELECT id, title, severity, status, mitre_technique, created_at
        FROM public.siem_alerts
        WHERE ${alertConditions.join(' AND ')} AND (${alertOr.join(' OR ')})
        ORDER BY created_at DESC
        LIMIT 10;
      `;
      const cAlertRes = await dbClient.query(alertSql, alertParams);
      correlatedAlerts = cAlertRes.rows;
    }

    // 5. Query Attack Chains (Filtered via SQL root_incident_id without blocking JSON.stringify serialization)
    let correlatedChains = [];
    if (targetIncident && targetIncident.id) {
      const chainSql = `
        SELECT id, root_incident_id, chain_length, confidence_score, timeline, created_at
        FROM public.attack_chain_snapshots
        WHERE organization_id = $1 AND root_incident_id = $2
        ORDER BY created_at DESC
        LIMIT 5;
      `;
      const chainRes = await dbClient.query(chainSql, [organization_id, targetIncident.id]);
      correlatedChains = chainRes.rows;
    } else {
      const chainSql = `
        SELECT id, root_incident_id, chain_length, confidence_score, timeline, created_at
        FROM public.attack_chain_snapshots
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT 5;
      `;
      const chainRes = await dbClient.query(chainSql, [organization_id]);
      if (extractedIndicators.length > 0) {
        correlatedChains = chainRes.rows.filter(c => {
          if (!Array.isArray(c.timeline)) return false;
          return c.timeline.some(step => {
            if (!step) return false;
            const indicators = step.indicators || step.iocs || [step.source, step.destination, step.entity];
            return extractedIndicators.some(i => indicators.includes(i));
          });
        });
      }
    }

    // 6. Calculate Correlation Score & Evidence
    let baseScore = 0.20;
    const evidence = [];

    if (commonActors.size > 0) {
      baseScore += 0.35;
      evidence.push(`Attributed to known threat actor(s): ${Array.from(commonActors).join(', ')}`);
    }
    if (commonInfrastructure.size > 0) {
      baseScore += 0.25;
      evidence.push(`Shared C2 infrastructure or observables: ${Array.from(commonInfrastructure).join(', ')}`);
    }
    if (extractedTechniques.length > 0) {
      baseScore += 0.15;
      evidence.push(`Convergent MITRE ATT&CK technique(s): ${Array.from(new Set(extractedTechniques)).join(', ')}`);
    }
    if (commonCampaigns.size > 0) {
      baseScore += 0.15;
      evidence.push(`Part of tracked threat campaign: ${Array.from(commonCampaigns).join(', ')}`);
    }
    if (correlatedChains.length > 0) {
      baseScore += 0.10;
      evidence.push(`Observed within active multi-stage attack chain snapshot`);
    }
    if (correlatedAlerts.length > 0 || correlatedIncidents.length > 0) {
      evidence.push(`Linked to ${correlatedAlerts.length} sibling alert(s) and ${correlatedIncidents.length} related incident(s)`);
    }

    const correlationScore = Math.min(0.99, Math.max(0.20, parseFloat(baseScore.toFixed(2))));

    const report = {
      correlation_score: correlationScore,
      target: {
        incident_id: incident_id || (targetAlert ? targetAlert.incident_id : null),
        alert_id: alert_id || null
      },
      related_entities: {
        alerts: correlatedAlerts,
        incidents: correlatedIncidents,
        iocs: correlatedIocs,
        actors: Array.from(commonActors),
        infrastructure: Array.from(commonInfrastructure),
        techniques: Array.from(new Set(extractedTechniques)),
        campaigns: Array.from(commonCampaigns),
        attack_chains: correlatedChains
      },
      evidence
    };

    // Audit Log
    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_CORRELATION_EXECUTED',
      resource_type: incident_id ? 'incident' : 'alert',
      resource_id: incident_id || alert_id,
      details: {
        correlation_score: correlationScore,
        correlated_alerts_count: correlatedAlerts.length,
        correlated_incidents_count: correlatedIncidents.length,
        actors: Array.from(commonActors)
      }
    }).catch(() => {});

    // Session Memory Persistence
    if (session_id) {
      await CopilotInvestigation.create({
        session_id,
        organization_id,
        investigation_type: 'correlate',
        title: `Correlation Analysis for ${incident_id ? `Incident ${incident_id}` : `Alert ${alert_id}`}`,
        target_type: incident_id ? 'incident' : 'alert',
        target_id: incident_id || alert_id,
        findings: [
          { type: 'correlation_score', score: correlationScore },
          { type: 'actors', actors: Array.from(commonActors) },
          { type: 'campaigns', campaigns: Array.from(commonCampaigns) }
        ],
        evidence,
        recommendations: [
          'Enforce cross-incident correlation containment and review campaign IOC sightings.'
        ],
        severity: correlationScore >= 0.80 ? 'high' : 'medium',
        confidence: correlationScore,
        created_by: user_id
      }, dbClient).catch(() => {});

      await CopilotMessage.create({
        session_id,
        role: 'assistant',
        content: `Correlated ${incident_id ? `Incident ${incident_id}` : `Alert ${alert_id}`}: Score ${correlationScore * 100}% with ${correlatedAlerts.length} alerts and ${correlatedIncidents.length} related incidents.`,
        metadata: { correlation_report: report }
      }, dbClient).catch(() => {});
    }

    return report;
  }
}

module.exports = new IncidentCorrelationService();
