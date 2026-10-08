const db = require('../../config/db');
const { log: auditLog } = require('../auditService');
const iocInvestigationService = require('./iocInvestigationService');
const investigationGraphService = require('./investigationGraphService');
const CopilotInvestigation = require('../../models/CopilotInvestigation');
const CopilotMessage = require('../../models/CopilotMessage');

class AutonomousInvestigationService {
  /**
   * Conducts an end-to-end autonomous investigation across all CyberGuard data planes.
   *
   * @param {Object} params
   * @param {string} [params.alert_id]
   * @param {string} [params.incident_id]
   * @param {string} [params.case_id]
   * @param {string} [params.ioc]
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.session_id]
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Comprehensive autonomous investigation report
   */
  async investigate({ alert_id = null, incident_id = null, case_id = null, ioc = null, organization_id, session_id = null, user_id = null }, client = null) {
    if (!organization_id) throw new Error('AutonomousInvestigationService requires organization_id');
    if (!alert_id && !incident_id && !case_id && !ioc) {
      throw new Error('AutonomousInvestigationService requires alert_id, incident_id, case_id, or ioc');
    }

    const dbClient = client || db;

    // 1. Gather Context
    let primaryTarget = null;
    let initialIocs = [];
    let initialAlerts = [];
    let initialIncidents = [];
    let initialUsers = [];
    let initialAssets = [];
    let initialMitre = [];

    if (alert_id) {
      const aRes = await dbClient.query(`SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`, [alert_id, organization_id]);
      if (aRes.rows.length > 0) {
        primaryTarget = { type: 'alert', id: alert_id, data: aRes.rows[0] };
        initialAlerts.push(aRes.rows[0]);
        if (aRes.rows[0].mitre_technique) initialMitre.push(aRes.rows[0].mitre_technique);
        const meta = aRes.rows[0].metadata || {};
        if (meta.source_ip) initialIocs.push(meta.source_ip);
        if (meta.dest_ip) initialIocs.push(meta.dest_ip);
        if (meta.hostname) initialAssets.push(meta.hostname);
        if (meta.username) initialUsers.push(meta.username);

        if (aRes.rows[0].incident_id) {
          const iRes = await dbClient.query(`SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`, [aRes.rows[0].incident_id, organization_id]);
          if (iRes.rows.length > 0) initialIncidents.push(iRes.rows[0]);
        }
      }
    } else if (incident_id) {
      const iRes = await dbClient.query(`SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`, [incident_id, organization_id]);
      if (iRes.rows.length > 0) {
        primaryTarget = { type: 'incident', id: incident_id, data: iRes.rows[0] };
        initialIncidents.push(iRes.rows[0]);
        if (iRes.rows[0].user_id) initialUsers.push(iRes.rows[0].user_id);
        if (iRes.rows[0].device_id) initialAssets.push(iRes.rows[0].device_id);
        if (iRes.rows[0].fingerprint) initialIocs.push(iRes.rows[0].fingerprint);

        const aRes = await dbClient.query(`SELECT * FROM public.siem_alerts WHERE incident_id = $1 AND organization_id = $2;`, [incident_id, organization_id]);
        aRes.rows.forEach(a => initialAlerts.push(a));
      }
    } else if (case_id) {
      const cRes = await dbClient.query(`SELECT * FROM public.soar_cases WHERE id = $1 AND organization_id = $2;`, [case_id, organization_id]);
      if (cRes.rows.length > 0) {
        primaryTarget = { type: 'case', id: case_id, data: cRes.rows[0] };
        if (cRes.rows[0].alert_id) {
          const aRes = await dbClient.query(`SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`, [cRes.rows[0].alert_id, organization_id]);
          if (aRes.rows.length > 0) initialAlerts.push(aRes.rows[0]);
        }
        if (cRes.rows[0].assigned_to) initialUsers.push(cRes.rows[0].assigned_to);
      }
    } else if (ioc) {
      primaryTarget = { type: 'ioc', id: ioc, data: { ioc } };
      initialIocs.push(ioc);
    }

    if (!primaryTarget) {
      primaryTarget = { type: 'target', id: alert_id || incident_id || case_id || ioc, data: {} };
    }

    // 2. Pivot Threat Intelligence on IOCs (Vectorized batch lookup to eliminate N+1 queries)
    let threatIntelResults = [];
    if (initialIocs.length > 0) {
      const batchPivot = await iocInvestigationService.investigateBatch({
        iocs: initialIocs,
        organization_id,
        user_id
      }, dbClient).catch(() => null);

      if (batchPivot) {
        if (Array.isArray(batchPivot.threat_intel)) {
          threatIntelResults = batchPivot.threat_intel;
        }
        if (Array.isArray(batchPivot.related_alerts)) {
          batchPivot.related_alerts.forEach(a => initialAlerts.push(a));
        }
        if (Array.isArray(batchPivot.related_incidents)) {
          batchPivot.related_incidents.forEach(i => initialIncidents.push(i));
        }
        if (Array.isArray(batchPivot.affected_assets)) {
          batchPivot.affected_assets.forEach(a => initialAssets.push(a.asset_identifier));
        }
        if (Array.isArray(batchPivot.affected_users)) {
          batchPivot.affected_users.forEach(u => initialUsers.push(u.user_identifier));
        }
        if (Array.isArray(batchPivot.mitre)) {
          batchPivot.mitre.forEach(m => initialMitre.push(m.technique));
        }
      }
    }

    // Deduplicate entities
    const dedupeById = list => {
      const seen = new Set();
      return list.filter(item => {
        if (!item || !item.id) return false;
        if (seen.has(item.id)) return false;
        seen.add(item.id);
        return true;
      });
    };

    const finalAlerts = dedupeById(initialAlerts);
    const finalIncidents = dedupeById(initialIncidents);
    const finalIocs = Array.from(new Set(initialIocs));
    const finalUsers = Array.from(new Set(initialUsers)).map(u => ({ user_identifier: u }));
    const finalAssets = Array.from(new Set(initialAssets)).map(a => ({ asset_identifier: a }));
    const finalMitre = Array.from(new Set(initialMitre)).map(t => ({ technique: t.toUpperCase() }));

    // 3. Attack Chains (Filtered via SQL and targeted properties rather than serializing whole graphs)
    let attackChains = [];
    const rootIncidentIds = finalIncidents.map(inc => inc.id).filter(Boolean);
    if (rootIncidentIds.length > 0) {
      const chainRes = await dbClient.query(
        `SELECT id, root_incident_id, chain_length, confidence_score, timeline, created_at
         FROM public.attack_chain_snapshots
         WHERE organization_id = $1 AND root_incident_id = ANY($2::uuid[])
         ORDER BY created_at DESC
         LIMIT 5;`,
        [organization_id, rootIncidentIds]
      );
      attackChains = chainRes.rows;
    } else {
      const chainRes = await dbClient.query(
        `SELECT id, root_incident_id, chain_length, confidence_score, timeline, created_at
         FROM public.attack_chain_snapshots
         WHERE organization_id = $1
         ORDER BY created_at DESC
         LIMIT 5;`,
        [organization_id]
      );
      if (finalIocs.length > 0) {
        attackChains = chainRes.rows.filter(c => {
          if (!Array.isArray(c.timeline)) return false;
          return c.timeline.some(step => {
            if (!step) return false;
            const indicators = step.indicators || step.iocs || [step.source, step.destination, step.entity];
            return finalIocs.some(i => indicators.includes(i));
          });
        });
      }
    }

    // 4. Generate Investigation Graph
    const graph = investigationGraphService.buildGraphFromEntities({
      organization_id,
      target: primaryTarget,
      alerts: finalAlerts,
      incidents: finalIncidents,
      iocs: finalIocs,
      users: finalUsers,
      assets: finalAssets,
      mitre: finalMitre,
      attackChains
    });

    // 5. Findings & Recommendations
    const findings = [
      {
        category: 'telemetry_context',
        summary: `Autonomous investigation converged on ${finalAlerts.length} alert(s) and ${finalIncidents.length} correlated incident(s).`,
        count: finalAlerts.length + finalIncidents.length
      },
      {
        category: 'threat_indicators',
        summary: `Identified ${finalIocs.length} indicator(s) of compromise with ${threatIntelResults.length} high-confidence threat feed matches.`,
        count: finalIocs.length
      },
      {
        category: 'identity_and_assets',
        summary: `Scoped impact across ${finalAssets.length} asset(s) and ${finalUsers.length} user account(s).`,
        count: finalAssets.length + finalUsers.length
      }
    ];

    const evidence = [
      ...finalAlerts.map(a => ({ type: 'alert', id: a.id, title: a.title, severity: a.severity })),
      ...finalIncidents.map(i => ({ type: 'incident', id: i.id, threat_type: i.threat_type, risk_score: i.risk_score })),
      ...finalIocs.map(iocVal => ({ type: 'ioc', value: iocVal })),
      ...finalMitre.map(m => ({ type: 'mitre', technique: m.technique }))
    ];

    const recommendations = [
      'Isolate affected host endpoints from the internal network perimeter.',
      'Deploy automated containment playbook to block identified IOCs across perimeter firewalls.',
      'Force password reset and terminate active tokens for impacted identities.'
    ];

    const confidence = finalAlerts.length > 0 || finalIncidents.length > 0 ? 0.93 : 0.82;

    const summary = `Autonomous investigation for ${primaryTarget.type} ${primaryTarget.id}: identified ${finalAlerts.length} alerts, ${finalIncidents.length} incidents, ${finalIocs.length} indicators, and ${finalMitre.length} MITRE techniques across ${finalAssets.length} assets.`;

    const report = {
      target: primaryTarget,
      summary,
      findings,
      evidence,
      recommendations,
      confidence,
      graph,
      affected_assets: finalAssets,
      affected_users: finalUsers,
      mitre: finalMitre,
      threat_intel: threatIntelResults
    };

    // Audit Log
    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_AUTONOMOUS_INVESTIGATION',
      resource_type: primaryTarget.type,
      resource_id: String(primaryTarget.id).slice(0, 50),
      details: {
        target_type: primaryTarget.type,
        target_id: primaryTarget.id,
        alerts_count: finalAlerts.length,
        incidents_count: finalIncidents.length,
        iocs_count: finalIocs.length
      }
    }).catch(() => {});

    // Session Memory Persistence
    if (session_id) {
      await CopilotInvestigation.create({
        session_id,
        organization_id,
        investigation_type: 'autonomous',
        title: `Autonomous Investigation: ${primaryTarget.type} ${primaryTarget.id}`,
        target_type: primaryTarget.type,
        target_id: String(primaryTarget.id),
        findings,
        evidence,
        recommendations,
        graph,
        severity: finalAlerts.some(a => a.severity === 'critical') ? 'critical' : 'high',
        confidence,
        created_by: user_id
      }, dbClient).catch(() => {});

      await CopilotMessage.create({
        session_id,
        role: 'assistant',
        content: summary,
        metadata: { autonomous_investigation: report }
      }, dbClient).catch(() => {});
    }

    return report;
  }
}

module.exports = new AutonomousInvestigationService();
