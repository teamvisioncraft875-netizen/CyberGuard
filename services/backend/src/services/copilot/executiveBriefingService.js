const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * Executive Security Briefing Service — Synthesizes high-level risk posture,
 * top business risks, and operational remediation for C-level and SOC leadership.
 */
class ExecutiveBriefingService {
  /**
   * Generates an executive risk briefing for an enterprise tenant.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id]
   * @param {number} [params.timeframe_days=30]
   * @returns {Promise<Object>} Executive briefing payload
   */
  async generateBriefing({ organization_id, user_id = null, timeframe_days = 30 }, client = null) {
    if (!organization_id) throw new Error('ExecutiveBriefingService requires organization_id');
    const dbClient = client || db;

    // 1. Fetch Alerts summary
    const alertRes = await dbClient.query(`
      SELECT id, title, severity, status, mitre_technique, metadata, created_at
      FROM public.siem_alerts
      WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' days')::interval
      ORDER BY created_at DESC;
    `, [organization_id, timeframe_days]);
    const alerts = alertRes.rows;

    // 2. Fetch Incidents
    const incRes = await dbClient.query(`
      SELECT id, threat_type, risk_level, risk_score, explanation, status, device_id, user_id, created_at
      FROM public.incidents
      WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' days')::interval
      ORDER BY risk_score DESC;
    `, [organization_id, timeframe_days]);
    const incidents = incRes.rows;

    // 3. Fetch Investigations & Hunts
    const invRes = await dbClient.query(`
      SELECT id, investigation_type, title, severity, confidence, created_at
      FROM public.copilot_investigations
      WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' days')::interval
      ORDER BY created_at DESC;
    `, [organization_id, timeframe_days]);
    const investigations = invRes.rows;
    const hunts = investigations.filter(i => i.investigation_type === 'hunt');

    // 4. Fetch Playbook Executions
    let executions = [];
    try {
      const execRes = await dbClient.query(`
        SELECT id, playbook_id, status, created_at
        FROM public.soar_executions
        WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' days')::interval
        ORDER BY created_at DESC;
      `, [organization_id, timeframe_days]);
      executions = execRes.rows;
    } catch (_) {}

    // 5. Aggregate metrics
    const criticalIncidents = incidents.filter(i => (i.risk_level || '').toLowerCase() === 'critical');
    const highIncidents = incidents.filter(i => (i.risk_level || '').toLowerCase() === 'high');
    const activeIncidents = incidents.filter(i => i.status !== 'resolved' && i.status !== 'closed');

    // Critical Assets
    const assetSet = new Set();
    incidents.forEach(i => { if (i.device_id) assetSet.add(String(i.device_id)); });
    alerts.forEach(a => {
      const meta = a.metadata || {};
      if (meta.hostname) assetSet.add(String(meta.hostname));
      if (meta.host) assetSet.add(String(meta.host));
    });
    const criticalAssets = Array.from(assetSet).map(a => ({ asset: a, critical_exposure: true }));

    // Severity distribution
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(a => {
      const s = (a.severity || 'medium').toLowerCase();
      if (severityCounts[s] !== undefined) severityCounts[s]++;
      else severityCounts.medium++;
    });

    // Top Risks
    const topRisks = [];
    if (criticalIncidents.length > 0) {
      topRisks.push({
        title: 'Active High-Impact Security Incidents',
        severity: 'critical',
        detail: `${criticalIncidents.length} critical incident(s) detected with high risk scores requiring immediate analyst response.`
      });
    }
    if (hunts.length > 0) {
      topRisks.push({
        title: 'Adversary Tradecraft Observed in Hunts',
        severity: 'high',
        detail: `${hunts.length} threat hunting operation(s) executed uncovering anomalous scripting and persistence markers.`
      });
    }
    if (alerts.some(a => a.mitre_technique === 'T1003')) {
      topRisks.push({
        title: 'Credential Exposure / Memory Dumping Risk',
        severity: 'critical',
        detail: 'ATT&CK Technique T1003 (OS Credential Dumping) logged on internal directory or domain endpoints.'
      });
    }
    if (topRisks.length === 0) {
      topRisks.push({
        title: 'Baseline Perimeter Exposure',
        severity: 'medium',
        detail: 'Routine perimeter scanning and opportunistic external probes observed within acceptable thresholds.'
      });
    }

    // Business Impact
    const overallRisk = (criticalIncidents.length > 0 || severityCounts.critical > 0) ? 'critical'
      : (highIncidents.length > 0 || severityCounts.high > 0) ? 'high' : 'medium';

    const businessImpact = {
      risk_level: overallRisk,
      financial_exposure_rating: overallRisk === 'critical' ? 'elevated' : 'moderate',
      operational_disruption_risk: criticalIncidents.length > 0 ? 'active_monitoring' : 'low',
      summary: `Enterprise risk posture currently ranked as ${overallRisk.toUpperCase()}. Incident response automation contained ${executions.length} threat event(s) across corporate digital assets.`
    };

    // Recommended Actions
    const recommendedActions = [
      'Maintain automated SOAR playbook containment for high-fidelity perimeter alerts.',
      'Enforce mandatory credential rotation and MFA verification on sensitive administrative accounts.',
      'Audit external attack surfaces and patch critical vulnerabilities on exposed network services.'
    ];

    const executiveSummary = `Executive Risk Briefing (${timeframe_days}d window): Enterprise threat monitoring processed ${alerts.length} alert(s) and ${incidents.length} incident(s). ${activeIncidents.length} incident(s) remain actively tracked. Automated SOAR workflows executed ${executions.length} response runbooks, containing lateral movement risks.`;

    const report = {
      executive_summary: executiveSummary,
      top_risks: topRisks,
      active_incidents: activeIncidents.map(i => ({ id: i.id, threat_type: i.threat_type, risk_level: i.risk_level, risk_score: i.risk_score })),
      critical_assets: criticalAssets,
      trend_analysis: {
        timeframe_days,
        alerts_count: alerts.length,
        incidents_count: incidents.length,
        hunts_count: hunts.length,
        playbooks_executed: executions.length,
        severity_distribution: severityCounts
      },
      recommended_actions: recommendedActions,
      business_impact: businessImpact
    };

    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_EXECUTIVE_BRIEFING',
      resource_type: 'executive_briefing',
      resource_id: organization_id,
      details: { risk_level: overallRisk, alerts_count: alerts.length, incidents_count: incidents.length }
    }).catch(() => {});

    return report;
  }
}

module.exports = new ExecutiveBriefingService();
