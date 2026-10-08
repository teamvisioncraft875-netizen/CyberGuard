const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * Security Posture Analysis Service — Calculates enterprise-wide cyber defense maturity
 * across detection coverage, MITRE mapping, alert quality, investigation completeness,
 * playbook orchestration, and response efficacy.
 */
class SecurityPostureService {
  /**
   * Evaluates tenant security posture and returns a 0–100 score.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Posture report
   */
  async evaluatePosture({ organization_id, user_id = null }, client = null) {
    if (!organization_id) throw new Error('SecurityPostureService requires organization_id');
    const dbClient = client || db;

    // 1. Alert counts & Quality
    const alertRes = await dbClient.query(`
      SELECT COUNT(*)::int as total,
             COUNT(*) FILTER (WHERE status != 'false_positive')::int as valid_alerts,
             COUNT(DISTINCT mitre_technique)::int as mitre_techniques
      FROM public.siem_alerts
      WHERE organization_id = $1;
    `, [organization_id]);
    const totalAlerts = alertRes.rows[0].total || 0;
    const validAlerts = alertRes.rows[0].valid_alerts || 0;
    const uniqueMitreTechniques = alertRes.rows[0].mitre_techniques || 0;

    const alertQuality = totalAlerts > 0 ? Math.round((validAlerts / totalAlerts) * 100) : 85;
    const mitreCoverage = Math.min(100, Math.round((uniqueMitreTechniques / 10) * 100) || 75);

    // 2. Incidents & Response Effectiveness
    const incRes = await dbClient.query(`
      SELECT COUNT(*)::int as total,
             COUNT(*) FILTER (WHERE status::text IN ('contained', 'resolved', 'closed'))::int as resolved_incidents
      FROM public.incidents
      WHERE organization_id = $1;
    `, [organization_id]);
    const totalIncidents = incRes.rows[0].total || 0;
    const resolvedIncidents = incRes.rows[0].resolved_incidents || 0;

    const responseEffectiveness = totalIncidents > 0 ? Math.round((resolvedIncidents / totalIncidents) * 100) : 80;

    // 3. Investigation Quality
    const invRes = await dbClient.query(`
      SELECT COUNT(*)::int as total
      FROM public.copilot_investigations
      WHERE organization_id = $1;
    `, [organization_id]);
    const totalInvestigations = invRes.rows[0].total || 0;
    const investigationQuality = totalIncidents > 0
      ? Math.min(100, Math.round((totalInvestigations / totalIncidents) * 100))
      : 85;

    // 4. Playbook Utilization
    let totalExecutions = 0;
    try {
      const execRes = await dbClient.query(`
        SELECT COUNT(*)::int as total FROM public.soar_executions WHERE organization_id = $1;
      `, [organization_id]);
      totalExecutions = execRes.rows[0].total || 0;
    } catch (_) {}
    const playbookUtilization = totalIncidents > 0
      ? Math.min(100, Math.round((totalExecutions / totalIncidents) * 100))
      : 75;

    // 5. Detection Coverage
    let activeRules = 5;
    try {
      const ruleRes = await dbClient.query(`
        SELECT COUNT(*)::int as total FROM public.siem_detection_rules WHERE organization_id = $1 AND enabled = true;
      `, [organization_id]);
      activeRules = ruleRes.rows[0].total || 5;
    } catch (_) {}
    const detectionCoverage = Math.min(100, Math.max(60, activeRules * 12));

    // Calculate aggregate score (0–100)
    const postureScore = Math.min(100, Math.max(0, Math.round(
      detectionCoverage * 0.20 +
      mitreCoverage * 0.20 +
      alertQuality * 0.15 +
      investigationQuality * 0.15 +
      playbookUtilization * 0.15 +
      responseEffectiveness * 0.15
    )));

    let rating = 'Robust';
    if (postureScore < 50) rating = 'Needs Improvement';
    else if (postureScore < 75) rating = 'Moderate';
    else if (postureScore >= 90) rating = 'Optimal';

    const report = {
      posture_score: postureScore,
      rating,
      metrics: {
        detection_coverage: detectionCoverage,
        mitre_coverage: mitreCoverage,
        alert_quality: alertQuality,
        investigation_quality: investigationQuality,
        playbook_utilization: playbookUtilization,
        response_effectiveness: responseEffectiveness
      },
      summary: `Overall Security Posture Score: ${postureScore}/100 (${rating}). Detection coverage stands at ${detectionCoverage}%, with response effectiveness at ${responseEffectiveness}%.`,
      recommendations: [
        'Expand MITRE ATT&CK coverage across Initial Access and Persistence tactics.',
        'Increase automated SOAR playbook containment workflows for tier-1 alerts.',
        'Conduct routine threat hunts to validate detection efficacy.'
      ]
    };

    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_POSTURE_ANALYZED',
      resource_type: 'security_posture',
      resource_id: organization_id,
      details: { posture_score: postureScore, rating }
    }).catch(() => {});

    return report;
  }
}

module.exports = new SecurityPostureService();
