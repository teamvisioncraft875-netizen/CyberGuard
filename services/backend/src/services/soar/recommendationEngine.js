const db = require('../../config/db');
const SoarResponseRecommendation = require('../../models/SoarResponseRecommendation');
const actionExecutor = require('./actionExecutor');
const { log: auditLog } = require('../auditService');

/**
 * Recommendation Engine — Computes intelligent, confidence-scored response actions
 * based on alert severity, MITRE techniques, IOC risk scores, and historical success rates.
 */
class RecommendationEngine {
  /**
   * Evaluates historical success rate for a given action type in the organization.
   */
  async getHistoricalSuccessRate(organizationId, actionType, client = null) {
    const dbClient = client || db;
    const query = `
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN ses.status = 'completed' THEN 1 END) as successes
      FROM public.soar_execution_steps ses
      JOIN public.soar_executions se ON ses.execution_id = se.id
      JOIN public.soar_playbook_steps sps ON ses.playbook_step_id = sps.id
      WHERE se.organization_id = $1 AND sps.action_type = $2;
    `;
    const { rows } = await dbClient.query(query, [organizationId, actionType]);
    const total = parseInt(rows[0]?.total || 0, 10);
    const successes = parseInt(rows[0]?.successes || 0, 10);
    if (total === 0) return 0.85; // Prior belief / baseline default
    return Math.max(0.4, Math.min(1.0, successes / total));
  }

  /**
   * Generates intelligent response recommendations.
   */
  async generateRecommendations({
    organization_id,
    alert_id = null,
    case_id = null,
    ioc_id = null,
    alert_severity = 'high',
    mitre_techniques = [],
    ioc_risk_score = 70,
    context = {}
  }, client = null) {
    const dbClient = client || db;

    if (!organization_id) throw new Error('RecommendationEngine requires organization_id');

    const cleanSeverity = (alert_severity || 'medium').toLowerCase();
    const cleanTechniques = Array.isArray(mitre_techniques) ? mitre_techniques : (mitre_techniques ? [mitre_techniques] : []);
    const riskScore = Number(ioc_risk_score || 50);

    const recommendations = [];

    // Rule 1: Perimeter Malicious IP -> Block IP
    if (context.ip || context.source_ip || cleanTechniques.some(t => ['T1071', 'T1071.001', 'T1110.003'].includes(t))) {
      const histRate = await this.getHistoricalSuccessRate(organization_id, 'block_ip', dbClient);
      const ip = context.ip || context.source_ip || '198.51.100.25';
      const severityMultiplier = cleanSeverity === 'critical' ? 1.15 : (cleanSeverity === 'high' ? 1.05 : 0.95);
      const confidence = Math.min(99, Math.round((riskScore * 0.4 + histRate * 50) * severityMultiplier));

      recommendations.push({
        action_type: 'block_ip',
        recommended_action: `Block IP ${ip} on perimeter firewalls`,
        action_payload: { ip },
        confidence_score: confidence,
        risk_score: riskScore,
        mitre_techniques: cleanTechniques.filter(t => t.startsWith('T1071') || t.startsWith('T1110')),
        rationale: `Detected external adversary network traffic with risk score ${riskScore} and ${(histRate * 100).toFixed(0)}% historical success.`
      });
    }

    // Rule 2: Account Compromise / Brute Force -> Disable User
    if (context.user || context.target_user || cleanTechniques.some(t => ['T1110', 'T1078', 'T1098'].includes(t))) {
      const histRate = await this.getHistoricalSuccessRate(organization_id, 'disable_user', dbClient);
      const user = context.user || context.target_user || 'compromised_user';
      const confidence = Math.min(98, Math.round(75 * histRate + (cleanSeverity === 'critical' ? 20 : 10)));

      recommendations.push({
        action_type: 'disable_account',
        recommended_action: `Disable compromised directory account "${user}"`,
        action_payload: { user },
        confidence_score: confidence,
        risk_score: Math.max(riskScore, 75),
        mitre_techniques: cleanTechniques.filter(t => t.startsWith('T1110') || t.startsWith('T1078')),
        rationale: `Credential theft/brute force indicator detected against user "${user}". Rapid account disablement prevents lateral movement.`
      });
    }

    // Rule 3: Endpoint Host Compromise / Malware -> Isolate Endpoint
    if (context.host || context.asset_name || cleanTechniques.some(t => ['T1059', 'T1204', 'T1486'].includes(t))) {
      const histRate = await this.getHistoricalSuccessRate(organization_id, 'isolate_host', dbClient);
      const host = context.host || context.asset_name || 'workstation-corp-01';
      const confidence = Math.min(99, Math.round(80 * histRate + (cleanSeverity === 'critical' ? 18 : 8)));

      recommendations.push({
        action_type: 'isolate_endpoint',
        recommended_action: `Isolate endpoint "${host}" via EDR network containment`,
        action_payload: { host },
        confidence_score: confidence,
        risk_score: Math.max(riskScore, 85),
        mitre_techniques: cleanTechniques.filter(t => t.startsWith('T1059') || t.startsWith('T1486')),
        rationale: `Malicious execution/ransomware behavior detected on host "${host}". Endpoint isolation recommended to sever C2 and prevent staging.`
      });
    }

    // Rule 4: High / Critical Incident -> Create Ticket & Escalate Approval
    if (cleanSeverity === 'critical' || cleanSeverity === 'high') {
      recommendations.push({
        action_type: 'create_ticket',
        recommended_action: 'Create high-priority ITSM security incident ticket',
        action_payload: {
          title: `Security Alert ${alert_id || 'Incident'}: Escalation required`,
          priority: cleanSeverity
        },
        confidence_score: 95.0,
        risk_score: riskScore,
        mitre_techniques: cleanTechniques,
        rationale: 'High/Critical alert requires automated ticketing for tracking and compliance.'
      });

      recommendations.push({
        action_type: 'escalate_approval',
        recommended_action: 'Escalate to Tier 2 / Tier 3 Incident Response lead for sign-off',
        action_payload: { level: cleanSeverity === 'critical' ? 'L3' : 'L2' },
        confidence_score: 90.0,
        risk_score: riskScore,
        mitre_techniques: cleanTechniques,
        rationale: 'Action risk policy mandates executive/senior analyst approval for high-impact remediations.'
      });
    }

    // Persist all generated recommendations
    const createdRecords = [];
    for (const rec of recommendations) {
      const recRecord = await SoarResponseRecommendation.create({
        organization_id,
        alert_id,
        case_id,
        ioc_id,
        action_type: rec.action_type,
        recommended_action: rec.recommended_action,
        action_payload: rec.action_payload,
        confidence_score: rec.confidence_score,
        risk_score: rec.risk_score,
        mitre_techniques: rec.mitre_techniques,
        rationale: rec.rationale,
        status: 'pending'
      }, dbClient);
      createdRecords.push(recRecord);
    }

    await auditLog({
      organization_id,
      action: 'SOAR_RECOMMENDATION_GENERATED',
      resource_type: 'soar_recommendation',
      resource_id: createdRecords[0]?.id || null,
      details: {
        alert_id,
        case_id,
        recommendations_count: createdRecords.length
      }
    });

    return createdRecords;
  }

  /**
   * Applies and executes a recommendation.
   */
  async applyRecommendation(recommendationId, organizationId, userId, client = null) {
    const dbClient = client || db;

    const recommendation = await SoarResponseRecommendation.findById(recommendationId, organizationId, dbClient);
    if (!recommendation) {
      throw new Error(`Recommendation "${recommendationId}" not found for organization`);
    }

    if (recommendation.status !== 'pending') {
      throw new Error(`Recommendation cannot be applied: current status is "${recommendation.status}"`);
    }

    // Execute the underlying action via ActionExecutor
    let execResult = null;
    try {
      const actionMapping = {
        'block_ip': 'block_ip',
        'disable_account': 'disable_user',
        'isolate_endpoint': 'isolate_host',
        'create_ticket': 'create_ticket',
        'dns_sinkhole': 'send_webhook'
      };
      const resolvedAction = actionMapping[recommendation.action_type] || recommendation.action_type;

      execResult = await actionExecutor.executeAction(
        resolvedAction,
        recommendation.action_payload || {},
        { organization_id: organizationId, actor_id: userId },
        dbClient
      );
    } catch (err) {
      execResult = { error: err.message, success: false };
    }

    // Mark recommendation applied
    const updated = await SoarResponseRecommendation.updateStatus(recommendationId, organizationId, {
      status: 'applied',
      applied_by: userId,
      applied_at: new Date()
    }, dbClient);

    await auditLog({
      organization_id: organizationId,
      user_id: userId,
      action: 'SOAR_RECOMMENDATION_APPLIED',
      resource_type: 'soar_recommendation',
      resource_id: recommendationId,
      details: {
        action_type: recommendation.action_type,
        execution_result: execResult
      }
    });

    return {
      recommendation: updated,
      execution_result: execResult
    };
  }

  /**
   * Dismisses a recommendation.
   */
  async dismissRecommendation(recommendationId, organizationId, userId, reason = 'Analyst override', client = null) {
    const dbClient = client || db;

    const recommendation = await SoarResponseRecommendation.findById(recommendationId, organizationId, dbClient);
    if (!recommendation) {
      throw new Error(`Recommendation "${recommendationId}" not found for organization`);
    }

    const updated = await SoarResponseRecommendation.updateStatus(recommendationId, organizationId, {
      status: 'dismissed',
      dismissed_by: userId,
      dismissed_reason: reason,
      dismissed_at: new Date()
    }, dbClient);

    await auditLog({
      organization_id: organizationId,
      user_id: userId,
      action: 'SOAR_RECOMMENDATION_DISMISSED',
      resource_type: 'soar_recommendation',
      resource_id: recommendationId,
      details: { reason }
    });

    return updated;
  }

  /**
   * Lists recommendations.
   */
  async listRecommendations(organizationId, filters = {}, client = null) {
    return await SoarResponseRecommendation.findMany({
      ...filters,
      organization_id: organizationId
    }, client);
  }
}

const recommendationEngine = new RecommendationEngine();
module.exports = recommendationEngine;
