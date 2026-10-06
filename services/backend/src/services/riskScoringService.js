const db = require('../config/db');
const AttackChainSnapshot = require('../models/AttackChainSnapshot');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Risk Scoring Engine
 *
 * Risk Score (0-100) =
 *   Incident Severity Weight (0-30)
 *   + Attack Chain Confidence (0-20)
 *   + IOC Confidence (0-15)
 *   + Threat Intel Confidence (0-15)
 *   + Asset Criticality (0-10)
 *   + Historical Incident Frequency (0-10)
 *
 * Risk Levels:
 *   0-25:   Low
 *   26-50:  Medium
 *   51-75:  High
 *   76-100: Critical
 */
class RiskScoringService {
  /**
   * Determine risk level from numeric score
   */
  getRiskLevel(score) {
    if (score >= 76) return 'critical';
    if (score >= 51) return 'high';
    if (score >= 26) return 'medium';
    return 'low';
  }

  /**
   * Calculate and persist risk score for an incident
   *
   * @param {string} incidentId
   * @param {string} organizationId
   * @param {Object} [options]
   * @param {Object} [options.client] - Optional db transaction client
   * @param {string} [options.actorUserId] - Optional actor ID for audit logging
   * @returns {Promise<{risk_score: number, risk_level: string, breakdown: Object}>}
   */
  async calculateRiskScore(incidentId, organizationId, { client = null, actorUserId = null } = {}) {
    const dbClient = client || db;

    // 1. Fetch incident record with strict tenant isolation
    const incRes = await dbClient.query(
      `SELECT id, user_id, organization_id, threat_type, risk_level, risk_score, occurrence_count, device_id, baseline_severity
       FROM public.incidents
       WHERE id = $1 AND organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      throw new Error(`Incident ${incidentId} not found in organization ${organizationId}`);
    }

    const incident = incRes.rows[0];

    // 2. Baseline Severity Weight (derived from immutable baseline_severity to prevent feedback inflation)
    let severityWeight = 28;
    const baselineLevel = (incident.baseline_severity || incident.risk_level || '').toLowerCase();
    switch (baselineLevel) {
      case 'critical':
        severityWeight = 76;
        break;
      case 'high':
        severityWeight = 52;
        break;
      case 'medium':
        severityWeight = 28;
        break;
      case 'low':
        severityWeight = 12;
        break;
      default:
        severityWeight = 28;
    }

    // 3. Attack Chain Confidence & Stage Progression (0-10)
    let attackChainScore = 0;
    try {
      const chainSnapshot = await AttackChainSnapshot.findByIncident(incidentId, dbClient);
      if (chainSnapshot) {
        const length = chainSnapshot.chain_length || 1;
        const conf = parseFloat(chainSnapshot.confidence_score) || 0.8;
        if (length >= 4) {
          attackChainScore = Math.round(20 * conf);
        } else if (length === 3) {
          attackChainScore = Math.round(16 * conf);
        } else if (length === 2) {
          attackChainScore = Math.round(12 * conf);
        } else {
          attackChainScore = Math.round(6 * conf);
        }
      }
    } catch {
      attackChainScore = 0;
    }

    // 4. IOC Confidence (0-15)
    let iocScore = 0;
    try {
      const iocRes = await dbClient.query(
        `SELECT COUNT(*)::int as count, COALESCE(MAX(reputation_score), 0) as max_rep
         FROM public.incident_ioc_matches
         WHERE incident_id = $1 AND organization_id = $2;`,
        [incidentId, organizationId]
      );
      const iocCount = iocRes.rows[0]?.count || 0;
      const maxRep = parseFloat(iocRes.rows[0]?.max_rep) || 0;

      if (iocCount > 0) {
        iocScore = Math.min(15, Math.round(iocCount * 4 + (maxRep / 100) * 5));
      }
    } catch {
      iocScore = 0;
    }

    // 5. Threat Intel Confidence (0-15)
    let threatIntelScore = 0;
    try {
      // Check related threat intel or feed sources
      const tiRes = await dbClient.query(
        `SELECT COUNT(DISTINCT feed_source)::int as sources, COUNT(*)::int as total
         FROM public.incident_ioc_matches
         WHERE incident_id = $1 AND organization_id = $2 AND feed_source IS NOT NULL;`,
        [incidentId, organizationId]
      );
      const sources = tiRes.rows[0]?.sources || 0;
      const total = tiRes.rows[0]?.total || 0;
      threatIntelScore = Math.min(15, sources * 5 + total * 2);
    } catch {
      threatIntelScore = 0;
    }

    // 6. Asset Criticality (0-10)
    let assetCriticalityScore = 5; // standard base criticality
    try {
      if (incident.device_id) {
        const devRes = await dbClient.query(
          `SELECT is_trusted, status, platform
           FROM public.devices
           WHERE id = $1 AND organization_id = $2;`,
          [incident.device_id, organizationId]
        );
        if (devRes.rows.length > 0) {
          const device = devRes.rows[0];
          if (device.platform === 'server' || device.is_trusted === false || device.status === 'suspended') {
            assetCriticalityScore = 10;
          } else {
            assetCriticalityScore = 8;
          }
        }
      }
    } catch {
      assetCriticalityScore = 5;
    }

    // 7. Historical Incident Frequency (0-10)
    const occurrences = incident.occurrence_count || 1;
    let frequencyScore = 2;
    if (occurrences >= 10) frequencyScore = 10;
    else if (occurrences >= 5) frequencyScore = 7;
    else if (occurrences >= 2) frequencyScore = 4;
    else frequencyScore = 2;

    // Calculate total score clamped between 0 and 100
    const rawTotal = severityWeight + attackChainScore + iocScore + threatIntelScore + assetCriticalityScore + frequencyScore;
    const finalScore = Math.min(100, Math.max(0, Math.round(rawTotal)));
    const newRiskLevel = this.getRiskLevel(finalScore);

    const breakdown = {
      severity_weight: severityWeight,
      attack_chain_confidence: attackChainScore,
      ioc_confidence: iocScore,
      threat_intel_confidence: threatIntelScore,
      asset_criticality: assetCriticalityScore,
      historical_frequency: frequencyScore
    };

    // Persist new score and level
    const previousScore = incident.risk_score;
    const previousLevel = incident.risk_level;

    await dbClient.query(
      `UPDATE public.incidents
       SET risk_score = $1, risk_level = $2::risk_level, baseline_severity = COALESCE(baseline_severity, $5)
       WHERE id = $3 AND organization_id = $4;`,
      [finalScore, newRiskLevel, incidentId, organizationId, baselineLevel]
    );

    // Audit log if score changed
    if (previousScore !== finalScore || previousLevel !== newRiskLevel) {
      auditLog({
        organization_id: organizationId,
        user_id: actorUserId,
        actor_type: actorUserId ? 'admin' : 'system_policy',
        action: AUDIT_ACTIONS.RISK_SCORE_UPDATED,
        resource_type: 'incident',
        resource_id: incidentId,
        details: {
          previous_score: previousScore,
          new_score: finalScore,
          previous_level: previousLevel,
          new_level: newRiskLevel,
          breakdown
        }
      });
    }

    return {
      risk_score: finalScore,
      risk_level: newRiskLevel,
      breakdown
    };
  }
}

module.exports = new RiskScoringService();
