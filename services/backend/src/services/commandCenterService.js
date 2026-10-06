const db = require('../config/db');
const investigationWorkspaceService = require('./investigationWorkspaceService');
const recommendationEngine = require('./recommendationEngine');
const riskScoringService = require('./riskScoringService');
const incidentPrioritizationService = require('./incidentPrioritizationService');
const AttackChainSnapshot = require('../models/AttackChainSnapshot');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

const localCache = new Map();
const CACHE_TTL_MS = 30000; // 30s cache TTL

/**
 * Incident Command Center Service
 *
 * Single consolidated SOC investigation intelligence endpoint providing:
 * - Incident profile
 * - Dynamic risk score & priority
 * - Chronological event timeline
 * - Analyst notes
 * - Tailored response recommendations
 * - Attack chain progression & snapshot
 * - Campaign cluster details
 * - Correlated related incidents
 * - Threat intelligence IOC indicators
 * - Complete audit history
 */
class CommandCenterService {
  /**
   * Invalidate cached command center data for an incident
   */
  invalidateCache(incidentId) {
    for (const key of localCache.keys()) {
      if (key.includes(incidentId)) {
        localCache.delete(key);
      }
    }
  }

  /**
   * Fetch complete Command Center intelligence payload
   *
   * @param {string} incidentId
   * @param {string} organizationId
   * @param {Object} [options]
   * @param {string} [options.actorUserId]
   * @returns {Promise<Object|null>}
   */
  async getCommandCenter(incidentId, organizationId, { actorUserId = null } = {}) {
    const cacheKey = `cmd_center:${organizationId}:${incidentId}`;
    const cached = localCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.payload;
    }

    // 1. Fetch incident record with strict tenant isolation
    const incRes = await db.query(
      `SELECT 
        i.*,
        u.email as assigned_user_email,
        d.device_name,
        d.hostname as device_hostname,
        d.platform as device_platform,
        d.is_trusted as device_trusted,
        d.status as device_status
       FROM public.incidents i
       LEFT JOIN public.users u ON u.id = i.assigned_to
       LEFT JOIN public.devices d ON d.id = i.device_id
       WHERE i.id = $1 AND i.organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      return null;
    }

    const incident = incRes.rows[0];

    // 2. Fetch workspace data & recommendations concurrently
    const [workspaceData, recommendations] = await Promise.all([
      investigationWorkspaceService.getWorkspace(incidentId, organizationId, { actorUserId }),
      recommendationEngine.getRecommendations(incidentId, organizationId, { actorUserId })
    ]);

    // 3. Assemble command center package reusing workspace sub-queries
    const payload = {
      incident,
      risk_score: parseFloat(incident.risk_score) || 0,
      risk_level: incident.risk_level,
      priority: incident.priority || 'P3',
      timeline: workspaceData?.timeline || [],
      notes: workspaceData?.notes || [],
      recommendations,
      attack_chain: workspaceData?.attack_chain || null,
      campaign: workspaceData?.group || null,
      related_incidents: workspaceData?.correlations || [],
      indicators: workspaceData?.iocs || [],
      audit_history: workspaceData?.audit_history || []
    };

    // Store in cache
    localCache.set(cacheKey, { payload, expiresAt: Date.now() + CACHE_TTL_MS });

    // 4. Audit log command center access
    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_guard',
      action: AUDIT_ACTIONS.COMMAND_CENTER_VIEWED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        risk_score: incident.risk_score,
        priority: incident.priority,
        recommendations_count: recommendations.length,
        related_incidents_count: payload.related_incidents.length,
        indicators_count: payload.indicators.length
      }
    });

    return payload;
  }
}

module.exports = new CommandCenterService();
