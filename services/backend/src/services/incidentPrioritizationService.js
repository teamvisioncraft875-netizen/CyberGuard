const db = require('../config/db');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Incident Prioritization Engine
 *
 * Responsibilities:
 * - Evaluate and assign P1, P2, P3, P4 priorities based on:
 *   - Risk score
 *   - Attack chain progression
 *   - Campaign/group membership
 *   - Asset criticality
 *   - Threat intelligence confidence
 * - Provide prioritized incident list and SOC action queue
 */
class IncidentPrioritizationService {
  /**
   * Determine priority level for an incident
   *
   * @param {Object} incident
   * @param {Object} [context]
   * @returns {'P1' | 'P2' | 'P3' | 'P4'}
   */
  determinePriority(incident, context = {}) {
    const riskScore = incident.risk_score ?? context.risk_score ?? 0;
    const riskLevel = (incident.risk_level || context.risk_level || '').toLowerCase();
    const chainLength = context.chain_length || 0;
    const hasCampaign = Boolean(context.group_id || context.is_campaign);
    const criticalAsset = Boolean(context.critical_asset);

    // Rule 1: Critical (P1)
    if (riskScore >= 76 || riskLevel === 'critical' || chainLength >= 3 || criticalAsset) {
      return 'P1';
    }

    // Rule 2: High (P2)
    if (riskScore >= 51 || riskLevel === 'high' || hasCampaign || chainLength >= 2) {
      return 'P2';
    }

    // Rule 3: Medium (P3)
    if (riskScore >= 26 || riskLevel === 'medium') {
      return 'P3';
    }

    // Rule 4: Low (P4)
    return 'P4';
  }

  /**
   * Evaluate and persist priority for an incident
   */
  async evaluateAndPersist(incidentId, organizationId, { client = null, actorUserId = null } = {}) {
    const dbClient = client || db;

    const incRes = await dbClient.query(
      `SELECT id, organization_id, risk_score, risk_level, priority, threat_type, device_id
       FROM public.incidents
       WHERE id = $1 AND organization_id = $2;`,
      [incidentId, organizationId]
    );

    if (incRes.rows.length === 0) {
      throw new Error(`Incident ${incidentId} not found in organization ${organizationId}`);
    }

    const incident = incRes.rows[0];

    // Check attack chain depth
    let chainLength = 0;
    const chainRes = await dbClient.query(
      `SELECT chain_length FROM public.attack_chain_snapshots WHERE root_incident_id = $1 LIMIT 1;`,
      [incidentId]
    );
    if (chainRes.rows.length > 0) {
      chainLength = chainRes.rows[0].chain_length;
    }

    // Check campaign membership
    let hasCampaign = false;
    const groupRes = await dbClient.query(
      `SELECT ig.id, ig.group_type
       FROM public.incident_group_members igm
       JOIN public.incident_groups ig ON ig.id = igm.group_id
       WHERE igm.incident_id = $1 AND ig.organization_id = $2 LIMIT 1;`,
      [incidentId, organizationId]
    );
    if (groupRes.rows.length > 0) {
      hasCampaign = groupRes.rows[0].group_type === 'campaign' || true;
    }

    const newPriority = this.determinePriority(incident, {
      chain_length: chainLength,
      is_campaign: hasCampaign
    });

    const previousPriority = incident.priority || 'P3';

    if (previousPriority !== newPriority) {
      await dbClient.query(
        `UPDATE public.incidents
         SET priority = $1
         WHERE id = $2 AND organization_id = $3;`,
        [newPriority, incidentId, organizationId]
      );

      auditLog({
        organization_id: organizationId,
        user_id: actorUserId,
        actor_type: actorUserId ? 'admin' : 'system_policy',
        action: AUDIT_ACTIONS.INCIDENT_PRIORITY_CHANGED,
        resource_type: 'incident',
        resource_id: incidentId,
        details: {
          previous_priority: previousPriority,
          new_priority: newPriority,
          risk_score: incident.risk_score
        }
      });
    }

    return newPriority;
  }

  /**
   * Get all prioritized incidents for organization with pagination
   */
  async getPrioritizedIncidents(organizationId, { status = null, priority = null, limit = 50, offset = 0 } = {}) {
    const conditions = ['i.organization_id = $1'];
    const values = [organizationId];

    if (status) {
      values.push(status.toLowerCase());
      conditions.push(`i.status = $${values.length}`);
    }

    if (priority) {
      values.push(priority.toUpperCase());
      conditions.push(`i.priority = $${values.length}`);
    }

    values.push(limit, offset);

    const query = `
      SELECT 
        i.*,
        u.email as assigned_user_email,
        COALESCE(acs.chain_length, 0) as attack_chain_length,
        ig.title as campaign_name,
        ig.id as campaign_id
      FROM public.incidents i
      LEFT JOIN public.users u ON u.id = i.assigned_to
      LEFT JOIN public.attack_chain_snapshots acs ON acs.root_incident_id = i.id
      LEFT JOIN public.incident_group_members igm ON igm.incident_id = i.id
      LEFT JOIN public.incident_groups ig ON ig.id = igm.group_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY 
        CASE i.priority
          WHEN 'P1' THEN 1
          WHEN 'P2' THEN 2
          WHEN 'P3' THEN 3
          WHEN 'P4' THEN 4
          ELSE 5
        END ASC,
        i.risk_score DESC,
        i.created_at DESC
      LIMIT $${values.length - 1} OFFSET $${values.length};
    `;

    const res = await db.query(query, values);
    return res.rows;
  }

  /**
   * Get SOC action queue (active, prioritized incidents awaiting triage/response)
   */
  async getQueue(organizationId, { assigned_to = null, limit = 50, offset = 0 } = {}) {
    const conditions = [
      'i.organization_id = $1',
      "i.status IN ('open', 'investigating')"
    ];
    const values = [organizationId];

    if (assigned_to !== undefined && assigned_to !== null) {
      if (assigned_to === 'unassigned') {
        conditions.push('i.assigned_to IS NULL');
      } else {
        values.push(assigned_to);
        conditions.push(`i.assigned_to = $${values.length}`);
      }
    }

    values.push(limit, offset);

    const query = `
      SELECT 
        i.id,
        i.organization_id,
        i.threat_type,
        i.source_type,
        i.risk_level,
        i.risk_score,
        i.priority,
        i.status,
        i.occurrence_count,
        i.first_seen_at,
        i.last_seen_at,
        i.created_at,
        i.assigned_to,
        i.assigned_at,
        i.escalated_at,
        u.email as assigned_user_email,
        (SELECT COUNT(*)::int FROM public.incident_notes WHERE incident_id = i.id) as notes_count,
        (SELECT COUNT(*)::int FROM public.incident_recommendations WHERE incident_id = i.id) as recommendations_count,
        COALESCE(acs.chain_length, 0) as chain_length,
        ig.title as campaign_name
      FROM public.incidents i
      LEFT JOIN public.users u ON u.id = i.assigned_to
      LEFT JOIN public.attack_chain_snapshots acs ON acs.root_incident_id = i.id
      LEFT JOIN public.incident_group_members igm ON igm.incident_id = i.id
      LEFT JOIN public.incident_groups ig ON ig.id = igm.group_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY 
        CASE i.priority
          WHEN 'P1' THEN 1
          WHEN 'P2' THEN 2
          WHEN 'P3' THEN 3
          WHEN 'P4' THEN 4
          ELSE 5
        END ASC,
        i.risk_score DESC,
        i.created_at DESC
      LIMIT $${values.length - 1} OFFSET $${values.length};
    `;

    const res = await db.query(query, values);
    return res.rows;
  }
}

module.exports = new IncidentPrioritizationService();
