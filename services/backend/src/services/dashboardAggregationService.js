const db = require('../config/db');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * SOC Dashboard Aggregation Engine
 *
 * Generates aggregated SOC operational metrics, trends, and SLA analytics:
 * - Open, Resolved, Critical, High incidents
 * - Active Attack Chains & Campaigns
 * - MTTD (Mean Time To Detect) & MTTR (Mean Time To Respond)
 * - Top Threat Types & MITRE ATT&CK Techniques
 * - Daily/Weekly incident volume trend graphs
 */
class DashboardAggregationService {
  /**
   * Main SOC Dashboard Overview
   */
  async getOverview(organizationId, { actorUserId = null } = {}) {
    // Single consolidated high-performance query for incident state counts & MTTD/MTTR
    const incStatsPromise = db.query(
      `SELECT 
        COUNT(CASE WHEN status IN ('open', 'investigating') THEN 1 END)::int AS open_incidents,
        COUNT(CASE WHEN status = 'resolved' THEN 1 END)::int AS resolved_incidents,
        COUNT(CASE WHEN risk_level = 'critical' THEN 1 END)::int AS critical_incidents,
        COUNT(CASE WHEN risk_level = 'high' THEN 1 END)::int AS high_risk_incidents,
        COUNT(*)::int AS total_incidents,
        ROUND(COALESCE(AVG(CASE 
          WHEN first_seen_at IS NOT NULL AND first_seen_at <= created_at 
          THEN EXTRACT(EPOCH FROM (created_at - first_seen_at)) / 3600.0 
          ELSE 0.1
        END), 0)::numeric, 2) AS mttd_hours,
        ROUND(COALESCE(AVG(CASE 
          WHEN resolved_at IS NOT NULL AND created_at <= resolved_at 
          THEN EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0 
          ELSE NULL 
        END), 0)::numeric, 2) AS mttr_hours
       FROM public.incidents
       WHERE organization_id = $1;`,
      [organizationId]
    );

    // Attack chains count
    const chainCountPromise = db.query(
      `SELECT COUNT(*)::int AS count FROM public.attack_chain_snapshots WHERE organization_id = $1;`,
      [organizationId]
    );

    // Campaigns count
    const campaignCountPromise = db.query(
      `SELECT COUNT(*)::int AS count FROM public.incident_groups WHERE organization_id = $1;`,
      [organizationId]
    );

    // Top 5 Threat Types
    const topThreatsPromise = db.query(
      `SELECT threat_type, COUNT(*)::int AS count
       FROM public.incidents
       WHERE organization_id = $1
       GROUP BY threat_type
       ORDER BY count DESC
       LIMIT 5;`,
      [organizationId]
    );

    // Top 5 MITRE ATT&CK Techniques
    const topMitrePromise = db.query(
      `SELECT m.technique_id, m.technique_name, COUNT(*)::int AS count
       FROM public.mitre_mappings m
       JOIN public.incidents i ON i.id = m.incident_id
       WHERE i.organization_id = $1
       GROUP BY m.technique_id, m.technique_name
       ORDER BY count DESC
       LIMIT 5;`,
      [organizationId]
    );

    const [incStatsRes, chainRes, campaignRes, topThreatsRes, topMitreRes] = await Promise.all([
      incStatsPromise,
      chainCountPromise,
      campaignCountPromise,
      topThreatsPromise,
      topMitrePromise
    ]);

    const stats = incStatsRes.rows[0] || {};

    const overview = {
      open_incidents: stats.open_incidents || 0,
      resolved_incidents: stats.resolved_incidents || 0,
      critical_incidents: stats.critical_incidents || 0,
      high_risk_incidents: stats.high_risk_incidents || 0,
      total_incidents: stats.total_incidents || 0,
      attack_chains: chainRes.rows[0]?.count || 0,
      campaigns: campaignRes.rows[0]?.count || 0,
      mttd_hours: parseFloat(stats.mttd_hours) || 0,
      mttr_hours: parseFloat(stats.mttr_hours) || 0,
      top_threat_types: topThreatsRes.rows,
      top_mitre_techniques: topMitreRes.rows
    };

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_guard',
      action: AUDIT_ACTIONS.DASHBOARD_VIEWED,
      resource_type: 'dashboard',
      resource_id: 'overview',
      details: { view_type: 'overview' }
    });

    return overview;
  }

  /**
   * Incident Trends over Time
   */
  async getTrends(organizationId, { days = 14, actorUserId = null } = {}) {
    const daysInt = Math.max(1, Math.min(90, parseInt(days, 10) || 14));

    const res = await db.query(
      `SELECT 
        DATE_TRUNC('day', created_at) AS date,
        COUNT(*)::int AS total,
        COUNT(CASE WHEN risk_level = 'critical' THEN 1 END)::int AS critical,
        COUNT(CASE WHEN risk_level = 'high' THEN 1 END)::int AS high,
        COUNT(CASE WHEN risk_level = 'medium' THEN 1 END)::int AS medium,
        COUNT(CASE WHEN risk_level = 'low' THEN 1 END)::int AS low,
        COUNT(CASE WHEN status = 'resolved' THEN 1 END)::int AS resolved
       FROM public.incidents
       WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' days')::interval
       GROUP BY DATE_TRUNC('day', created_at)
       ORDER BY date ASC;`,
      [organizationId, daysInt]
    );

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_guard',
      action: AUDIT_ACTIONS.DASHBOARD_VIEWED,
      resource_type: 'dashboard',
      resource_id: 'trends',
      details: { view_type: 'trends', days: daysInt }
    });

    return res.rows;
  }

  /**
   * Detailed SOC Operational Metrics & Breakdown
   */
  async getMetrics(organizationId, { actorUserId = null } = {}) {
    // 1. Priority breakdown
    const priorityPromise = db.query(
      `SELECT priority, COUNT(*)::int as count
       FROM public.incidents
       WHERE organization_id = $1
       GROUP BY priority
       ORDER BY priority ASC;`,
      [organizationId]
    );

    // 2. Status & Assignment breakdown
    const assignmentPromise = db.query(
      `SELECT 
        COUNT(CASE WHEN assigned_to IS NOT NULL THEN 1 END)::int AS assigned_count,
        COUNT(CASE WHEN assigned_to IS NULL THEN 1 END)::int AS unassigned_count,
        COUNT(CASE WHEN escalated_at IS NOT NULL THEN 1 END)::int AS escalated_count,
        COUNT(*)::int AS total_count
       FROM public.incidents
       WHERE organization_id = $1;`,
      [organizationId]
    );

    // 3. Source types breakdown
    const sourceTypesPromise = db.query(
      `SELECT source_type, COUNT(*)::int as count
       FROM public.incidents
       WHERE organization_id = $1
       GROUP BY source_type
       ORDER BY count DESC;`,
      [organizationId]
    );

    const [priorityRes, assignmentRes, sourceTypesRes] = await Promise.all([
      priorityPromise,
      assignmentPromise,
      sourceTypesPromise
    ]);

    const assign = assignmentRes.rows[0] || {};

    const metrics = {
      priority_distribution: priorityRes.rows,
      assigned_incidents: assign.assigned_count || 0,
      unassigned_incidents: assign.unassigned_count || 0,
      escalated_incidents: assign.escalated_count || 0,
      total_incidents: assign.total_count || 0,
      source_type_distribution: sourceTypesRes.rows
    };

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_guard',
      action: AUDIT_ACTIONS.DASHBOARD_VIEWED,
      resource_type: 'dashboard',
      resource_id: 'metrics',
      details: { view_type: 'metrics' }
    });

    return metrics;
  }
}

module.exports = new DashboardAggregationService();
