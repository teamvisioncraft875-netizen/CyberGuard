const db = require('../../config/db');

/**
 * Playbook Metrics Service — High-performance SQL analytics for SOAR executions,
 * approval SLA bottlenecks, response latency distributions, and playbook utilization.
 */
const playbookMetricsService = {
  /**
   * Retrieves organization-level aggregate SOAR metrics.
   */
  async getGlobalMetrics(organization_id, client = null) {
    if (!organization_id) throw new Error('playbookMetricsService Error: organization_id is required');
    const dbClient = client || db;

    // 1. Execution Counts and Rates
    const execCountsQuery = `
      SELECT 
        COUNT(*)::int AS total_executions,
        COUNT(CASE WHEN status = 'completed' THEN 1 END)::int AS completed_count,
        COUNT(CASE WHEN status = 'failed' THEN 1 END)::int AS failed_count,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END)::int AS cancelled_count,
        COUNT(CASE WHEN status = 'waiting_approval' THEN 1 END)::int AS waiting_approval_count,
        COUNT(CASE WHEN status = 'retrying' THEN 1 END)::int AS retrying_count,
        COUNT(CASE WHEN status = 'running' THEN 1 END)::int AS running_count,
        COALESCE(AVG(
          CASE 
            WHEN status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL 
            THEN EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000 
          END
        ), 0)::float AS avg_duration_ms
      FROM public.soar_executions
      WHERE organization_id = $1;
    `;
    const execCountsRes = await dbClient.query(execCountsQuery, [organization_id]);
    const ec = execCountsRes.rows[0] || {};

    const total = ec.total_executions || 0;
    const completed = ec.completed_count || 0;
    const failed = ec.failed_count || 0;
    const successRate = total > 0 ? parseFloat(((completed / total) * 100).toFixed(2)) : 0;
    const failureRate = total > 0 ? parseFloat(((failed / total) * 100).toFixed(2)) : 0;
    const avgDurationMs = parseFloat((ec.avg_duration_ms || 0).toFixed(2));

    // 2. Approval Bottlenecks & Metrics
    const approvalQuery = `
      SELECT 
        COUNT(*)::int AS total_approvals,
        COUNT(CASE WHEN a.status = 'approved' THEN 1 END)::int AS approved_count,
        COUNT(CASE WHEN a.status = 'rejected' THEN 1 END)::int AS rejected_count,
        COUNT(CASE WHEN a.status = 'pending' THEN 1 END)::int AS pending_count,
        COUNT(CASE WHEN a.is_expired = true THEN 1 END)::int AS expired_count,
        COUNT(CASE WHEN a.level = 'L1' THEN 1 END)::int AS l1_count,
        COUNT(CASE WHEN a.level = 'L2' THEN 1 END)::int AS l2_count,
        COUNT(CASE WHEN a.level = 'L3' THEN 1 END)::int AS l3_count,
        COALESCE(AVG(
          CASE 
            WHEN a.decided_at IS NOT NULL 
            THEN EXTRACT(EPOCH FROM (a.decided_at - a.created_at)) * 1000 
          END
        ), 0)::float AS avg_decision_time_ms
      FROM public.soar_approvals a
      JOIN public.soar_executions e ON a.execution_id = e.id
      WHERE e.organization_id = $1;
    `;
    const approvalRes = await dbClient.query(approvalQuery, [organization_id]);
    const ap = approvalRes.rows[0] || {};

    // 3. Most Used Playbooks
    const playbooksQuery = `
      SELECT 
        p.id AS playbook_id,
        p.name AS playbook_name,
        COUNT(e.id)::int AS execution_count,
        COUNT(CASE WHEN e.status = 'completed' THEN 1 END)::int AS completed_count,
        COUNT(CASE WHEN e.status = 'failed' THEN 1 END)::int AS failed_count,
        ROUND(
          (COUNT(CASE WHEN e.status = 'completed' THEN 1 END)::numeric / NULLIF(COUNT(e.id), 0)::numeric) * 100, 2
        )::float AS success_rate
      FROM public.soar_playbooks p
      LEFT JOIN public.soar_executions e ON p.id = e.playbook_id
      WHERE p.organization_id = $1
      GROUP BY p.id, p.name
      ORDER BY execution_count DESC
      LIMIT 10;
    `;
    const playbooksRes = await dbClient.query(playbooksQuery, [organization_id]);

    // 4. Response Time Distributions
    const distributionQuery = `
      SELECT 
        COUNT(CASE WHEN duration_sec < 1 THEN 1 END)::int AS under_1s,
        COUNT(CASE WHEN duration_sec >= 1 AND duration_sec < 5 THEN 1 END)::int AS between_1s_5s,
        COUNT(CASE WHEN duration_sec >= 5 AND duration_sec < 30 THEN 1 END)::int AS between_5s_30s,
        COUNT(CASE WHEN duration_sec >= 30 THEN 1 END)::int AS over_30s
      FROM (
        SELECT EXTRACT(EPOCH FROM (completed_at - started_at)) AS duration_sec
        FROM public.soar_executions
        WHERE organization_id = $1 AND status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL
      ) sub;
    `;
    const distRes = await dbClient.query(distributionQuery, [organization_id]);
    const dist = distRes.rows[0] || {};

    return {
      summary: {
        total_executions: total,
        completed_count: completed,
        failed_count: failed,
        cancelled_count: ec.cancelled_count || 0,
        waiting_approval_count: ec.waiting_approval_count || 0,
        retrying_count: ec.retrying_count || 0,
        running_count: ec.running_count || 0,
        success_rate: successRate,
        failure_rate: failureRate,
        average_duration_ms: avgDurationMs
      },
      approval_bottlenecks: {
        total_approvals: ap.total_approvals || 0,
        approved_count: ap.approved_count || 0,
        rejected_count: ap.rejected_count || 0,
        pending_count: ap.pending_count || 0,
        expired_count: ap.expired_count || 0,
        by_level: {
          L1: ap.l1_count || 0,
          L2: ap.l2_count || 0,
          L3: ap.l3_count || 0
        },
        avg_decision_time_ms: parseFloat((ap.avg_decision_time_ms || 0).toFixed(2))
      },
      most_used_playbooks: playbooksRes.rows,
      response_time_distributions: {
        under_1s: dist.under_1s || 0,
        between_1s_5s: dist.between_1s_5s || 0,
        between_5s_30s: dist.between_5s_30s || 0,
        over_30s: dist.over_30s || 0
      }
    };
  },

  /**
   * Retrieves execution and performance metrics for a specific playbook.
   */
  async getPlaybookMetrics(playbook_id, organization_id, client = null) {
    if (!playbook_id) throw new Error('playbookMetricsService Error: playbook_id is required');
    if (!organization_id) throw new Error('playbookMetricsService Error: organization_id is required');
    const dbClient = client || db;

    // Check playbook exists
    const pbRes = await dbClient.query(
      'SELECT id, name, description, trigger_type, enabled FROM public.soar_playbooks WHERE id = $1 AND organization_id = $2;',
      [playbook_id, organization_id]
    );
    const playbook = pbRes.rows[0];
    if (!playbook) {
      throw new Error(`Playbook "${playbook_id}" not found in organization`);
    }

    const countsQuery = `
      SELECT 
        COUNT(*)::int AS total_executions,
        COUNT(CASE WHEN status = 'completed' THEN 1 END)::int AS completed_count,
        COUNT(CASE WHEN status = 'failed' THEN 1 END)::int AS failed_count,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END)::int AS cancelled_count,
        COALESCE(AVG(
          CASE 
            WHEN status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL 
            THEN EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000 
          END
        ), 0)::float AS avg_duration_ms
      FROM public.soar_executions
      WHERE playbook_id = $1 AND organization_id = $2;
    `;
    const countsRes = await dbClient.query(countsQuery, [playbook_id, organization_id]);
    const c = countsRes.rows[0] || {};

    const total = c.total_executions || 0;
    const completed = c.completed_count || 0;
    const failed = c.failed_count || 0;
    const successRate = total > 0 ? parseFloat(((completed / total) * 100).toFixed(2)) : 0;
    const failureRate = total > 0 ? parseFloat(((failed / total) * 100).toFixed(2)) : 0;

    // Step Failures breakdown
    const stepFailuresQuery = `
      SELECT 
        ps.action_type,
        COUNT(es.id)::int AS failure_count
      FROM public.soar_execution_steps es
      JOIN public.soar_playbook_steps ps ON es.playbook_step_id = ps.id
      JOIN public.soar_executions e ON es.execution_id = e.id
      WHERE e.playbook_id = $1 AND e.organization_id = $2 AND es.status = 'failed'
      GROUP BY ps.action_type
      ORDER BY failure_count DESC;
    `;
    const stepFailuresRes = await dbClient.query(stepFailuresQuery, [playbook_id, organization_id]);

    return {
      playbook,
      metrics: {
        total_executions: total,
        completed_count: completed,
        failed_count: failed,
        cancelled_count: c.cancelled_count || 0,
        success_rate: successRate,
        failure_rate: failureRate,
        avg_duration_ms: parseFloat((c.avg_duration_ms || 0).toFixed(2))
      },
      step_failures: stepFailuresRes.rows
    };
  }
};

module.exports = playbookMetricsService;
