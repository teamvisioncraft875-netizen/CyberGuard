const db = require('../../config/db');
const SoarCase = require('../../models/SoarCase');
const SoarApproval = require('../../models/SoarApproval');
const SoarExecution = require('../../models/SoarExecution');
const SoarConnector = require('../../models/SoarConnector');
const SoarPlaybook = require('../../models/SoarPlaybook');
const SoarResponseRecommendation = require('../../models/SoarResponseRecommendation');
const { log: auditLog } = require('../auditService');

/**
 * SOAR Dashboard Service — Aggregates real-time SOC perspectives:
 * Executive, Analyst, and Engineering views.
 */
const soarDashboardService = {
  /**
   * Executive View — High-level ROI, resolution velocity, and threat landscape
   */
  async getExecutiveView(organizationId, client = null) {
    const dbClient = client || db;

    // 1. Cases resolved & closed
    const casesQuery = `
      SELECT 
        COUNT(*)::int as total_cases,
        COUNT(CASE WHEN status IN ('resolved', 'closed') THEN 1 END)::int as cases_resolved,
        COALESCE(AVG(
          CASE WHEN closed_at IS NOT NULL AND created_at IS NOT NULL
          THEN EXTRACT(EPOCH FROM (closed_at - created_at)) * 1000
          END
        ), 900000.0)::float as avg_resolution_time_ms
      FROM public.soar_cases
      WHERE organization_id = $1;
    `;
    const { rows: caseRows } = await dbClient.query(casesQuery, [organizationId]);
    const caseStats = caseRows[0] || {};

    // 2. Automated responses executed
    const execQuery = `
      SELECT 
        COUNT(*)::int as responses_executed,
        COALESCE(AVG(
          CASE WHEN status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL
          THEN EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000
          END
        ), 1250.0)::float as mean_response_time_ms
      FROM public.soar_executions
      WHERE organization_id = $1 AND status = 'completed';
    `;
    const { rows: execRows } = await dbClient.query(execQuery, [organizationId]);
    const execStats = execRows[0] || {};

    // 3. Threat categories distribution
    const threatQuery = `
      SELECT 
        COALESCE(severity, 'medium') as category,
        COUNT(*)::int as count
      FROM public.soar_cases
      WHERE organization_id = $1
      GROUP BY severity;
    `;
    const { rows: threatRows } = await dbClient.query(threatQuery, [organizationId]);

    const responsesExecuted = execStats.responses_executed || 0;
    const hoursSaved = parseFloat((responsesExecuted * 1.5).toFixed(1)); // 1.5 analyst hours saved per SOAR automation

    const result = {
      cases_resolved: caseStats.cases_resolved || 0,
      total_cases: caseStats.total_cases || 0,
      responses_executed: responsesExecuted,
      mean_response_time_ms: parseFloat((execStats.mean_response_time_ms || 0).toFixed(2)),
      avg_case_resolution_time_ms: parseFloat((caseStats.avg_resolution_time_ms || 0).toFixed(2)),
      hours_saved_estimate: hoursSaved,
      threat_categories: threatRows.map(r => ({ category: r.category, count: r.count }))
    };

    await auditLog({
      organization_id: organizationId,
      action: 'SOAR_DASHBOARD_VIEWED',
      resource_type: 'soar_dashboard',
      details: { view: 'executive' }
    });

    return result;
  },

  /**
   * Analyst View — Triage queue, active investigations, and pending recommendations
   */
  async getAnalystView(organizationId, client = null) {
    const dbClient = client || db;

    // 1. Active cases
    const activeCasesRes = await SoarCase.findMany({
      organization_id: organizationId,
      status: 'open',
      limit: 10
    }, dbClient);
    const activeCases = activeCasesRes?.data || (Array.isArray(activeCasesRes) ? activeCasesRes : []);
    const activeCasesCount = typeof activeCasesRes?.total === 'number' ? activeCasesRes.total : activeCases.length;

    // 2. Pending approvals
    const approvalRes = await SoarApproval.findMany({
      organization_id: organizationId,
      status: 'pending',
      limit: 10
    }, dbClient);
    const pendingApprovals = approvalRes?.data || (Array.isArray(approvalRes) ? approvalRes : []);
    const pendingApprovalsCount = typeof approvalRes?.total === 'number' ? approvalRes.total : pendingApprovals.length;

    // 3. Pending recommended actions
    const recommendationsRes = await SoarResponseRecommendation.findMany({
      organization_id: organizationId,
      status: 'pending',
      limit: 10
    }, dbClient);
    const recommendations = recommendationsRes?.data || (Array.isArray(recommendationsRes) ? recommendationsRes : []);
    const recommendationsCount = typeof recommendationsRes?.total === 'number' ? recommendationsRes.total : recommendations.length;

    // 4. Execution response queue (running or waiting approval)
    const queueQuery = `
      SELECT e.id, e.playbook_id, e.status, e.started_at, p.name as playbook_name
      FROM public.soar_executions e
      JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE e.organization_id = $1 AND e.status IN ('running', 'waiting_approval', 'retrying')
      ORDER BY e.created_at DESC
      LIMIT 10;
    `;
    const { rows: responseQueue } = await dbClient.query(queueQuery, [organizationId]);

    const result = {
      active_cases_count: activeCasesCount,
      active_cases: activeCases,
      pending_approvals_count: pendingApprovalsCount,
      pending_approvals: pendingApprovals,
      recommended_actions_count: recommendationsCount,
      recommended_actions: recommendations,
      response_queue_count: responseQueue.length,
      response_queue: responseQueue
    };

    await auditLog({
      organization_id: organizationId,
      action: 'SOAR_DASHBOARD_VIEWED',
      resource_type: 'soar_dashboard',
      details: { view: 'analyst' }
    });

    return result;
  },

  /**
   * Engineering View — Health telemetry, connector diagnostics, and recovery metrics
   */
  async getEngineeringView(organizationId, client = null) {
    const dbClient = client || db;

    // 1. Playbook health
    const playbooksQuery = `
      SELECT 
        p.id, p.name, p.enabled,
        COUNT(e.id)::int as total_runs,
        COUNT(CASE WHEN e.status = 'completed' THEN 1 END)::int as completed_runs,
        COUNT(CASE WHEN e.status = 'failed' THEN 1 END)::int as failed_runs
      FROM public.soar_playbooks p
      LEFT JOIN public.soar_executions e ON p.id = e.playbook_id
      WHERE p.organization_id = $1
      GROUP BY p.id, p.name, p.enabled;
    `;
    const { rows: playbookRows } = await dbClient.query(playbooksQuery, [organizationId]);
    const playbookHealth = playbookRows.map(p => ({
      id: p.id,
      name: p.name,
      status: p.enabled ? 'healthy' : 'disabled',
      total_runs: p.total_runs,
      completed_runs: p.completed_runs,
      failed_runs: p.failed_runs,
      health_percentage: p.total_runs > 0 ? parseFloat(((p.completed_runs / p.total_runs) * 100).toFixed(1)) : 100.0
    }));

    // 2. Connector health
    const connectors = await SoarConnector.findMany({ organization_id: organizationId }, dbClient);
    const connectorHealth = connectors.map(c => ({
      id: c.id,
      name: c.name,
      type: c.type,
      status: c.status,
      health_status: c.health_status,
      last_health_check: c.last_health_check
    }));

    // 3. Failed executions
    const failedQuery = `
      SELECT e.id, e.playbook_id, e.status, e.started_at, e.completed_at, p.name as playbook_name
      FROM public.soar_executions e
      JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE e.organization_id = $1 AND e.status = 'failed'
      ORDER BY e.created_at DESC
      LIMIT 10;
    `;
    const { rows: failedExecutions } = await dbClient.query(failedQuery, [organizationId]);

    // 4. Recovery statistics
    const recoveryQuery = `
      SELECT 
        COALESCE(SUM(retry_count), 0)::int as total_retries,
        COUNT(CASE WHEN status = 'completed' AND retry_count > 0 THEN 1 END)::int as recovered_executions,
        COUNT(CASE WHEN status = 'failed' THEN 1 END)::int as unrecovered_failures
      FROM public.soar_executions
      WHERE organization_id = $1;
    `;
    const { rows: recRows } = await dbClient.query(recoveryQuery, [organizationId]);
    const recStats = recRows[0] || {};

    const result = {
      playbook_health: playbookHealth,
      connector_health: connectorHealth,
      failed_executions_count: failedExecutions.length,
      failed_executions: failedExecutions,
      recovery_statistics: {
        total_retries: recStats.total_retries || 0,
        recovered_executions: recStats.recovered_executions || 0,
        unrecovered_failures: recStats.unrecovered_failures || 0,
        recovery_success_rate: (recStats.recovered_executions + recStats.unrecovered_failures) > 0
          ? parseFloat(((recStats.recovered_executions / (recStats.recovered_executions + recStats.unrecovered_failures)) * 100).toFixed(1))
          : 100.0
      }
    };

    await auditLog({
      organization_id: organizationId,
      action: 'SOAR_DASHBOARD_VIEWED',
      resource_type: 'soar_dashboard',
      details: { view: 'engineering' }
    });

    return result;
  }
};

module.exports = soarDashboardService;
