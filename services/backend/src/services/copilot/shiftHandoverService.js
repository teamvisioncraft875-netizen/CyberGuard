const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * SOC Shift Handover Generator — Produces seamless shift transfer briefings for incoming
 * SOC lead analysts and operators.
 */
class ShiftHandoverService {
  /**
   * Generates a shift handover report.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id]
   * @param {number} [params.shift_hours=12]
   * @returns {Promise<Object>} Handover report
   */
  async generateHandover({ organization_id, user_id = null, shift_hours = 12 }, client = null) {
    if (!organization_id) throw new Error('ShiftHandoverService requires organization_id');
    const dbClient = client || db;

    // 1. Incidents worked during shift
    const incRes = await dbClient.query(`
      SELECT id, threat_type, risk_level, risk_score, status, assigned_to, created_at, last_seen_at
      FROM public.incidents
      WHERE organization_id = $1 AND (created_at >= NOW() - ($2 || ' hours')::interval OR last_seen_at >= NOW() - ($2 || ' hours')::interval)
      ORDER BY created_at DESC;
    `, [organization_id, shift_hours]);
    const incidentsWorked = incRes.rows;

    // 2. Investigations completed
    const invRes = await dbClient.query(`
      SELECT id, investigation_type, title, severity, confidence, created_at
      FROM public.copilot_investigations
      WHERE organization_id = $1 AND created_at >= NOW() - ($2 || ' hours')::interval
      ORDER BY created_at DESC;
    `, [organization_id, shift_hours]);
    const investigationsCompleted = invRes.rows;

    // 3. Unresolved threats (incidents open or investigating)
    const unresRes = await dbClient.query(`
      SELECT id, threat_type, risk_level, risk_score, status, created_at
      FROM public.incidents
      WHERE organization_id = $1 AND status::text IN ('open', 'investigating')
      ORDER BY risk_score DESC
      LIMIT 15;
    `, [organization_id]);
    const unresolvedThreats = unresRes.rows;

    // 4. Pending approvals
    let pendingApprovals = [];
    try {
      const appRes = await dbClient.query(`
        SELECT a.id, a.level, a.status, a.reason, a.created_at
        FROM public.soar_approvals a
        JOIN public.soar_executions e ON a.execution_id = e.id
        WHERE e.organization_id = $1 AND a.status = 'pending'
        ORDER BY a.created_at DESC;
      `, [organization_id]);
      pendingApprovals = appRes.rows;
    } catch (_) {}

    // 5. Pending playbook executions
    let pendingExecutions = [];
    try {
      const execRes = await dbClient.query(`
        SELECT id, playbook_id, status, created_at
        FROM public.soar_executions
        WHERE organization_id = $1 AND status IN ('pending', 'running')
        ORDER BY created_at DESC;
      `, [organization_id]);
      pendingExecutions = execRes.rows;
    } catch (_) {}

    // 6. Analyst notes
    let analystNotes = [];
    try {
      const noteRes = await dbClient.query(`
        SELECT id, incident_id, note, created_at
        FROM public.incident_notes
        WHERE incident_id IN (
          SELECT id FROM public.incidents WHERE organization_id = $1
        ) AND created_at >= NOW() - ($2 || ' hours')::interval
        ORDER BY created_at DESC;
      `, [organization_id, shift_hours]);
      analystNotes = noteRes.rows.map(n => ({
        id: n.id,
        incident_id: n.incident_id,
        note: n.note,
        created_at: n.created_at
      }));
    } catch (_) {}

    const summary = `Shift Handover (${shift_hours}h window): ${incidentsWorked.length} incident(s) worked, ${investigationsCompleted.length} autonomous investigation(s) completed. ${unresolvedThreats.length} unresolved threat(s) flagged for incoming shift. ${pendingApprovals.length} action(s) require manual authorization.`;

    const report = {
      shift_hours,
      generated_at: new Date().toISOString(),
      summary,
      incidents_worked: incidentsWorked,
      investigations_completed: investigationsCompleted,
      unresolved_threats: unresolvedThreats,
      pending_approvals: pendingApprovals,
      pending_playbook_executions: pendingExecutions,
      analyst_notes: analystNotes
    };

    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_HANDOVER_GENERATED',
      resource_type: 'shift_handover',
      resource_id: organization_id,
      details: { shift_hours, incidents_count: incidentsWorked.length, unresolved_count: unresolvedThreats.length }
    }).catch(() => {});

    return report;
  }
}

module.exports = new ShiftHandoverService();
