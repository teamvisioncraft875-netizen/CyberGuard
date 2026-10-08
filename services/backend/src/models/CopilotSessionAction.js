const db = require('../config/db');

/**
 * CopilotSessionAction Model — Records recommended, pending, approved, and executed actions
 * associated with an investigation session for auditability and conversation action memory.
 */
const CopilotSessionAction = {
  VALID_STATUSES: ['recommended', 'pending_approval', 'approved', 'rejected', 'executed', 'failed'],

  /**
   * Records a new session action.
   */
  async create({
    session_id = null,
    organization_id,
    action_type,
    action_payload = {},
    status = 'recommended',
    execution_id = null,
    approval_id = null,
    case_id = null,
    confidence = 0.90,
    reason = '',
    explanation = {},
    requires_approval = false,
    created_by = null
  }, client = null) {
    if (!organization_id) throw new Error('CopilotSessionAction Error: organization_id is required');
    if (!action_type) throw new Error('CopilotSessionAction Error: action_type is required');

    const cleanStatus = (status || 'recommended').toLowerCase();
    if (!this.VALID_STATUSES.includes(cleanStatus)) {
      throw new Error(`CopilotSessionAction Error: Invalid status "${status}". Allowed: ${this.VALID_STATUSES.join(', ')}`);
    }

    const dbClient = client || db;
    const query = `
      INSERT INTO public.copilot_session_actions (
        session_id,
        organization_id,
        action_type,
        action_payload,
        status,
        execution_id,
        approval_id,
        case_id,
        confidence,
        reason,
        explanation,
        requires_approval,
        created_by,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
      RETURNING *;
    `;

    const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    const validSessionId = session_id && UUID_REGEX.test(session_id) ? session_id : null;
    const validExecutionId = execution_id && UUID_REGEX.test(execution_id) ? execution_id : null;
    const validApprovalId = approval_id && UUID_REGEX.test(approval_id) ? approval_id : null;
    const validCaseId = case_id && UUID_REGEX.test(case_id) ? case_id : null;
    const validCreatedBy = created_by && UUID_REGEX.test(created_by) ? created_by : null;

    const res = await dbClient.query(query, [
      validSessionId,
      organization_id,
      action_type.toLowerCase().trim(),
      JSON.stringify(action_payload || {}),
      cleanStatus,
      validExecutionId,
      validApprovalId,
      validCaseId,
      confidence,
      reason,
      JSON.stringify(explanation || {}),
      Boolean(requires_approval),
      validCreatedBy
    ]);

    return res.rows[0];
  },

  /**
   * Finds an action record by ID within an organization.
   */
  async findById(id, organization_id, client = null) {
    if (!id || !organization_id) return null;
    const dbClient = client || db;

    const res = await dbClient.query(
      `SELECT * FROM public.copilot_session_actions WHERE id = $1 AND organization_id = $2;`,
      [id, organization_id]
    );

    return res.rows[0] || null;
  },

  /**
   * Retrieves all actions associated with a session.
   */
  async findBySession(session_id, organization_id, client = null) {
    if (!session_id || !organization_id) return [];
    const dbClient = client || db;

    const res = await dbClient.query(
      `SELECT * FROM public.copilot_session_actions 
       WHERE session_id = $1 AND organization_id = $2
       ORDER BY created_at ASC;`,
      [session_id, organization_id]
    );

    return res.rows;
  },

  /**
   * Updates status and optional metadata (execution_id, approval_id, etc.).
   */
  async updateStatus(id, organization_id, status, updates = {}, client = null) {
    if (!id || !organization_id) throw new Error('CopilotSessionAction Error: id and organization_id required');
    const cleanStatus = (status || '').toLowerCase();
    if (!this.VALID_STATUSES.includes(cleanStatus)) {
      throw new Error(`CopilotSessionAction Error: Invalid status "${status}"`);
    }

    const dbClient = client || db;
    const fields = ['status = $3', 'updated_at = NOW()'];
    const params = [id, organization_id, cleanStatus];
    let idx = 4;

    if (updates.execution_id !== undefined) {
      fields.push(`execution_id = $${idx++}`);
      params.push(updates.execution_id);
    }
    if (updates.approval_id !== undefined) {
      fields.push(`approval_id = $${idx++}`);
      params.push(updates.approval_id);
    }
    if (updates.case_id !== undefined) {
      fields.push(`case_id = $${idx++}`);
      params.push(updates.case_id);
    }
    if (updates.reason !== undefined) {
      fields.push(`reason = $${idx++}`);
      params.push(updates.reason);
    }

    const query = `
      UPDATE public.copilot_session_actions
      SET ${fields.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  }
};

module.exports = CopilotSessionAction;
