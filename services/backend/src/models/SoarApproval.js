const db = require('../config/db');

/**
 * SoarApproval Model — Tenant-scoped approval workflows for gated playbook actions
 * Supports multi-level escalation (L1 Analyst, L2 Senior Analyst, L3 SOC Admin), expiration, and rejection tracking.
 */
const SoarApproval = {
  VALID_STATUSES: ['pending', 'approved', 'rejected'],
  VALID_LEVELS: ['L1', 'L2', 'L3'],

  /**
   * Creates an approval request record for an execution.
   */
  async create({
    execution_id,
    requested_by = null,
    reason = null,
    level = 'L1',
    expires_at = null
  }, client = null) {
    if (!execution_id) throw new Error('SoarApproval Error: execution_id is required');

    const cleanLevel = (level || 'L1').toUpperCase();
    if (!this.VALID_LEVELS.includes(cleanLevel)) {
      throw new Error(`SoarApproval Error: Invalid approval level "${level}". Allowed: ${this.VALID_LEVELS.join(', ')}`);
    }

    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_approvals (
        execution_id,
        requested_by,
        status,
        reason,
        level,
        expires_at,
        created_at
      )
      VALUES ($1, $2, 'pending', $3, $4, $5, NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      execution_id,
      requested_by,
      reason,
      cleanLevel,
      expires_at
    ]);
    return res.rows[0];
  },

  /**
   * Retrieves an approval by ID, verifying tenant boundary via joined execution.
   */
  async findById(id, organization_id = null, client = null) {
    if (!id) return null;
    const dbClient = client || db;

    let query = `
      SELECT 
        a.*,
        e.organization_id,
        e.playbook_id,
        e.status AS execution_status,
        p.name AS playbook_name
      FROM public.soar_approvals a
      JOIN public.soar_executions e ON a.execution_id = e.id
      JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE a.id = $1
    `;
    const params = [id];

    if (organization_id) {
      query += ` AND e.organization_id = $2;`;
      params.push(organization_id);
    }

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Retrieves the most recent approval for a given execution.
   */
  async findByExecutionId(execution_id, client = null) {
    if (!execution_id) return null;
    const dbClient = client || db;

    const query = `
      SELECT *
      FROM public.soar_approvals
      WHERE execution_id = $1
      ORDER BY created_at DESC
      LIMIT 1;
    `;

    const res = await dbClient.query(query, [execution_id]);
    return res.rows[0] || null;
  },

  /**
   * Updates an approval decision (approved or rejected).
   */
  async decide(id, {
    status,
    decided_by = null,
    reason = null,
    rejection_comment = null
  }, client = null) {
    if (!id) throw new Error('SoarApproval Error: id is required');
    if (!status || !['approved', 'rejected'].includes(status.toLowerCase())) {
      throw new Error('SoarApproval Error: status must be "approved" or "rejected"');
    }

    const dbClient = client || db;
    const cleanStatus = status.toLowerCase();

    const query = `
      UPDATE public.soar_approvals
      SET status = $2,
          approved_by = $3,
          reason = COALESCE($4, reason),
          rejection_comment = COALESCE($5, rejection_comment),
          decided_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      id,
      cleanStatus,
      decided_by,
      reason,
      rejection_comment
    ]);

    return res.rows[0] || null;
  },

  /**
   * Escalates an approval request to a higher authority level (e.g., L1 -> L2 or L2 -> L3).
   */
  async escalate(id, {
    escalated_to_level,
    reason = null,
    expires_at = null
  }, client = null) {
    if (!id) throw new Error('SoarApproval Error: id is required');
    const targetLevel = (escalated_to_level || 'L2').toUpperCase();
    if (!this.VALID_LEVELS.includes(targetLevel)) {
      throw new Error(`SoarApproval Error: Invalid target level "${escalated_to_level}"`);
    }

    const dbClient = client || db;
    const query = `
      UPDATE public.soar_approvals
      SET escalated_to_level = $2,
          level = $2,
          reason = COALESCE($3, reason),
          expires_at = COALESCE($4, expires_at)
      WHERE id = $1
      RETURNING *;
    `;

    const res = await dbClient.query(query, [id, targetLevel, reason, expires_at]);
    return res.rows[0] || null;
  },

  /**
   * Marks a pending approval as expired.
   */
  async markExpired(id, client = null) {
    if (!id) return null;
    const dbClient = client || db;
    const query = `
      UPDATE public.soar_approvals
      SET is_expired = true,
          status = 'rejected',
          rejection_comment = 'Approval expired automatically due to timeout SLA',
          decided_at = NOW()
      WHERE id = $1 AND status = 'pending'
      RETURNING *;
    `;
    const res = await dbClient.query(query, [id]);
    return res.rows[0] || null;
  },

  /**
   * Finds all pending approvals that have exceeded their expires_at timestamp.
   */
  async findPendingExpired(client = null) {
    const dbClient = client || db;
    const query = `
      SELECT a.*, e.organization_id
      FROM public.soar_approvals a
      JOIN public.soar_executions e ON a.execution_id = e.id
      WHERE a.status = 'pending' AND a.expires_at IS NOT NULL AND a.expires_at <= NOW();
    `;
    const res = await dbClient.query(query);
    return res.rows;
  },

  /**
   * Lists approvals for an organization with optional status and level filtering.
   */
  async findMany({
    organization_id,
    status,
    level,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('SoarApproval Error: organization_id is required');

    const dbClient = client || db;
    const params = [organization_id];
    let idx = 2;
    const whereClauses = ['e.organization_id = $1'];

    if (status) {
      whereClauses.push(`a.status = $${idx++}`);
      params.push(status.toLowerCase());
    }

    if (level) {
      whereClauses.push(`a.level = $${idx++}`);
      params.push(level.toUpperCase());
    }

    const whereStr = whereClauses.join(' AND ');

    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM public.soar_approvals a
      JOIN public.soar_executions e ON a.execution_id = e.id
      WHERE ${whereStr};
    `;
    const countRes = await dbClient.query(countQuery, params);
    const total = countRes.rows[0]?.total || 0;

    const dataQuery = `
      SELECT 
        a.*,
        e.playbook_id,
        e.status AS execution_status,
        p.name AS playbook_name
      FROM public.soar_approvals a
      JOIN public.soar_executions e ON a.execution_id = e.id
      JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE ${whereStr}
      ORDER BY a.created_at DESC
      LIMIT $${idx++} OFFSET $${idx++};
    `;
    params.push(Math.max(1, limit), Math.max(0, offset));

    const res = await dbClient.query(dataQuery, params);
    return { data: res.rows, total };
  },

  /**
   * Atomically consumes an approved approval for single-use high-risk action execution.
   * Enforces tenant isolation via joined execution.
   * Race-safe: exactly one concurrent request can consume an approval.
   */
  async consumeApproval(id, organization_id, client = null) {
    if (!id || !organization_id) return null;
    const dbClient = client || db;

    const query = `
      UPDATE public.soar_approvals a
      SET consumed = true,
          consumed_at = NOW()
      FROM public.soar_executions e
      WHERE a.id = $1
        AND a.execution_id = e.id
        AND e.organization_id = $2
        AND a.status = 'approved'
        AND a.consumed = false
      RETURNING a.*, e.organization_id;
    `;

    const res = await dbClient.query(query, [id, organization_id]);
    return res.rows[0] || null;
  }
};

module.exports = SoarApproval;
