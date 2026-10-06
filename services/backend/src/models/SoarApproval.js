const db = require('../config/db');

/**
 * SoarApproval Model — Tenant-scoped approval workflows for gated playbook actions
 */
const SoarApproval = {
  VALID_STATUSES: ['pending', 'approved', 'rejected'],

  /**
   * Creates an approval request record for an execution.
   */
  async create({
    execution_id,
    requested_by = null,
    reason = null
  }, client = null) {
    if (!execution_id) throw new Error('SoarApproval Error: execution_id is required');

    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_approvals (
        execution_id,
        requested_by,
        status,
        reason,
        created_at
      )
      VALUES ($1, $2, 'pending', $3, NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [execution_id, requested_by, reason]);
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
    reason = null
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
          decided_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      id,
      cleanStatus,
      decided_by,
      reason
    ]);

    return res.rows[0] || null;
  },

  /**
   * Lists approvals for an organization with optional status filtering.
   */
  async findMany({
    organization_id,
    status,
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
  }
};

module.exports = SoarApproval;
