const db = require('../config/db');

/**
 * ResponseAction Model — Phase 1B Automated Response Layer.
 * Manages proposed, pending, and executed response actions.
 * Strictly exposes create() and list() — no update or delete operations are exposed directly.
 */
const ResponseAction = {
  /**
   * Creates a response action record.
   *
   * @param {Object} params
   * @param {string|null} [params.organization_id]
   * @param {string} params.incident_id
   * @param {string|null} [params.policy_id]
   * @param {'notify_admin'|'notify_user'|'revoke_session'|'force_password_reset'|'require_mfa'|'block_ip'|'block_domain'|'suspend_device'|'isolate_device'} params.action_type
   * @param {'shadow'|'live'} [params.action_mode='shadow']
   * @param {'proposed'|'pending_approval'|'approved'|'scheduled'|'rejected'|'executed'|'failed'|'expired'|'rolled_back'} [params.status='proposed']
   * @param {string|null} [params.requested_by_id]
   * @param {string|null} [params.approved_by_id]
   * @param {Date|string|null} [params.approved_at]
   * @param {Object} [params.target={}]
   * @param {Object|null} [params.result=null]
   * @param {Date|string|null} [params.scheduled_at]
   * @param {Date|string|null} [params.executed_at]
   * @param {Date|string|null} [params.expires_at]
   * @param {import('pg').PoolClient} [client=null] - Optional transaction client
   * @returns {Promise<Object>} The inserted response action record
   */
  async create({
    organization_id = null,
    incident_id,
    policy_id = null,
    action_type,
    action_mode = 'shadow',
    status = 'proposed',
    requested_by_id = null,
    approved_by_id = null,
    approved_at = null,
    target = {},
    result = null,
    scheduled_at = null,
    executed_at = null,
    expires_at = null,
    target_device_id = null
  }, client = null) {
    const dbClient = client || db;
    const targetJsonStr = typeof target === 'string' ? target : JSON.stringify(target || {});

    // 1. Dedup check: Query existing active response action
    const existingCheckSql = `
      SELECT * FROM public.response_actions
      WHERE incident_id = $1
        AND action_type = $2
        AND target::text = $3
        AND status NOT IN ('rejected', 'failed', 'expired', 'rolled_back')
      LIMIT 1;
    `;
    const existingRes = await dbClient.query(existingCheckSql, [incident_id, action_type, targetJsonStr]);
    if (existingRes.rows && existingRes.rows.length > 0) {
      return existingRes.rows[0];
    }

    // 2. Insert with ON CONFLICT DO NOTHING using the partial unique index
    const text = `
      INSERT INTO public.response_actions (
        organization_id,
        incident_id,
        policy_id,
        action_type,
        action_mode,
        status,
        requested_by_id,
        approved_by_id,
        approved_at,
        target,
        result,
        created_at,
        scheduled_at,
        executed_at,
        expires_at,
        target_device_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), $12, $13, $14, $15)
      ON CONFLICT (incident_id, action_type, (target::text))
      WHERE status NOT IN ('rejected', 'failed', 'expired', 'rolled_back')
      DO NOTHING
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      incident_id,
      policy_id,
      action_type,
      action_mode,
      status,
      requested_by_id,
      approved_by_id,
      approved_at,
      targetJsonStr,
      result ? (typeof result === 'string' ? result : JSON.stringify(result)) : null,
      scheduled_at,
      executed_at,
      expires_at,
      target_device_id
    ]);

    if (res.rows && res.rows.length > 0) {
      return res.rows[0];
    }

    // 3. Fallback: If ON CONFLICT prevented insert, return the newly created row
    const fallbackRes = await dbClient.query(existingCheckSql, [incident_id, action_type, targetJsonStr]);
    return fallbackRes.rows[0] || null;
  },

  /**
   * Queries response actions with filtering and pagination scoped by organization.
   *
   * @param {Object} filters
   * @param {string} filters.organization_id - Mandatory scoping organization ID
   * @param {string} [filters.incident_id]
   * @param {string} [filters.status]
   * @param {string|Date} [filters.from] - Start timestamp (inclusive)
   * @param {string|Date} [filters.to] - End timestamp (inclusive)
   * @param {number} [filters.limit=25] - Max records (1-100)
   * @param {number} [filters.offset=0] - Offset index
   * @returns {Promise<{ total: number, limit: number, offset: number, actions: Array<Object> }>}
   */
  async list({
    organization_id,
    incident_id,
    status,
    from,
    to,
    limit = 25,
    offset = 0
  }) {
    const conditions = ['organization_id = $1'];
    const values = [organization_id];

    if (incident_id) {
      values.push(incident_id);
      conditions.push(`incident_id = $${values.length}`);
    }

    if (status) {
      values.push(status);
      conditions.push(`status = $${values.length}`);
    }

    if (from) {
      values.push(from);
      conditions.push(`created_at >= $${values.length}`);
    }

    if (to) {
      values.push(to);
      conditions.push(`created_at <= $${values.length}`);
    }

    const whereClause = conditions.join(' AND ');

    // 1. Total count query
    const countSql = `SELECT COUNT(*)::int AS count FROM public.response_actions WHERE ${whereClause};`;
    const countRes = await db.query(countSql, values);
    const total = countRes.rows[0]?.count || 0;

    // 2. Paginated results query
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 25, 1), 100);
    const parsedOffset = Math.max(parseInt(offset, 10) || 0, 0);

    const dataSql = `
      SELECT *
      FROM public.response_actions
      WHERE ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${values.length + 1} OFFSET $${values.length + 2};
    `;
    const dataRes = await db.query(dataSql, [...values, parsedLimit, parsedOffset]);

    return {
      total,
      limit: parsedLimit,
      offset: parsedOffset,
      actions: dataRes.rows
    };
  },

  /**
   * Finds a response action by ID scoped to organization.
   *
   * @param {string} id
   * @param {string} organization_id
   * @returns {Promise<Object|null>}
   */
  async findByIdAndOrg(id, organization_id) {
    const text = 'SELECT * FROM public.response_actions WHERE id = $1 AND organization_id = $2;';
    const res = await db.query(text, [id, organization_id]);
    return res.rows[0] || null;
  },

  /**
   * Updates response action status upon administrator approval or rejection.
   *
   * @param {string} id
   * @param {Object} params
   * @param {string} params.organization_id
   * @param {'approved'|'rejected'} params.status
   * @param {string} params.approved_by_id
   * @param {Date|string} [params.approved_at]
   * @returns {Promise<Object|null>}
   */
  async setApproval(id, { organization_id, status, approved_by_id, approved_at = new Date() }) {
    const text = `
      UPDATE public.response_actions
      SET status = $1,
          approved_by_id = $2,
          approved_at = $3
      WHERE id = $4 AND organization_id = $5
      RETURNING *;
    `;
    const res = await db.query(text, [status, approved_by_id, approved_at, id, organization_id]);
    return res.rows[0] || null;
  }
};

module.exports = ResponseAction;
