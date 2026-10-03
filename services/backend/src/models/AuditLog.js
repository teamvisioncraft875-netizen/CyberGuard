const db = require('../config/db');

/**
 * AuditLog Model — Append-only operations on the 'audit_logs' table.
 * Strictly exposes create() and list() — no update or delete functions exist.
 */
const AuditLog = {
  /**
   * Appends an audit log entry.
   *
   * @param {Object} params
   * @param {string|null} [params.organization_id]
   * @param {string|null} [params.user_id]
   * @param {'user'|'admin'|'system_policy'|'system_guard'} params.actor_type
   * @param {string} params.action
   * @param {string} params.resource_type
   * @param {string|null} [params.resource_id]
   * @param {Object} [params.details={}]
   * @param {string|null} [params.ip_address]
   * @param {import('pg').PoolClient} [client=null] - Optional transaction client
   * @returns {Promise<Object>} The inserted audit log record
   */
  async create({
    organization_id = null,
    user_id = null,
    actor_type,
    action,
    resource_type,
    resource_id = null,
    details = {},
    ip_address = null
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.audit_logs (
        organization_id,
        user_id,
        actor_type,
        action,
        resource_type,
        resource_id,
        details,
        ip_address,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      user_id,
      actor_type,
      action,
      resource_type,
      resource_id,
      typeof details === 'string' ? details : JSON.stringify(details),
      ip_address
    ]);
    return res.rows[0];
  },

  /**
   * Queries audit logs with filtering and pagination scoped by organization.
   *
   * @param {Object} filters
   * @param {string} filters.organization_id
   * @param {string} [filters.action]
   * @param {string} [filters.resource_type]
   * @param {string} [filters.user_id]
   * @param {string|Date} [filters.from] - Start timestamp (inclusive)
   * @param {string|Date} [filters.to] - End timestamp (inclusive)
   * @param {number} [filters.limit=25] - Max records (1-100)
   * @param {number} [filters.offset=0] - Offset index
   * @returns {Promise<{ total: number, limit: number, offset: number, logs: Array<Object> }>}
   */
  async list({
    organization_id,
    action,
    resource_type,
    user_id,
    from,
    to,
    limit = 25,
    offset = 0
  }) {
    const conditions = ['organization_id = $1'];
    const values = [organization_id];

    if (action) {
      values.push(action);
      conditions.push(`action = $${values.length}`);
    }

    if (resource_type) {
      values.push(resource_type);
      conditions.push(`resource_type = $${values.length}`);
    }

    if (user_id) {
      values.push(user_id);
      conditions.push(`user_id = $${values.length}`);
    }

    if (from) {
      values.push(from);
      conditions.push(`created_at >= $${values.length}`);
    }

    if (to) {
      values.push(to);
      conditions.push(`created_at <= $${values.length}`);
    }

    const parsedLimit = parseInt(limit, 10);
    const clampedLimit = Number.isInteger(parsedLimit) && parsedLimit > 0
      ? Math.min(parsedLimit, 100)
      : 25;

    const parsedOffset = parseInt(offset, 10);
    const clampedOffset = Number.isInteger(parsedOffset) && parsedOffset >= 0
      ? parsedOffset
      : 0;

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM public.audit_logs
      ${whereClause};
    `;

    const dataQuery = `
      SELECT id, organization_id, user_id, actor_type, action, resource_type, resource_id, details, ip_address, created_at
      FROM public.audit_logs
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${values.length + 1} OFFSET $${values.length + 2};
    `;

    const [countRes, dataRes] = await Promise.all([
      db.query(countQuery, values),
      db.query(dataQuery, [...values, clampedLimit, clampedOffset])
    ]);

    const total = countRes.rows[0]?.total || 0;

    return {
      total,
      limit: clampedLimit,
      offset: clampedOffset,
      logs: dataRes.rows
    };
  }
};

module.exports = AuditLog;
