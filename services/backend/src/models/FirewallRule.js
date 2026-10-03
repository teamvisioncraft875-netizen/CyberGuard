const db = require('../config/db');

/**
 * FirewallRule Model — CRUD and lifecycle operations on 'agent_firewall_rules'
 */
const FirewallRule = {
  /**
   * Creates a new firewall rule record.
   */
  async create({
    agent_id,
    organization_id,
    rule_type,
    target_ip = null,
    target_domain = null,
    rule_id_local = null,
    status = 'pending',
    created_by_id = null,
    expires_at = null,
    result = {}
  }) {
    const text = `
      INSERT INTO public.agent_firewall_rules (
        agent_id,
        organization_id,
        rule_type,
        target_ip,
        target_domain,
        rule_id_local,
        status,
        created_by_id,
        expires_at,
        result,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING *;
    `;
    const params = [
      agent_id,
      organization_id,
      rule_type,
      target_ip,
      target_domain,
      rule_id_local,
      status,
      created_by_id,
      expires_at,
      JSON.stringify(result || {})
    ];
    const res = await db.query(text, params);
    return res.rows[0];
  },

  /**
   * Finds a rule by id, optionally scoped by organization_id.
   */
  async findById(id, organization_id = null) {
    let text = `SELECT * FROM public.agent_firewall_rules WHERE id = $1`;
    const params = [id];
    if (organization_id) {
      text += ` AND organization_id = $2`;
      params.push(organization_id);
    }
    const res = await db.query(text, params);
    return res.rows[0] || null;
  },

  /**
   * Lists firewall rules for an organization with optional filtering and pagination.
   */
  async findByOrg(organization_id, { agent_id, status, rule_type, limit = 50, offset = 0 } = {}) {
    const conditions = ['organization_id = $1'];
    const params = [organization_id];
    let paramIndex = 2;

    if (agent_id) {
      conditions.push(`agent_id = $${paramIndex++}`);
      params.push(agent_id);
    }
    if (status) {
      conditions.push(`status = $${paramIndex++}`);
      params.push(status);
    }
    if (rule_type) {
      conditions.push(`rule_type = $${paramIndex++}`);
      params.push(rule_type);
    }

    const whereClause = conditions.join(' AND ');
    const countSql = `SELECT COUNT(*)::int AS total FROM public.agent_firewall_rules WHERE ${whereClause}`;
    const countRes = await db.query(countSql, params);
    const total = countRes.rows[0]?.total || 0;

    const querySql = `
      SELECT id, agent_id, organization_id, rule_type, target_ip, target_domain,
             rule_id_local, status, created_by_id, created_at, expires_at, deleted_at, result
      FROM public.agent_firewall_rules
      WHERE ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++};
    `;
    params.push(limit, offset);

    const rowsRes = await db.query(querySql, params);
    return {
      total,
      limit,
      offset,
      rules: rowsRes.rows
    };
  },

  /**
   * Marks a rule for deletion (status = 'pending_delete' or 'deleted').
   */
  async updateStatus(id, organization_id, status, deleted_at = null) {
    const text = `
      UPDATE public.agent_firewall_rules
      SET status = $3,
          deleted_at = COALESCE($4, deleted_at)
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const res = await db.query(text, [id, organization_id, status, deleted_at]);
    return res.rows[0] || null;
  },

  /**
   * Deletes a rule permanently.
   */
  async deleteById(id, organization_id) {
    const text = `
      DELETE FROM public.agent_firewall_rules
      WHERE id = $1 AND organization_id = $2
      RETURNING id;
    `;
    const res = await db.query(text, [id, organization_id]);
    return res.rows[0] || null;
  }
};

module.exports = FirewallRule;
