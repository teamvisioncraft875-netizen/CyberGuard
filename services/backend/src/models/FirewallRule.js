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
    rule_hash = null,
    status = 'pending',
    created_by_id = null,
    expires_at = null,
    source_command_id = null,
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
        rule_hash,
        status,
        created_by_id,
        expires_at,
        source_command_id,
        result,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
      ON CONFLICT (agent_id, rule_hash) WHERE status IN ('pending', 'active') AND rule_hash IS NOT NULL
      DO NOTHING
      RETURNING *;
    `;
    const params = [
      agent_id,
      organization_id,
      rule_type,
      target_ip,
      target_domain,
      rule_id_local,
      rule_hash,
      status,
      created_by_id,
      expires_at,
      source_command_id,
      JSON.stringify(result || {})
    ];
    const res = await db.query(text, params);
    if (res.rows && res.rows.length > 0) {
      return res.rows[0];
    }
    // Conflict fallback
    if (rule_hash) {
      return await this.findActiveByHash(agent_id, rule_hash);
    }
    return null;
  },

  /**
   * Finds an active or pending rule matching agent_id and rule_hash.
   */
  async findActiveByHash(agent_id, rule_hash) {
    const text = `
      SELECT * FROM public.agent_firewall_rules
      WHERE agent_id = $1 AND rule_hash = $2 AND status IN ('pending', 'active')
      ORDER BY created_at DESC LIMIT 1;
    `;
    const res = await db.query(text, [agent_id, rule_hash]);
    return res.rows[0] || null;
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
    const conditions = ['r.organization_id = $1'];
    const params = [organization_id];
    let paramIndex = 2;

    if (agent_id) {
      conditions.push(`r.agent_id = $${paramIndex++}`);
      params.push(agent_id);
    }
    if (status) {
      conditions.push(`r.status = $${paramIndex++}`);
      params.push(status);
    }
    if (rule_type) {
      conditions.push(`r.rule_type = $${paramIndex++}`);
      params.push(rule_type);
    }

    const whereClause = conditions.join(' AND ');
    const countSql = `SELECT COUNT(*)::int AS total FROM public.agent_firewall_rules r WHERE ${whereClause}`;
    const countRes = await db.query(countSql, params);
    const total = countRes.rows[0]?.total || 0;

    const querySql = `
      SELECT r.id, r.agent_id, r.organization_id, r.rule_type, r.target_ip, r.target_domain,
             COALESCE(r.target_ip, r.target_domain) AS target,
             d.hostname AS agent_name,
             r.rule_id_local, r.status, r.created_by_id,
             u.email AS created_by,
             r.source_command_id,
             CASE 
               WHEN r.created_by_id IS NOT NULL OR cmd.requested_by_id IS NOT NULL THEN 'manual'
               ELSE 'policy_engine'
             END AS source,
             r.created_at, r.expires_at, r.deleted_at, r.result
      FROM public.agent_firewall_rules r
      LEFT JOIN public.devices d ON d.id = r.agent_id
      LEFT JOIN public.agent_commands cmd ON cmd.id = r.source_command_id
      LEFT JOIN public.users u ON u.id = COALESCE(r.created_by_id, cmd.requested_by_id)
      WHERE ${whereClause}
      ORDER BY r.created_at DESC
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
