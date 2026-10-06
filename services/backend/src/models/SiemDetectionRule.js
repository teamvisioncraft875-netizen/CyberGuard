const db = require('../config/db');

/**
 * SiemDetectionRule Model — Manages detection rules for real-time SIEM correlation
 */
const SiemDetectionRule = {
  /**
   * Creates a new detection rule
   */
  async create({
    organization_id = null,
    name,
    description = '',
    enabled = true,
    severity = 'medium',
    rule_type,
    conditions = {}
  }, client = null) {
    const dbClient = client || db;
    const query = `
      INSERT INTO public.siem_detection_rules (
        organization_id, name, description, enabled, severity, rule_type, conditions, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(query, [
      organization_id,
      name,
      description,
      enabled,
      severity,
      rule_type,
      JSON.stringify(conditions)
    ]);
    return res.rows[0];
  },

  /**
   * Finds a rule by ID (tenant-scoped or system template)
   */
  async findById(id, organizationId = null, client = null) {
    const dbClient = client || db;
    let query = `SELECT * FROM public.siem_detection_rules WHERE id = $1`;
    const params = [id];

    if (organizationId) {
      query += ` AND (organization_id IS NULL OR organization_id = $2)`;
      params.push(organizationId);
    }

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Finds all rules applicable to an organization (both global templates and org-specific rules)
   */
  async findByOrg(organizationId, { enabledOnly = false } = {}, client = null) {
    const dbClient = client || db;
    let query = `
      SELECT * FROM public.siem_detection_rules
      WHERE (organization_id IS NULL OR organization_id = $1)
    `;
    const params = [organizationId];

    if (enabledOnly) {
      query += ` AND enabled = true`;
    }

    query += ` ORDER BY organization_id NULLS LAST, created_at ASC`;
    const res = await dbClient.query(query, params);
    return res.rows;
  },

  /**
   * Updates an existing rule
   */
  async update(id, organizationId, fields = {}, client = null) {
    const dbClient = client || db;
    const setClauses = [];
    const params = [id];

    if (organizationId) {
      params.push(organizationId);
    }

    const orgParamIndex = organizationId ? `$${params.length}` : null;

    if (fields.name !== undefined) {
      params.push(fields.name);
      setClauses.push(`name = $${params.length}`);
    }
    if (fields.description !== undefined) {
      params.push(fields.description);
      setClauses.push(`description = $${params.length}`);
    }
    if (fields.enabled !== undefined) {
      params.push(Boolean(fields.enabled));
      setClauses.push(`enabled = $${params.length}`);
    }
    if (fields.severity !== undefined) {
      params.push(fields.severity);
      setClauses.push(`severity = $${params.length}`);
    }
    if (fields.rule_type !== undefined) {
      params.push(fields.rule_type);
      setClauses.push(`rule_type = $${params.length}`);
    }
    if (fields.conditions !== undefined) {
      params.push(JSON.stringify(fields.conditions));
      setClauses.push(`conditions = $${params.length}`);
    }

    if (setClauses.length === 0) {
      return this.findById(id, organizationId, dbClient);
    }

    setClauses.push(`updated_at = NOW()`);

    let query = `
      UPDATE public.siem_detection_rules
      SET ${setClauses.join(', ')}
      WHERE id = $1
    `;

    if (organizationId) {
      // Allows updating org's own rules or modifying system rules by cloning or editing
      query += ` AND (organization_id = ${orgParamIndex} OR organization_id IS NULL)`;
    }

    query += ` RETURNING *;`;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Deletes a rule
   */
  async delete(id, organizationId, client = null) {
    const dbClient = client || db;
    let query = `DELETE FROM public.siem_detection_rules WHERE id = $1`;
    const params = [id];

    if (organizationId) {
      query += ` AND organization_id = $2`;
      params.push(organizationId);
    }

    const res = await dbClient.query(query, params);
    return res.rowCount > 0;
  }
};

module.exports = SiemDetectionRule;
