const db = require('../config/db');

/**
 * IncidentGroup Model — Groups and campaign clusters aggregating related incidents
 */
const IncidentGroup = {
  /**
   * Creates a new incident group entity.
   */
  async create({
    organization_id,
    title,
    description = null,
    group_type,
    status = 'open',
    severity = 'medium',
    confidence_score = 0.800,
    primary_incident_id = null,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.incident_groups (
        organization_id,
        title,
        description,
        group_type,
        status,
        severity,
        confidence_score,
        primary_incident_id,
        metadata,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(text, [
      organization_id,
      title,
      description,
      group_type,
      status,
      severity,
      confidence_score,
      primary_incident_id,
      typeof metadata === 'object' && metadata !== null ? JSON.stringify(metadata) : '{}'
    ]);

    return res.rows[0];
  },

  /**
   * Finds an incident group by ID.
   */
  async findById(id, client = null) {
    const dbClient = client || db;
    const text = `SELECT * FROM public.incident_groups WHERE id = $1;`;
    const res = await dbClient.query(text, [id]);
    return res.rows[0] || null;
  },

  /**
   * Lists incident groups with optional filtering and pagination.
   */
  async list({
    organization_id = null,
    status = null,
    group_type = null,
    limit = 25,
    offset = 0
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = [];
    const values = [];

    if (organization_id) {
      values.push(organization_id);
      conditions.push(`organization_id = $${values.length}`);
    }

    if (status) {
      values.push(status);
      conditions.push(`status = $${values.length}`);
    }

    if (group_type) {
      values.push(group_type);
      conditions.push(`group_type = $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    values.push(Math.max(1, Math.min(parseInt(limit, 10) || 25, 100)));
    const limitIdx = values.length;

    values.push(Math.max(0, parseInt(offset, 10) || 0));
    const offsetIdx = values.length;

    const text = `
      SELECT *
      FROM public.incident_groups
      ${whereClause}
      ORDER BY updated_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;

    const countText = `
      SELECT COUNT(*)::int AS total
      FROM public.incident_groups
      ${whereClause};
    `;

    const [rowsRes, countRes] = await Promise.all([
      dbClient.query(text, values),
      dbClient.query(countText, values.slice(0, values.length - 2))
    ]);

    return {
      groups: rowsRes.rows,
      total: countRes.rows[0]?.total || 0
    };
  },

  /**
   * Updates group status and advances updated_at.
   */
  async updateStatus(id, status, client = null) {
    const dbClient = client || db;
    const text = `
      UPDATE public.incident_groups
      SET status = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING *;
    `;
    const res = await dbClient.query(text, [status, id]);
    return res.rows[0] || null;
  },

  /**
   * Updates multiple attributes of an incident group.
   */
  async update(id, updates = {}, client = null) {
    const dbClient = client || db;
    const allowed = ['title', 'description', 'group_type', 'status', 'severity', 'confidence_score', 'primary_incident_id', 'metadata'];
    const setClauses = [];
    const values = [];

    for (const [key, val] of Object.entries(updates)) {
      if (allowed.includes(key)) {
        values.push(key === 'metadata' ? JSON.stringify(val) : val);
        setClauses.push(`${key} = $${values.length}`);
      }
    }

    if (setClauses.length === 0) return this.findById(id, dbClient);

    setClauses.push(`updated_at = NOW()`);
    values.push(id);
    const idIdx = values.length;

    const text = `
      UPDATE public.incident_groups
      SET ${setClauses.join(', ')}
      WHERE id = $${idIdx}
      RETURNING *;
    `;

    const res = await dbClient.query(text, values);
    return res.rows[0] || null;
  },

  /**
   * Deletes an incident group by ID.
   */
  async delete(id, client = null) {
    const dbClient = client || db;
    const text = `DELETE FROM public.incident_groups WHERE id = $1 RETURNING *;`;
    const res = await dbClient.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = IncidentGroup;
