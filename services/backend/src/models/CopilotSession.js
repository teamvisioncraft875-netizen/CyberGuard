const db = require('../config/db');

/**
 * CopilotSession Model — Manages multi-turn investigation sessions scoped to tenant.
 */
const CopilotSession = {
  async create({
    organization_id,
    created_by = null,
    title = 'New Investigation Session',
    entity_type = null,
    entity_id = null,
    status = 'active'
  }, client = null) {
    if (!organization_id) throw new Error('CopilotSession Error: organization_id is required');

    const dbClient = client || db;
    const query = `
      INSERT INTO public.copilot_sessions (
        organization_id, created_by, title, entity_type, entity_id, status, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(query, [
      organization_id,
      created_by,
      title || 'New Investigation Session',
      entity_type,
      entity_id ? String(entity_id) : null,
      status || 'active'
    ]);
    return res.rows[0];
  },

  async findById(id, organization_id, client = null) {
    if (!id || !organization_id) return null;
    const dbClient = client || db;
    const query = `
      SELECT s.*, u.email as created_by_email
      FROM public.copilot_sessions s
      LEFT JOIN public.users u ON s.created_by = u.id
      WHERE s.id = $1 AND s.organization_id = $2;
    `;
    const res = await dbClient.query(query, [id, organization_id]);
    return res.rows[0] || null;
  },

  async findMany({
    organization_id,
    created_by = null,
    status = null,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('CopilotSession Error: organization_id is required');
    const dbClient = client || db;

    const conditions = ['s.organization_id = $1'];
    const params = [organization_id];

    if (created_by) {
      params.push(created_by);
      conditions.push(`s.created_by = $${params.length}`);
    }

    if (status) {
      params.push(status);
      conditions.push(`s.status = $${params.length}`);
    }

    params.push(limit);
    const limitIdx = params.length;
    params.push(offset);
    const offsetIdx = params.length;

    const query = `
      SELECT s.*, u.email as created_by_email
      FROM public.copilot_sessions s
      LEFT JOIN public.users u ON s.created_by = u.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY s.updated_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;
    const res = await dbClient.query(query, params);
    return res.rows;
  },

  async delete(id, organization_id, client = null) {
    if (!id || !organization_id) return false;
    const dbClient = client || db;
    const res = await dbClient.query(
      `DELETE FROM public.copilot_sessions WHERE id = $1 AND organization_id = $2 RETURNING id;`,
      [id, organization_id]
    );
    return (res.rowCount || 0) > 0;
  },

  async update(id, organization_id, fields = {}, client = null) {
    if (!id || !organization_id) return null;
    const dbClient = client || db;

    const setClauses = [];
    const params = [id, organization_id];

    if (fields.title !== undefined) {
      params.push(fields.title);
      setClauses.push(`title = $${params.length}`);
    }
    if (fields.status !== undefined) {
      params.push(fields.status);
      setClauses.push(`status = $${params.length}`);
    }

    if (setClauses.length === 0) return this.findById(id, organization_id, dbClient);

    setClauses.push('updated_at = NOW()');

    const query = `
      UPDATE public.copilot_sessions
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  }
};

module.exports = CopilotSession;
