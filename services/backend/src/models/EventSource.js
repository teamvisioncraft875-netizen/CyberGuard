const db = require('../config/db');

/**
 * EventSource Model — CRUD operations on public.event_sources
 */
const EventSource = {
  /**
   * Registers a new event source.
   */
  async create({
    organization_id,
    source_name,
    source_type,
    status = 'active',
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.event_sources (
        organization_id,
        source_name,
        source_type,
        status,
        last_seen_at,
        metadata,
        created_at
      )
      VALUES ($1, $2, $3, $4, NOW(), $5, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      source_name,
      source_type.toLowerCase(),
      status.toLowerCase(),
      JSON.stringify(metadata || {})
    ]);
    return res.rows[0];
  },

  /**
   * Finds an event source by ID within an organization.
   */
  async findById(id, organizationId, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT *
      FROM public.event_sources
      WHERE id = $1 AND organization_id = $2;
    `;
    const res = await dbClient.query(text, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Lists event sources for an organization with optional filters.
   */
  async findByOrganization(organizationId, { sourceType = null, status = null, limit = 50, offset = 0 } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['organization_id = $1'];
    const values = [organizationId];

    if (sourceType) {
      values.push(sourceType.toLowerCase());
      conditions.push(`source_type = $${values.length}`);
    }

    if (status) {
      values.push(status.toLowerCase());
      conditions.push(`status = $${values.length}`);
    }

    values.push(Math.max(1, Math.min(100, parseInt(limit, 10) || 50)));
    const limitPlaceholder = `$${values.length}`;

    values.push(Math.max(0, parseInt(offset, 10) || 0));
    const offsetPlaceholder = `$${values.length}`;

    const text = `
      SELECT *
      FROM public.event_sources
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder};
    `;

    const countText = `
      SELECT COUNT(*)::int AS total
      FROM public.event_sources
      WHERE ${conditions.join(' AND ')};
    `;

    const [rowsRes, countRes] = await Promise.all([
      dbClient.query(text, values),
      dbClient.query(countText, values.slice(0, values.length - 2))
    ]);

    return {
      sources: rowsRes.rows,
      total: countRes.rows[0]?.total || 0
    };
  },

  /**
   * Updates status and last_seen_at for an event source.
   */
  async touch(id, organizationId, status = 'active', client = null) {
    const dbClient = client || db;
    const text = `
      UPDATE public.event_sources
      SET status = $1, last_seen_at = NOW()
      WHERE id = $2 AND organization_id = $3
      RETURNING *;
    `;
    const res = await dbClient.query(text, [status, id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Deletes an event source.
   */
  async delete(id, organizationId, client = null) {
    const dbClient = client || db;
    const text = `
      DELETE FROM public.event_sources
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const res = await dbClient.query(text, [id, organizationId]);
    return res.rows[0] || null;
  }
};

module.exports = EventSource;
