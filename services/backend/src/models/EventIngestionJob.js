const db = require('../config/db');

/**
 * EventIngestionJob Model — Tracking bulk ingestion jobs and status
 */
const EventIngestionJob = {
  /**
   * Starts an event ingestion job record.
   */
  async create({
    organization_id,
    source_id = null,
    total_events = 0,
    status = 'in_progress'
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.event_ingestion_jobs (
        organization_id,
        source_id,
        total_events,
        successful_events,
        failed_events,
        started_at,
        status
      )
      VALUES ($1, $2, $3, 0, 0, NOW(), $4)
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      source_id,
      total_events,
      status
    ]);
    return res.rows[0];
  },

  /**
   * Updates an event ingestion job with outcome metrics.
   */
  async update(id, organizationId, {
    successful_events = 0,
    failed_events = 0,
    status = 'completed',
    error_details = null
  }, client = null) {
    const dbClient = client || db;
    const text = `
      UPDATE public.event_ingestion_jobs
      SET successful_events = $1,
          failed_events = $2,
          status = $3,
          completed_at = NOW(),
          error_details = $4
      WHERE id = $5 AND organization_id = $6
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      successful_events,
      failed_events,
      status,
      error_details ? JSON.stringify(error_details) : null,
      id,
      organizationId
    ]);
    return res.rows[0] || null;
  },

  /**
   * Finds an ingestion job by ID within an organization.
   */
  async findById(id, organizationId, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT *
      FROM public.event_ingestion_jobs
      WHERE id = $1 AND organization_id = $2;
    `;
    const res = await dbClient.query(text, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Lists ingestion jobs for an organization.
   */
  async findByOrganization(organizationId, { limit = 20, offset = 0 } = {}, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT *
      FROM public.event_ingestion_jobs
      WHERE organization_id = $1
      ORDER BY started_at DESC
      LIMIT $2 OFFSET $3;
    `;
    const countText = `
      SELECT COUNT(*)::int AS total
      FROM public.event_ingestion_jobs
      WHERE organization_id = $1;
    `;

    const [rowsRes, countRes] = await Promise.all([
      dbClient.query(text, [organizationId, limit, offset]),
      dbClient.query(countText, [organizationId])
    ]);

    return {
      jobs: rowsRes.rows,
      total: countRes.rows[0]?.total || 0
    };
  }
};

module.exports = EventIngestionJob;
