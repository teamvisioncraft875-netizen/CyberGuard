const db = require('../config/db');

/**
 * CopilotInvestigation Model — Persists threat hunts, autonomous investigations,
 * IOC pivots, incident correlations, and generated investigation graphs.
 */
const CopilotInvestigation = {
  VALID_TYPES: ['hunt', 'ioc', 'incident', 'alert', 'correlate', 'autonomous', 'report'],

  /**
   * Persists a new investigation record.
   */
  async create({
    session_id = null,
    organization_id,
    investigation_type,
    title,
    target_type = null,
    target_id = null,
    findings = [],
    evidence = [],
    recommendations = [],
    graph = {},
    metadata = {},
    severity = 'medium',
    confidence = 0.90,
    created_by = null
  }, client = null) {
    if (!organization_id) throw new Error('CopilotInvestigation Error: organization_id is required');
    if (!investigation_type) throw new Error('CopilotInvestigation Error: investigation_type is required');
    if (!title) throw new Error('CopilotInvestigation Error: title is required');

    const cleanType = investigation_type.toLowerCase().trim();
    const dbClient = client || db;

    const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    const validSessionId = session_id && UUID_REGEX.test(session_id) ? session_id : null;
    const validCreatedBy = created_by && UUID_REGEX.test(created_by) ? created_by : null;

    const query = `
      INSERT INTO public.copilot_investigations (
        session_id,
        organization_id,
        investigation_type,
        title,
        target_type,
        target_id,
        findings,
        evidence,
        recommendations,
        graph,
        metadata,
        severity,
        confidence,
        created_by,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      validSessionId,
      organization_id,
      cleanType,
      title,
      target_type,
      target_id ? String(target_id) : null,
      JSON.stringify(findings || []),
      JSON.stringify(evidence || []),
      JSON.stringify(recommendations || []),
      JSON.stringify(graph || {}),
      JSON.stringify(metadata || {}),
      severity || 'medium',
      confidence || 0.90,
      validCreatedBy
    ]);

    return res.rows[0];
  },

  /**
   * Finds an investigation by ID scoped to organization.
   */
  async findById(id, organization_id, client = null) {
    if (!id || !organization_id) return null;
    const dbClient = client || db;
    const res = await dbClient.query(
      `SELECT * FROM public.copilot_investigations WHERE id = $1 AND organization_id = $2;`,
      [id, organization_id]
    );
    return res.rows[0] || null;
  },

  /**
   * Retrieves all investigations for a given session.
   */
  async findBySession(session_id, organization_id, client = null) {
    if (!session_id || !organization_id) return [];
    const dbClient = client || db;
    const res = await dbClient.query(
      `SELECT * FROM public.copilot_investigations
       WHERE session_id = $1 AND organization_id = $2
       ORDER BY created_at DESC;`,
      [session_id, organization_id]
    );
    return res.rows;
  },

  /**
   * Queries investigations with flexible filters (by type, time range, etc.).
   */
  async findMany({
    organization_id,
    session_id = null,
    investigation_type = null,
    timeRangeDays = null,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('CopilotInvestigation Error: organization_id is required');
    const dbClient = client || db;

    const conditions = ['organization_id = $1'];
    const params = [organization_id];

    if (session_id) {
      params.push(session_id);
      conditions.push(`session_id = $${params.length}`);
    }

    if (investigation_type) {
      params.push(investigation_type.toLowerCase().trim());
      conditions.push(`investigation_type = $${params.length}`);
    }

    if (timeRangeDays) {
      params.push(timeRangeDays);
      conditions.push(`created_at >= NOW() - ($${params.length} || ' days')::interval`);
    }

    params.push(limit);
    const limitIdx = params.length;
    params.push(offset);
    const offsetIdx = params.length;

    const query = `
      SELECT * FROM public.copilot_investigations
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;

    const res = await dbClient.query(query, params);
    return res.rows;
  }
};

module.exports = CopilotInvestigation;
