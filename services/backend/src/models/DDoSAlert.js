const db = require('../config/db');

/**
 * DDoSAlert Model — CRUD operations on the 'ddos_metrics' table.
 */
const DDoSAlert = {
  /**
   * Records a DDoS metric or alert entry.
   */
  async create({
    organization_id = null,
    metric_type,
    source_ip,
    endpoint = null,
    count = 1,
    window_start = null,
    window_end = null,
    threshold_exceeded = false,
    metadata = {}
  }, client = db) {
    const text = `
      INSERT INTO public.ddos_metrics (
        organization_id,
        metric_type,
        source_ip,
        endpoint,
        count,
        window_start,
        window_end,
        threshold_exceeded,
        metadata,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, COALESCE($6, NOW() - INTERVAL '5 minutes'), COALESCE($7, NOW()), $8, $9, NOW())
      RETURNING *;
    `;
    const res = await client.query(text, [
      organization_id,
      metric_type,
      source_ip,
      endpoint,
      count,
      window_start,
      window_end,
      Boolean(threshold_exceeded),
      typeof metadata === 'string' ? metadata : JSON.stringify(metadata || {})
    ]);
    return res.rows[0];
  },

  /**
   * Finds metrics by organization with optional filtering.
   */
  async findByOrg(organization_id, { metric_type = null, threshold_exceeded = null, limit = 50, offset = 0 } = {}) {
    const whereClauses = ['organization_id = $1'];
    const params = [organization_id];

    if (metric_type) {
      params.push(metric_type);
      whereClauses.push(`metric_type = $${params.length}`);
    }

    if (threshold_exceeded !== null && threshold_exceeded !== undefined) {
      params.push(Boolean(threshold_exceeded));
      whereClauses.push(`threshold_exceeded = $${params.length}`);
    }

    const whereSql = whereClauses.join(' AND ');
    params.push(limit);
    const limitIdx = params.length;
    params.push(offset);
    const offsetIdx = params.length;

    const text = `
      SELECT * FROM public.ddos_metrics
      WHERE ${whereSql}
      ORDER BY created_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;
    const res = await db.query(text, params);
    return res.rows;
  },

  /**
   * Finds recent metrics for a specific source IP.
   */
  async findRecentByIp(source_ip, limit = 20) {
    const text = `
      SELECT * FROM public.ddos_metrics
      WHERE source_ip = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await db.query(text, [source_ip, limit]);
    return res.rows;
  }
};

module.exports = DDoSAlert;
