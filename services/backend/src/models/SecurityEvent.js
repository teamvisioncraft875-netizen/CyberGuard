const db = require('../config/db');

/**
 * SecurityEvent Model — High-throughput event storage and search operations
 */
const SecurityEvent = {
  /**
   * Persists a single security event.
   */
  async create({
    organization_id,
    source_id = null,
    event_timestamp,
    source_type,
    event_type,
    severity = 'info',
    device_id = null,
    user_id = null,
    raw_event,
    normalized_event
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.security_events (
        organization_id,
        source_id,
        event_timestamp,
        source_type,
        event_type,
        severity,
        device_id,
        user_id,
        raw_event,
        normalized_event,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      source_id,
      event_timestamp || new Date(),
      source_type,
      event_type,
      severity.toLowerCase(),
      device_id,
      user_id,
      typeof raw_event === 'string' ? raw_event : JSON.stringify(raw_event || {}),
      typeof normalized_event === 'string' ? normalized_event : JSON.stringify(normalized_event || {})
    ]);
    return res.rows[0];
  },

  /**
   * High-Performance Multi-Row Batch Insert (prevents N+1 database round trips).
   * Automatically chunks large arrays into batches (max 500 records per statement)
   * to respect PostgreSQL query parameter limits.
   */
  async createMany(events, client = null) {
    if (!Array.isArray(events) || events.length === 0) {
      return [];
    }

    const dbClient = client || db;
    const CHUNK_SIZE = 500;
    const insertedRecords = [];

    for (let i = 0; i < events.length; i += CHUNK_SIZE) {
      const chunk = events.slice(i, i + CHUNK_SIZE);
      const values = [];
      const rowPlaceholders = [];

      chunk.forEach((ev, idx) => {
        const offset = idx * 10;
        rowPlaceholders.push(`(
          $${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5},
          $${offset + 6}, $${offset + 7}, $${offset + 8}, $${offset + 9}, $${offset + 10}, NOW()
        )`);

        values.push(
          ev.organization_id,
          ev.source_id || null,
          ev.event_timestamp || new Date(),
          ev.source_type,
          ev.event_type,
          (ev.severity || 'info').toLowerCase(),
          ev.device_id || null,
          ev.user_id || null,
          typeof ev.raw_event === 'string' ? ev.raw_event : JSON.stringify(ev.raw_event || {}),
          typeof ev.normalized_event === 'string' ? ev.normalized_event : JSON.stringify(ev.normalized_event || {})
        );
      });

      const sql = `
        INSERT INTO public.security_events (
          organization_id,
          source_id,
          event_timestamp,
          source_type,
          event_type,
          severity,
          device_id,
          user_id,
          raw_event,
          normalized_event,
          created_at
        )
        VALUES ${rowPlaceholders.join(', ')}
        RETURNING *;
      `;

      const res = await dbClient.query(sql, values);
      insertedRecords.push(...res.rows);
    }

    return insertedRecords;
  },

  /**
   * Finds a single security event by ID within an organization.
   */
  async findById(id, organizationId, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT *
      FROM public.security_events
      WHERE id = $1 AND organization_id = $2;
    `;
    const res = await dbClient.query(text, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * SOC Filtered Event Search with Multi-Factor Index Utilization & Pagination.
   */
  async search(organizationId, {
    severity = null,
    sourceType = null,
    eventType = null,
    deviceId = null,
    userId = null,
    startTime = null,
    endTime = null,
    q = null,
    limit = 20,
    page = 1
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['organization_id = $1'];
    const values = [organizationId];

    if (severity) {
      values.push(severity.toLowerCase());
      conditions.push(`severity = $${values.length}`);
    }

    if (sourceType) {
      values.push(sourceType.toLowerCase());
      conditions.push(`source_type = $${values.length}`);
    }

    if (eventType) {
      values.push(eventType);
      conditions.push(`event_type = $${values.length}`);
    }

    if (deviceId) {
      values.push(deviceId);
      conditions.push(`device_id = $${values.length}`);
    }

    if (userId) {
      values.push(userId);
      conditions.push(`user_id = $${values.length}`);
    }

    if (startTime) {
      values.push(new Date(startTime));
      conditions.push(`event_timestamp >= $${values.length}`);
    }

    if (endTime) {
      values.push(new Date(endTime));
      conditions.push(`event_timestamp <= $${values.length}`);
    }

    if (q && typeof q === 'string' && q.trim()) {
      values.push(`%${q.trim()}%`);
      conditions.push(`(
        event_type ILIKE $${values.length} OR
        normalized_event::text ILIKE $${values.length} OR
        raw_event::text ILIKE $${values.length}
      )`);
    }

    const parsedLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
    const parsedPage = Math.max(1, parseInt(page, 10) || 1);
    const offset = (parsedPage - 1) * parsedLimit;

    const countSql = `
      SELECT COUNT(*)::int AS total
      FROM public.security_events
      WHERE ${conditions.join(' AND ')};
    `;

    values.push(parsedLimit);
    const limitPlaceholder = `$${values.length}`;
    values.push(offset);
    const offsetPlaceholder = `$${values.length}`;

    const querySql = `
      SELECT id, organization_id, source_id, event_timestamp, source_type,
             event_type, severity, device_id, user_id, normalized_event, created_at
      FROM public.security_events
      WHERE ${conditions.join(' AND ')}
      ORDER BY event_timestamp DESC
      LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder};
    `;

    const [countRes, queryRes] = await Promise.all([
      dbClient.query(countSql, values.slice(0, values.length - 2)),
      dbClient.query(querySql, values)
    ]);

    const total = countRes.rows[0]?.total || 0;
    const totalPages = Math.ceil(total / parsedLimit);

    return {
      events: queryRes.rows,
      pagination: {
        total,
        page: parsedPage,
        limit: parsedLimit,
        totalPages,
        hasMore: parsedPage < totalPages
      }
    };
  },

  /**
   * Aggregates event metrics for SOC intelligence dashboards.
   */
  async getStats(organizationId, client = null) {
    const dbClient = client || db;

    const severitySql = `
      SELECT severity, COUNT(*)::int AS count
      FROM public.security_events
      WHERE organization_id = $1
      GROUP BY severity;
    `;

    const sourceSql = `
      SELECT source_type, COUNT(*)::int AS count
      FROM public.security_events
      WHERE organization_id = $1
      GROUP BY source_type;
    `;

    const recentSql = `
      SELECT COUNT(*)::int AS count_24h
      FROM public.security_events
      WHERE organization_id = $1
        AND event_timestamp >= NOW() - INTERVAL '24 hours';
    `;

    const [sevRes, srcRes, recentRes] = await Promise.all([
      dbClient.query(severitySql, [organizationId]),
      dbClient.query(sourceSql, [organizationId]),
      dbClient.query(recentSql, [organizationId])
    ]);

    const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    sevRes.rows.forEach(r => {
      bySeverity[r.severity] = r.count;
    });

    const bySource = {};
    srcRes.rows.forEach(r => {
      bySource[r.source_type] = r.count;
    });

    return {
      total_24h: recentRes.rows[0]?.count_24h || 0,
      by_severity: bySeverity,
      by_source: bySource
    };
  }
};

module.exports = SecurityEvent;
