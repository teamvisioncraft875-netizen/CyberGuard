const db = require('../config/db');

/**
 * SiemAlert Model — Manages SOC alerts lifecycle, queue ordering, and investigation state
 */
const SiemAlert = {
  VALID_STATUSES: ['new', 'investigating', 'contained', 'resolved', 'false_positive'],
  VALID_SEVERITIES: ['critical', 'high', 'medium', 'low'],

  /**
   * Creates a new SIEM alert
   */
  async create({
    organization_id,
    hit_id = null,
    incident_id = null,
    rule_id = null,
    title,
    severity = 'medium',
    status = 'new',
    assigned_analyst = null,
    notes = '',
    resolution = '',
    mitre_technique = null,
    source_type = 'siem',
    rule_code = null,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const query = `
      INSERT INTO public.siem_alerts (
        organization_id, hit_id, incident_id, rule_id, title, severity, status,
        assigned_analyst, notes, resolution, mitre_technique, source_type, rule_code, metadata,
        created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(query, [
      organization_id,
      hit_id,
      incident_id,
      rule_id,
      title,
      severity,
      status,
      assigned_analyst,
      notes,
      resolution,
      mitre_technique,
      source_type,
      rule_code,
      JSON.stringify(metadata)
    ]);
    return res.rows[0];
  },

  /**
   * Finds an alert by ID with joined analyst and incident details
   */
  async findById(id, organizationId, client = null) {
    const dbClient = client || db;
    const query = `
      SELECT
        a.*,
        u.email AS analyst_email,
        r.name AS rule_name,
        r.description AS rule_description,
        i.threat_type AS incident_threat_type,
        i.risk_score AS incident_risk_score,
        i.status AS incident_status
      FROM public.siem_alerts a
      LEFT JOIN public.users u ON a.assigned_analyst = u.id
      LEFT JOIN public.siem_detection_rules r ON a.rule_id = r.id
      LEFT JOIN public.incidents i ON a.incident_id = i.id
      WHERE a.id = $1 AND a.organization_id = $2;
    `;
    const res = await dbClient.query(query, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Finds paginated alerts for an organization
   */
  async findByOrg(organizationId, {
    status = null,
    severity = null,
    assigned_analyst = null,
    limit = 50,
    offset = 0,
    startDate = null,
    endDate = null
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['a.organization_id = $1'];
    const params = [organizationId];

    if (status) {
      if (Array.isArray(status)) {
        params.push(status);
        conditions.push(`a.status = ANY($${params.length})`);
      } else {
        params.push(status);
        conditions.push(`a.status = $${params.length}`);
      }
    }

    if (severity) {
      params.push(severity);
      conditions.push(`a.severity = $${params.length}`);
    }

    if (assigned_analyst) {
      params.push(assigned_analyst);
      conditions.push(`a.assigned_analyst = $${params.length}`);
    }

    if (startDate) {
      params.push(new Date(startDate));
      conditions.push(`a.created_at >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      conditions.push(`a.created_at <= $${params.length}`);
    }

    params.push(parseInt(limit, 10) || 50);
    const limitIndex = params.length;

    params.push(parseInt(offset, 10) || 0);
    const offsetIndex = params.length;

    const query = `
      SELECT
        a.*,
        u.email AS analyst_email,
        r.name AS rule_name
      FROM public.siem_alerts a
      LEFT JOIN public.users u ON a.assigned_analyst = u.id
      LEFT JOIN public.siem_detection_rules r ON a.rule_id = r.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY a.created_at DESC
      LIMIT $${limitIndex} OFFSET $${offsetIndex};
    `;

    const res = await dbClient.query(query, params);
    return res.rows;
  },

  /**
   * Counts total alerts matching criteria
   */
  async countByOrg(organizationId, {
    status = null,
    severity = null,
    assigned_analyst = null,
    startDate = null,
    endDate = null
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['organization_id = $1'];
    const params = [organizationId];

    if (status) {
      if (Array.isArray(status)) {
        params.push(status);
        conditions.push(`status = ANY($${params.length})`);
      } else {
        params.push(status);
        conditions.push(`status = $${params.length}`);
      }
    }

    if (severity) {
      params.push(severity);
      conditions.push(`severity = $${params.length}`);
    }

    if (assigned_analyst) {
      params.push(assigned_analyst);
      conditions.push(`assigned_analyst = $${params.length}`);
    }

    if (startDate) {
      params.push(new Date(startDate));
      conditions.push(`created_at >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      conditions.push(`created_at <= $${params.length}`);
    }

    const query = `
      SELECT COUNT(*)::int AS total
      FROM public.siem_alerts
      WHERE ${conditions.join(' AND ')};
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0]?.total || 0;
  },

  /**
   * Updates an alert with lifecycle transitions and timestamps
   */
  async update(id, organizationId, fields = {}, client = null) {
    const dbClient = client || db;
    const setClauses = [];
    const params = [id, organizationId];

    if (fields.status !== undefined) {
      params.push(fields.status);
      setClauses.push(`status = $${params.length}`);

      if (fields.status === 'investigating') {
        setClauses.push(`investigating_at = COALESCE(investigating_at, NOW())`);
      } else if (fields.status === 'contained') {
        setClauses.push(`contained_at = COALESCE(contained_at, NOW())`);
      } else if (fields.status === 'resolved' || fields.status === 'false_positive') {
        setClauses.push(`resolved_at = COALESCE(resolved_at, NOW())`);
      }
    }

    if (fields.assigned_analyst !== undefined) {
      params.push(fields.assigned_analyst);
      setClauses.push(`assigned_analyst = $${params.length}`);
    }

    if (fields.notes !== undefined) {
      params.push(fields.notes);
      setClauses.push(`notes = $${params.length}`);
    }

    if (fields.resolution !== undefined) {
      params.push(fields.resolution);
      setClauses.push(`resolution = $${params.length}`);
    }

    if (fields.severity !== undefined) {
      params.push(fields.severity);
      setClauses.push(`severity = $${params.length}`);
    }

    if (setClauses.length === 0) {
      return this.findById(id, organizationId, dbClient);
    }

    setClauses.push(`updated_at = NOW()`);

    const query = `
      UPDATE public.siem_alerts
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Gets analyst queue ordered by severity (critical > high > medium > low), then newest first
   */
  async getQueue(organizationId, {
    status = ['new', 'investigating'],
    severity = null,
    limit = 50,
    offset = 0
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['a.organization_id = $1'];
    const params = [organizationId];

    if (status) {
      if (Array.isArray(status) && status.length > 0) {
        params.push(status);
        conditions.push(`a.status = ANY($${params.length})`);
      } else if (typeof status === 'string') {
        params.push(status);
        conditions.push(`a.status = $${params.length}`);
      }
    }

    if (severity) {
      params.push(severity);
      conditions.push(`a.severity = $${params.length}`);
    }

    params.push(parseInt(limit, 10) || 50);
    const limitIndex = params.length;

    params.push(parseInt(offset, 10) || 0);
    const offsetIndex = params.length;

    const query = `
      SELECT
        a.*,
        u.email AS analyst_email,
        r.name AS rule_name
      FROM public.siem_alerts a
      LEFT JOIN public.users u ON a.assigned_analyst = u.id
      LEFT JOIN public.siem_detection_rules r ON a.rule_id = r.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY
        CASE a.severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END ASC,
        a.created_at DESC
      LIMIT $${limitIndex} OFFSET $${offsetIndex};
    `;

    const res = await dbClient.query(query, params);
    return res.rows;
  }
};

module.exports = SiemAlert;
