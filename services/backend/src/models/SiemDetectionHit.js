const db = require('../config/db');

/**
 * SiemDetectionHit Model — Records rule execution hits, linked events, and generated incidents
 */
const SiemDetectionHit = {
  /**
   * Creates a new detection hit record
   */
  async create({
    organization_id,
    rule_id = null,
    incident_id = null,
    event_ids = [],
    matched_at = new Date(),
    confidence_score = 1.0,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const query = `
      INSERT INTO public.siem_detection_hits (
        organization_id, rule_id, incident_id, event_ids, matched_at, confidence_score, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;
    const res = await dbClient.query(query, [
      organization_id,
      rule_id,
      incident_id,
      event_ids,
      matched_at,
      confidence_score,
      JSON.stringify(metadata)
    ]);
    return res.rows[0];
  },

  /**
   * Finds a detection hit by ID with joined rule and incident data
   */
  async findById(id, organizationId, client = null) {
    const dbClient = client || db;
    const query = `
      SELECT
        h.*,
        r.name AS rule_name,
        r.severity AS rule_severity,
        r.rule_type AS rule_type,
        i.threat_type AS incident_threat_type,
        i.risk_level AS incident_risk_level,
        i.risk_score AS incident_risk_score,
        i.status AS incident_status
      FROM public.siem_detection_hits h
      LEFT JOIN public.siem_detection_rules r ON h.rule_id = r.id
      LEFT JOIN public.incidents i ON h.incident_id = i.id
      WHERE h.id = $1 AND h.organization_id = $2;
    `;
    const res = await dbClient.query(query, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Finds paginated detection hits for an organization
   */
  async findByOrg(organizationId, {
    rule_id = null,
    limit = 50,
    offset = 0,
    startDate = null,
    endDate = null
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['h.organization_id = $1'];
    const params = [organizationId];

    if (rule_id) {
      params.push(rule_id);
      conditions.push(`h.rule_id = $${params.length}`);
    }

    if (startDate) {
      params.push(new Date(startDate));
      conditions.push(`h.matched_at >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      conditions.push(`h.matched_at <= $${params.length}`);
    }

    params.push(parseInt(limit, 10) || 50);
    const limitIndex = params.length;

    params.push(parseInt(offset, 10) || 0);
    const offsetIndex = params.length;

    const query = `
      SELECT
        h.*,
        r.name AS rule_name,
        r.severity AS rule_severity,
        r.rule_type AS rule_type,
        i.threat_type AS incident_threat_type,
        i.risk_level AS incident_risk_level,
        i.risk_score AS incident_risk_score,
        i.status AS incident_status
      FROM public.siem_detection_hits h
      LEFT JOIN public.siem_detection_rules r ON h.rule_id = r.id
      LEFT JOIN public.incidents i ON h.incident_id = i.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY h.matched_at DESC
      LIMIT $${limitIndex} OFFSET $${offsetIndex};
    `;

    const res = await dbClient.query(query, params);
    return res.rows;
  },

  /**
   * Counts total detection hits matching criteria
   */
  async countByOrg(organizationId, { rule_id = null, startDate = null, endDate = null } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['organization_id = $1'];
    const params = [organizationId];

    if (rule_id) {
      params.push(rule_id);
      conditions.push(`rule_id = $${params.length}`);
    }

    if (startDate) {
      params.push(new Date(startDate));
      conditions.push(`matched_at >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      conditions.push(`matched_at <= $${params.length}`);
    }

    const query = `
      SELECT COUNT(*)::int AS total
      FROM public.siem_detection_hits
      WHERE ${conditions.join(' AND ')};
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0]?.total || 0;
  }
};

module.exports = SiemDetectionHit;
