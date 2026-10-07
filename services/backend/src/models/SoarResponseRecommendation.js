const db = require('../config/db');

/**
 * SoarResponseRecommendation Model — Automated response recommendations for security alerts,
 * cases, and IOCs with confidence scores and rationale.
 */
class SoarResponseRecommendation {
  static async create({
    organization_id,
    alert_id = null,
    case_id = null,
    ioc_id = null,
    action_type,
    recommended_action,
    action_payload = {},
    confidence_score = 50.0,
    risk_score = 50,
    mitre_techniques = [],
    rationale = null,
    status = 'pending',
    applied_by = null,
    applied_at = null,
    execution_id = null
  }, client = null) {
    const dbClient = client || db;

    if (!organization_id) throw new Error('SoarResponseRecommendation.create requires organization_id');
    if (!action_type || !recommended_action) {
      throw new Error('SoarResponseRecommendation.create requires action_type and recommended_action');
    }

    const query = `
      INSERT INTO public.soar_response_recommendations (
        organization_id, alert_id, case_id, ioc_id,
        action_type, recommended_action, action_payload,
        confidence_score, risk_score, mitre_techniques, rationale,
        status, applied_by, applied_at, execution_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *;
    `;
    const values = [
      organization_id,
      alert_id,
      case_id,
      ioc_id,
      action_type,
      recommended_action,
      JSON.stringify(action_payload || {}),
      Number(confidence_score),
      Number(risk_score),
      JSON.stringify(mitre_techniques || []),
      rationale,
      status,
      applied_by,
      applied_at,
      execution_id
    ];

    const { rows } = await dbClient.query(query, values);
    return rows[0];
  }

  static async findById(id, organization_id, client = null) {
    const dbClient = client || db;
    let query = 'SELECT * FROM public.soar_response_recommendations WHERE id = $1';
    const params = [id];

    if (organization_id) {
      query += ' AND organization_id = $2';
      params.push(organization_id);
    }

    const { rows } = await dbClient.query(query, params);
    return rows[0] || null;
  }

  static async findMany(filters = {}, client = null) {
    const dbClient = client || db;
    const {
      organization_id,
      alert_id,
      case_id,
      ioc_id,
      status,
      action_type,
      min_confidence,
      limit = 50,
      offset = 0
    } = filters;

    let query = 'SELECT * FROM public.soar_response_recommendations WHERE 1=1';
    const params = [];
    let pIdx = 1;

    if (organization_id) {
      query += ` AND organization_id = $${pIdx++}`;
      params.push(organization_id);
    }
    if (alert_id) {
      query += ` AND alert_id = $${pIdx++}`;
      params.push(alert_id);
    }
    if (case_id) {
      query += ` AND case_id = $${pIdx++}`;
      params.push(case_id);
    }
    if (ioc_id) {
      query += ` AND ioc_id = $${pIdx++}`;
      params.push(ioc_id);
    }
    if (status) {
      query += ` AND status = $${pIdx++}`;
      params.push(status);
    }
    if (action_type) {
      query += ` AND action_type = $${pIdx++}`;
      params.push(action_type);
    }
    if (min_confidence !== undefined && min_confidence !== null) {
      query += ` AND confidence_score >= $${pIdx++}`;
      params.push(Number(min_confidence));
    }

    query += ' ORDER BY confidence_score DESC, created_at DESC';

    if (limit) {
      query += ` LIMIT $${pIdx++}`;
      params.push(limit);
    }
    if (offset) {
      query += ` OFFSET $${pIdx++}`;
      params.push(offset);
    }

    const { rows } = await dbClient.query(query, params);
    return rows;
  }

  static async updateStatus(id, organization_id, updates = {}, client = null) {
    const dbClient = client || db;
    const {
      status,
      applied_by = null,
      applied_at = null,
      dismissed_by = null,
      dismissed_reason = null,
      dismissed_at = null,
      execution_id = null
    } = updates;

    const query = `
      UPDATE public.soar_response_recommendations
      SET
        status = COALESCE($3, status),
        applied_by = COALESCE($4, applied_by),
        applied_at = COALESCE($5, applied_at),
        dismissed_by = COALESCE($6, dismissed_by),
        dismissed_reason = COALESCE($7, dismissed_reason),
        dismissed_at = COALESCE($8, dismissed_at),
        execution_id = COALESCE($9, execution_id),
        updated_at = NOW()
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const values = [
      id,
      organization_id,
      status,
      applied_by,
      applied_at,
      dismissed_by,
      dismissed_reason,
      dismissed_at,
      execution_id
    ];

    const { rows } = await dbClient.query(query, values);
    return rows[0] || null;
  }

  static async delete(id, organization_id, client = null) {
    const dbClient = client || db;
    const query = `
      DELETE FROM public.soar_response_recommendations
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const { rows } = await dbClient.query(query, [id, organization_id]);
    return rows[0] || null;
  }
}

module.exports = SoarResponseRecommendation;
