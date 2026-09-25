const db = require('../config/db');

/**
 * Incident Model — CRUD operations on the 'incidents' table
 */
const Incident = {
  async create({
    user_id = null,
    organization_id = null,
    threat_type = null,
    source_type = 'email',
    risk_level = null,
    risk_score = 0,
    explanation = '',
    status = 'open',
    mitre_technique = null
  }, client = null) {
    const dbClient = client || db;
    const resolvedThreatType = (threat_type || 'phishing').toLowerCase();
    const resolvedRiskLevel = (risk_level || 'high').toLowerCase();
    const validSourceTypes = ['email', 'sms', 'url', 'image', 'audio', 'video', 'login', 'system'];
    const resolvedSourceType = validSourceTypes.includes(source_type?.toLowerCase()) ? source_type.toLowerCase() : 'email';

    const text = `
      INSERT INTO incidents (
        user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      user_id,
      organization_id,
      resolvedThreatType,
      resolvedSourceType,
      resolvedRiskLevel,
      risk_score,
      explanation,
      status
    ]);

    const created = res.rows[0];
    if (mitre_technique && created?.id) {
      await dbClient.query(
        `INSERT INTO mitre_mappings (incident_id, technique_id, technique_name) VALUES ($1, $2, $3)`,
        [created.id, mitre_technique.id || mitre_technique.technique_id || 'T1566', mitre_technique.name || mitre_technique.technique_name || 'Phishing']
      );
    }

    return created;
  },

  async findById(id) {
    const text = `SELECT * FROM incidents WHERE id = $1;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findAll({ user_id = null, organization_id = null, risk_level, category, status, limit = 50, offset = 0 } = {}) {
    const conditions = [];
    const values = [];

    // Explicit tenant / user isolation filters
    if (user_id) {
      values.push(user_id);
      conditions.push(`user_id = $${values.length}`);
    }
    if (organization_id) {
      values.push(organization_id);
      conditions.push(`organization_id = $${values.length}`);
    }

    if (risk_level) {
      values.push(risk_level.toLowerCase());
      conditions.push(`risk_level = $${values.length}`);
    }
    if (category) {
      values.push(category.toLowerCase());
      conditions.push(`threat_type = $${values.length}`);
    }
    if (status) {
      values.push(status.toLowerCase());
      conditions.push(`status = $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    values.push(limit, offset);
    const text = `
      SELECT * FROM incidents
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${values.length - 1} OFFSET $${values.length};
    `;

    const res = await db.query(text, values);
    return res.rows;
  },

  async updateStatus(id, status, resolved_by = null, organization_id = null) {
    const conditions = ['id = $1'];
    const values = [id, status.toLowerCase(), resolved_by];

    // Explicit organization scope restriction for admin updates
    if (organization_id) {
      values.push(organization_id);
      conditions.push(`organization_id = $${values.length}`);
    }

    const text = `
      UPDATE incidents
      SET status = $2::incident_status, resolved_by = $3, resolved_at = CASE WHEN $2::text = 'resolved' THEN NOW() ELSE resolved_at END
      WHERE ${conditions.join(' AND ')}
      RETURNING id, status, resolved_by, resolved_at;
    `;
    const res = await db.query(text, values);
    return res.rows[0] || null;
  },

  async deleteById(id) {
    const text = `DELETE FROM incidents WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Incident;
