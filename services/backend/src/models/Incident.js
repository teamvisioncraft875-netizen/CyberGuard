const db = require('../config/db');

/**
 * Incident Model — CRUD operations on the 'incidents' table
 */
const Incident = {
  async create({
    user_id = null,
    org_id = null,
    threat_scenario,
    risk_tier,
    risk_score,
    explanation,
    recommended_action,
    mitre_technique = null,
    signals = {}
  }) {
    const text = `
      INSERT INTO incidents (
        user_id, org_id, threat_scenario, risk_tier, risk_score,
        explanation, recommended_action, mitre_technique, signals, status, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', NOW(), NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      user_id,
      org_id,
      threat_scenario,
      risk_tier,
      risk_score,
      explanation,
      recommended_action,
      mitre_technique,
      JSON.stringify(signals)
    ]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `SELECT * FROM incidents WHERE id = $1;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findAll({ risk_level, category, status, organization_id, limit = 50, offset = 0 } = {}) {
    const conditions = [];
    const values = [];

    if (risk_level) {
      values.push(risk_level);
      conditions.push(`risk_tier = $${values.length}`);
    }
    if (category) {
      values.push(category);
      conditions.push(`threat_scenario = $${values.length}`);
    }
    if (status) {
      values.push(status);
      conditions.push(`status = $${values.length}`);
    }
    if (organization_id) {
      values.push(organization_id);
      conditions.push(`org_id = $${values.length}`);
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

  async updateStatus(id, status, resolved_by = null) {
    const text = `
      UPDATE incidents
      SET status = $2, resolved_by = $3, updated_at = NOW()
      WHERE id = $1
      RETURNING id, status, resolved_by, updated_at;
    `;
    const res = await db.query(text, [id, status, resolved_by]);
    return res.rows[0] || null;
  },

  async deleteById(id) {
    const text = `DELETE FROM incidents WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Incident;
