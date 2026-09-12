const db = require('../config/db');

/**
 * MitreMapping Model — CRUD operations on the 'mitre_mappings' table
 */
const MitreMapping = {
  async create({ incident_id, technique_id, technique_name, tactic_name = 'Initial Access', confidence_score = 0.9 }) {
    const text = `
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name, tactic_name, confidence_score, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [incident_id, technique_id, technique_name, tactic_name, confidence_score]);
    return res.rows[0];
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM mitre_mappings
      WHERE incident_id = $1;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  },

  async getTechniqueAggregates(limit = 10) {
    const text = `
      SELECT technique_id, technique_name, COUNT(*) as incident_count
      FROM mitre_mappings
      GROUP BY technique_id, technique_name
      ORDER BY incident_count DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = MitreMapping;
