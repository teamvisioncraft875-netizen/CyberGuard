const db = require('../config/db');

/**
 * RecommendedAction Model — CRUD operations on the 'recommended_actions' table
 */
const RecommendedAction = {
  async create({ incident_id, action_text, is_automated = false, execution_status = 'pending' }) {
    const text = `
      INSERT INTO recommended_actions (incident_id, action_text, is_automated, execution_status, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [incident_id, action_text, is_automated, execution_status]);
    return res.rows[0];
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM recommended_actions
      WHERE incident_id = $1
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  },

  async updateStatus(id, execution_status) {
    const text = `
      UPDATE recommended_actions
      SET execution_status = $2
      WHERE id = $1
      RETURNING *;
    `;
    const res = await db.query(text, [id, execution_status]);
    return res.rows[0] || null;
  }
};

module.exports = RecommendedAction;
