const db = require('../config/db');

/**
 * DetectionSignal Model — CRUD operations on the 'detection_signals' table
 */
const DetectionSignal = {
  async create({ incident_id, signal_name, signal_value, weight = 1.0 }) {
    const text = `
      INSERT INTO detection_signals (incident_id, signal_name, signal_value, weight, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      incident_id,
      signal_name,
      JSON.stringify(signal_value),
      weight
    ]);
    return res.rows[0];
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM detection_signals
      WHERE incident_id = $1
      ORDER BY weight DESC;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  }
};

module.exports = DetectionSignal;
