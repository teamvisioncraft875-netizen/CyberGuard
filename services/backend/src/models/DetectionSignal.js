const db = require('../config/db');

/**
 * DetectionSignal Model — CRUD operations on the 'detection_signals' table
 */
const DetectionSignal = {
  async create({ incident_id, signal_name, signal_value, weight = null }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO detection_signals (incident_id, signal_name, signal_value, weight)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      incident_id,
      signal_name,
      signal_value !== undefined && signal_value !== null ? String(signal_value) : null,
      weight
    ]);
    return res.rows[0];
  },

  async createMany(signals = [], client = null) {
    if (!signals || signals.length === 0) return [];
    const dbClient = client || db;
    const inserted = [];
    for (const signal of signals) {
      const res = await DetectionSignal.create(signal, dbClient);
      inserted.push(res);
    }
    return inserted;
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
