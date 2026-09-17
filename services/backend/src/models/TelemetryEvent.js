const db = require('../config/db');

/**
 * TelemetryEvent Model — CRUD operations on the 'telemetry_logs' table
 */
const TelemetryEvent = {
  async create({ user_id, device_id = 'unknown', event_type, telemetry_data = {}, is_anomalous = false }) {
    const text = `
      INSERT INTO telemetry_logs (user_id, device_id, event_type, telemetry_data, is_anomalous, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      user_id,
      device_id,
      event_type,
      JSON.stringify(telemetry_data),
      is_anomalous
    ]);
    return res.rows[0];
  },

  async findByUserId(user_id, limit = 50) {
    const text = `
      SELECT * FROM telemetry_logs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await db.query(text, [user_id, limit]);
    return res.rows;
  },

  async findRecent(limit = 100) {
    const text = `
      SELECT * FROM telemetry_logs
      ORDER BY created_at DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = TelemetryEvent;
