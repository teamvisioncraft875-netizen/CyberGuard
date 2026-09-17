const db = require('../config/db');

/**
 * LoginEvent Model — CRUD operations on the 'login_events' table
 */
const LoginEvent = {
  async create({ user_id, device_id, location, failed_attempts = 0, is_anomalous = false, risk_tier = 'Safe' }) {
    const text = `
      INSERT INTO login_events (user_id, device_id, location, failed_attempts, is_anomalous, risk_tier, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [user_id, device_id, location, failed_attempts, is_anomalous, risk_tier]);
    return res.rows[0];
  },

  async findByUserId(user_id, limit = 20) {
    const text = `
      SELECT * FROM login_events
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await db.query(text, [user_id, limit]);
    return res.rows;
  },

  async findRecentAnomalies(limit = 50) {
    const text = `
      SELECT * FROM login_events
      WHERE is_anomalous = true
      ORDER BY created_at DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = LoginEvent;
