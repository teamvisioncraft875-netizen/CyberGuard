const db = require('../config/db');

/**
 * Device Model — CRUD operations on the 'devices' table
 */
const Device = {
  async registerOrUpdate({ user_id, device_id, device_name = 'Unknown Device', platform = 'desktop', is_trusted = true }) {
    const text = `
      INSERT INTO devices (user_id, device_id, device_name, platform, is_trusted, last_seen_at, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
      ON CONFLICT (device_id) DO UPDATE
      SET last_seen_at = NOW(), device_name = EXCLUDED.device_name
      RETURNING *;
    `;
    const res = await db.query(text, [user_id, device_id, device_name, platform, is_trusted]);
    return res.rows[0];
  },

  async findByDeviceId(device_id) {
    const text = `SELECT * FROM devices WHERE device_id = $1;`;
    const res = await db.query(text, [device_id]);
    return res.rows[0] || null;
  },

  async findByUserId(user_id) {
    const text = `SELECT * FROM devices WHERE user_id = $1 ORDER BY last_seen_at DESC;`;
    const res = await db.query(text, [user_id]);
    return res.rows;
  },

  async deleteById(id) {
    const text = `DELETE FROM devices WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Device;
