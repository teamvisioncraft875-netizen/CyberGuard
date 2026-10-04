const db = require('../config/db');

/**
 * Device Model — CRUD and lifecycle operations on the 'devices' table
 */
const Device = {
  async registerOrUpdate({ organization_id = null, user_id = null, device_id, device_name = 'Unknown Device', platform = 'desktop', is_trusted = true }) {
    const text = `
      INSERT INTO devices (organization_id, user_id, device_id, device_name, platform, is_trusted, last_seen, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      ON CONFLICT (device_id) DO UPDATE
      SET last_seen = NOW(), device_name = EXCLUDED.device_name
      RETURNING *;
    `;
    const res = await db.query(text, [organization_id, user_id, device_id, device_name, platform, is_trusted]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `SELECT * FROM devices WHERE id = $1;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByDeviceId(device_id) {
    const text = `SELECT * FROM devices WHERE device_id = $1 OR id::text = $1;`;
    const res = await db.query(text, [device_id]);
    return res.rows[0] || null;
  },

  async findByUserId(user_id) {
    const text = `SELECT * FROM devices WHERE user_id = $1 ORDER BY last_seen DESC;`;
    const res = await db.query(text, [user_id]);
    return res.rows;
  },

  async findByOrgId(organization_id) {
    const text = `SELECT * FROM devices WHERE organization_id = $1 ORDER BY created_at DESC;`;
    const res = await db.query(text, [organization_id]);
    return res.rows;
  },

  async updateStatus(device_id, status) {
    const text = `
      UPDATE public.devices
      SET status = $2
      WHERE device_id = $1 OR device_fingerprint = $1 OR id::text = $1
      RETURNING *;
    `;
    const res = await db.query(text, [device_id, status]);
    return res.rows[0] || null;
  },

  async deleteById(id) {
    const text = `DELETE FROM devices WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Device;
