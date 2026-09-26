const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUUID = (val) => typeof val === 'string' && UUID_REGEX.test(val);

/**
 * Resolves a valid devices.id UUID or registers a device row for foreign-key safety.
 * Falls back to null if device resolution fails or device_id is omitted.
 */
async function resolveDeviceId(user_id, device_id, client = db) {
  if (!device_id) return null;
  if (isUUID(device_id)) {
    try {
      const res = await client.query('SELECT id FROM devices WHERE id = $1', [device_id]);
      if (res.rows.length > 0) return res.rows[0].id;
    } catch (_) {}
  }
  // Try resolving or creating device row by fingerprint if user_id is a valid UUID
  if (isUUID(user_id)) {
    try {
      const existing = await client.query(
        'SELECT id FROM devices WHERE user_id = $1 AND device_fingerprint = $2',
        [user_id, String(device_id)]
      );
      if (existing.rows.length > 0) return existing.rows[0].id;

      const inserted = await client.query(
        'INSERT INTO devices (user_id, device_name, device_fingerprint, is_trusted) VALUES ($1, $2, $3, false) RETURNING id',
        [user_id, `Device ${String(device_id).slice(0, 16)}`, String(device_id)]
      );
      return inserted.rows[0].id;
    } catch (_) {
      return null;
    }
  }
  return null;
}

/**
 * LoginEvent Model — CRUD operations on the 'login_events' table
 */
const LoginEvent = {
  async create({
    user_id,
    device_id,
    device_fingerprint,
    ip_address = null,
    location = null,
    success,
    failed_attempt_count,
    failed_attempts
  }, client = db) {
    const count = failed_attempt_count !== undefined 
      ? Number(failed_attempt_count) 
      : (failed_attempts !== undefined ? Number(failed_attempts) : 0);
    const isSuccess = success !== undefined ? Boolean(success) : count === 0;
    const resolvedDevice = await resolveDeviceId(user_id, device_id || device_fingerprint, client);

    const text = `
      INSERT INTO login_events (user_id, device_id, ip_address, location, success, failed_attempt_count, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *;
    `;
    const res = await client.query(text, [
      user_id,
      resolvedDevice,
      ip_address,
      location,
      isSuccess,
      count
    ]);
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
      WHERE success = false OR failed_attempt_count > 0
      ORDER BY created_at DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = LoginEvent;
