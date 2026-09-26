const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUUID = (val) => typeof val === 'string' && UUID_REGEX.test(val);

/**
 * Normalizes input event_type to match the Postgres telemetry_event_type enum ('process', 'network', 'api').
 */
function normalizeTelemetryEventType(rawType) {
  if (!rawType) return 'process';
  const lower = String(rawType).toLowerCase();
  if (lower.startsWith('net')) return 'network';
  if (lower.startsWith('api')) return 'api';
  return 'process';
}

/**
 * Resolves a valid devices.id UUID or falls back to null for nullable foreign key safety.
 */
async function resolveDeviceId(user_id, device_id, client = db) {
  if (!device_id) return null;
  if (isUUID(device_id)) {
    try {
      const res = await client.query('SELECT id FROM devices WHERE id = $1', [device_id]);
      if (res.rows.length > 0) return res.rows[0].id;
    } catch (_) {}
  }
  if (isUUID(user_id)) {
    try {
      const existing = await client.query(
        'SELECT id FROM devices WHERE user_id = $1 AND device_fingerprint = $2',
        [user_id, String(device_id)]
      );
      if (existing.rows.length > 0) return existing.rows[0].id;
    } catch (_) {}
  }
  return null;
}

/**
 * TelemetryEvent Model — CRUD operations on the 'telemetry_events' table
 */
const TelemetryEvent = {
  async create({
    user_id,
    device_id = null,
    event_type,
    payload,
    details,
    telemetry_data
  }, client = db) {
    const resolvedDevice = await resolveDeviceId(user_id, device_id, client);
    const normalizedType = normalizeTelemetryEventType(event_type);
    const eventPayload = payload || details || telemetry_data || {};

    const text = `
      INSERT INTO telemetry_events (user_id, device_id, event_type, payload, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await client.query(text, [
      user_id,
      resolvedDevice,
      normalizedType,
      JSON.stringify(eventPayload)
    ]);
    return res.rows[0];
  },

  async findByUserId(user_id, limit = 50) {
    const text = `
      SELECT * FROM telemetry_events
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await db.query(text, [user_id, limit]);
    return res.rows;
  },

  async findRecent(limit = 100) {
    const text = `
      SELECT * FROM telemetry_events
      ORDER BY created_at DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = TelemetryEvent;
