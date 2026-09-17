const db = require('../config/db');

/**
 * AuditLog Model — CRUD operations on the 'audit_logs' table
 */
const AuditLog = {
  async create({ user_id, action, resource_type, resource_id = null, details = {}, ip_address = null }) {
    const text = `
      INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      user_id,
      action,
      resource_type,
      resource_id,
      JSON.stringify(details),
      ip_address
    ]);
    return res.rows[0];
  },

  async findByUserId(user_id, limit = 50) {
    const text = `
      SELECT * FROM audit_logs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await db.query(text, [user_id, limit]);
    return res.rows;
  },

  async findRecent(limit = 100) {
    const text = `
      SELECT * FROM audit_logs
      ORDER BY created_at DESC
      LIMIT $1;
    `;
    const res = await db.query(text, [limit]);
    return res.rows;
  }
};

module.exports = AuditLog;
