const db = require('../config/db');

/**
 * GuardianLink Model — CRUD operations on the 'guardian_links' table
 */
const GuardianLink = {
  async create({ guardian_user_id, dependent_user_id, status = 'active' }) {
    const text = `
      INSERT INTO guardian_links (guardian_user_id, ward_user_id, status, created_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (guardian_user_id, ward_user_id) DO UPDATE
      SET status = EXCLUDED.status
      RETURNING id as link_id, guardian_user_id, ward_user_id as dependent_user_id, status, created_at;
    `;
    const res = await db.query(text, [guardian_user_id, dependent_user_id, status]);
    return res.rows[0];
  },

  async findByGuardianId(guardian_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.ward_user_id as dependent_user_id,
             u.full_name as dependent_name, u.email as dependent_email, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.ward_user_id
      WHERE gl.guardian_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [guardian_user_id]);
    return res.rows;
  },

  async findByDependentId(dependent_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.ward_user_id as dependent_user_id,
             u.full_name as guardian_name, u.email as guardian_email, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.guardian_user_id
      WHERE gl.ward_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [dependent_user_id]);
    return res.rows;
  },

  async updateStatus(link_id, status) {
    const text = `
      UPDATE guardian_links
      SET status = $2
      WHERE id = $1
      RETURNING id as link_id, guardian_user_id, ward_user_id as dependent_user_id, status;
    `;
    const res = await db.query(text, [link_id, status]);
    return res.rows[0] || null;
  }
};

module.exports = GuardianLink;
