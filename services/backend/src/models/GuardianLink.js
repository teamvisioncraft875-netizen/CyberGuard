const db = require('../config/db');

/**
 * GuardianLink Model — CRUD operations on the 'guardian_links' table
 */
const GuardianLink = {
  async create({ guardian_user_id, dependent_user_id, status = 'pending' }) {
    const text = `
      INSERT INTO guardian_links (guardian_user_id, dependent_user_id, status, created_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (guardian_user_id, dependent_user_id) DO UPDATE
      SET status = EXCLUDED.status
      RETURNING id as link_id, id, guardian_user_id, dependent_user_id, status, created_at;
    `;
    const res = await db.query(text, [guardian_user_id, dependent_user_id, status]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `
      SELECT id as link_id, id, guardian_user_id, dependent_user_id, status, created_at
      FROM guardian_links
      WHERE id = $1;
    `;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByGuardianId(guardian_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.dependent_user_id,
             u.email as dependent_email, split_part(u.email, '@', 1) as dependent_name, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.dependent_user_id
      WHERE gl.guardian_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [guardian_user_id]);
    return res.rows;
  },

  async findByDependentId(dependent_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.dependent_user_id,
             u.email as guardian_email, split_part(u.email, '@', 1) as guardian_name, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.guardian_user_id
      WHERE gl.dependent_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [dependent_user_id]);
    return res.rows;
  },

  async updateStatus(link_id, status) {
    const text = `
      UPDATE guardian_links
      SET status = $2
      WHERE id = $1
      RETURNING id as link_id, id, guardian_user_id, dependent_user_id, status, created_at;
    `;
    const res = await db.query(text, [link_id, status]);
    return res.rows[0] || null;
  }
};

module.exports = GuardianLink;
