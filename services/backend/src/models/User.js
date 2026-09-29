const db = require('../config/db');

const ALLOWED_UPDATE_FIELDS = Object.freeze(['role', 'organization_id']);

/**
 * User Model — CRUD operations on the 'users' table
 */
const User = {
  async create({ organization_id = null, email, password_hash, role = 'individual' }) {
    const text = `
      INSERT INTO users (organization_id, email, password_hash, role, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING id, organization_id, email, role, created_at;
    `;
    const res = await db.query(text, [organization_id, email, password_hash, role]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `
      SELECT id, email, password_hash, role, organization_id, created_at
      FROM users
      WHERE id = $1;
    `;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByEmail(email) {
    const text = `
      SELECT id, email, password_hash, role, organization_id, created_at
      FROM users
      WHERE LOWER(email) = LOWER($1);
    `;
    const res = await db.query(text, [email]);
    return res.rows[0] || null;
  },

  async findByOrganizationId(organization_id) {
    const text = `
      SELECT id, organization_id, email, role, created_at
      FROM users
      WHERE organization_id = $1
      ORDER BY created_at DESC;
    `;
    const res = await db.query(text, [organization_id]);
    return res.rows;
  },


  async update(id, fields = {}) {
    const keys = Object.keys(fields).filter(k => ALLOWED_UPDATE_FIELDS.includes(k));
    if (keys.length === 0) return null;

    const setClauses = keys.map((k, i) => `${k} = $${i + 2}`).join(', ');
    const values = [id, ...keys.map(k => fields[k])];

    const text = `
      UPDATE users
      SET ${setClauses}
      WHERE id = $1
      RETURNING id, organization_id, email, role, created_at;
    `;
    const res = await db.query(text, values);
    return res.rows[0] || null;
  },

  async deleteById(id) {
    const text = `DELETE FROM users WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = User;
