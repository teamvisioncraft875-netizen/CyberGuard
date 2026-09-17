const db = require('../config/db');

/**
 * User Model — CRUD operations on the 'users' table
 */
const User = {
  async create({ org_id = null, email, password_hash, full_name, role = 'individual' }) {
    const text = `
      INSERT INTO users (org_id, email, password_hash, full_name, role, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
      RETURNING id, org_id, email, full_name, role, created_at, updated_at;
    `;
    const res = await db.query(text, [org_id, email, password_hash, full_name, role]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `
      SELECT id, org_id, email, full_name, role, created_at, updated_at
      FROM users
      WHERE id = $1;
    `;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByEmail(email) {
    const text = `
      SELECT *
      FROM users
      WHERE email = $1;
    `;
    const res = await db.query(text, [email]);
    return res.rows[0] || null;
  },

  async findByOrgId(org_id) {
    const text = `
      SELECT id, org_id, email, full_name, role, created_at
      FROM users
      WHERE org_id = $1
      ORDER BY created_at DESC;
    `;
    const res = await db.query(text, [org_id]);
    return res.rows;
  },

  async update(id, fields = {}) {
    const allowed = ['full_name', 'role', 'org_id'];
    const keys = Object.keys(fields).filter(k => allowed.includes(k));
    if (keys.length === 0) return null;

    const setClauses = keys.map((k, i) => `${k} = $${i + 2}`).join(', ');
    const values = [id, ...keys.map(k => fields[k])];

    const text = `
      UPDATE users
      SET ${setClauses}, updated_at = NOW()
      WHERE id = $1
      RETURNING id, org_id, email, full_name, role, updated_at;
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
