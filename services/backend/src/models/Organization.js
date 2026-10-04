const db = require('../config/db');

/**
 * Organization Model — CRUD operations on the 'organizations' table
 */
const Organization = {
  async create({ name }) {
    const text = `
      INSERT INTO organizations (name, created_at)
      VALUES ($1, NOW())
      RETURNING id, name, created_at;
    `;
    const res = await db.query(text, [name]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `SELECT id, name, created_at FROM organizations WHERE id = $1;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByName(name) {
    const text = `SELECT id, name, created_at FROM organizations WHERE LOWER(name) = LOWER($1);`;
    const res = await db.query(text, [name]);
    return res.rows[0] || null;
  },

  async findAll() {
    const text = `SELECT id, name, created_at FROM organizations ORDER BY name ASC;`;
    const res = await db.query(text, []);
    return res.rows;
  },

  async deleteById(id) {
    const text = `DELETE FROM organizations WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Organization;
