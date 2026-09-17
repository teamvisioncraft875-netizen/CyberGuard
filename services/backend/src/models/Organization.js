const db = require('../config/db');

/**
 * Organization Model — CRUD operations on the 'organisations' table
 */
const Organization = {
  async create({ name, domain }) {
    const text = `
      INSERT INTO organisations (name, domain, created_at)
      VALUES ($1, $2, NOW())
      RETURNING id, name, domain, created_at;
    `;
    const res = await db.query(text, [name, domain]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `SELECT * FROM organisations WHERE id = $1;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByDomain(domain) {
    const text = `SELECT * FROM organisations WHERE domain = $1;`;
    const res = await db.query(text, [domain]);
    return res.rows[0] || null;
  },

  async findAll() {
    const text = `SELECT * FROM organisations ORDER BY name ASC;`;
    const res = await db.query(text, []);
    return res.rows;
  },

  async deleteById(id) {
    const text = `DELETE FROM organisations WHERE id = $1 RETURNING id;`;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = Organization;
