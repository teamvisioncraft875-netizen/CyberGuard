const db = require('../config/db');

/**
 * MitreMapping Model — CRUD operations on the 'mitre_mappings' table
 */
const MitreMapping = {
  async create({ incident_id, technique_id, technique_name }) {
    const text = `
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const res = await db.query(text, [incident_id, technique_id, technique_name]);
    return res.rows[0];
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM mitre_mappings
      WHERE incident_id = $1;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  },

  async getTechniqueAggregates({ user_id = null, organization_id = null, limit = 10 } = {}) {
    const conditions = [];
    const values = [];

    // Enforce tenant/user isolation through parent incidents link
    if (user_id) {
      values.push(user_id);
      conditions.push(`i.user_id = $${values.length}`);
    }
    if (organization_id) {
      values.push(organization_id);
      conditions.push(`i.organization_id = $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    values.push(limit);

    const text = `
      SELECT m.technique_id, m.technique_name, COUNT(*) as incident_count
      FROM mitre_mappings m
      JOIN incidents i ON i.id = m.incident_id
      ${whereClause}
      GROUP BY m.technique_id, m.technique_name
      ORDER BY incident_count DESC
      LIMIT $${values.length};
    `;
    const res = await db.query(text, values);
    return res.rows;
  }
};

module.exports = MitreMapping;
