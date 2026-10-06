const db = require('../config/db');

/**
 * IncidentNote Model — CRUD operations on the 'incident_notes' table
 */
const IncidentNote = {
  /**
   * Create a new note for an incident
   */
  async create({
    organization_id,
    incident_id,
    user_id = null,
    note
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO incident_notes (
        organization_id, incident_id, user_id, note, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      incident_id,
      user_id,
      note
    ]);
    return res.rows[0];
  },

  /**
   * Find all notes for an incident, sorted chronologically with optional user details
   */
  async findByIncident(incidentId, organizationId = null, client = null) {
    const dbClient = client || db;
    const conditions = ['n.incident_id = $1'];
    const values = [incidentId];

    if (organizationId) {
      values.push(organizationId);
      conditions.push(`n.organization_id = $${values.length}`);
    }

    const text = `
      SELECT n.*, u.email as author_email, u.role as author_role
      FROM incident_notes n
      LEFT JOIN users u ON u.id = n.user_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY n.created_at ASC;
    `;
    const res = await dbClient.query(text, values);
    return res.rows;
  },

  /**
   * Find a specific note by ID and scope
   */
  async findById(id, organizationId = null) {
    const conditions = ['id = $1'];
    const values = [id];

    if (organizationId) {
      values.push(organizationId);
      conditions.push(`organization_id = $${values.length}`);
    }

    const text = `SELECT * FROM incident_notes WHERE ${conditions.join(' AND ')};`;
    const res = await db.query(text, values);
    return res.rows[0] || null;
  }
};

module.exports = IncidentNote;
