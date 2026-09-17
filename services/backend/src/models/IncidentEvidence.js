const db = require('../config/db');

/**
 * IncidentEvidence Model — CRUD operations on the 'incident_evidence' table
 */
const IncidentEvidence = {
  async create({ incident_id, evidence_type, raw_payload = {}, file_url = null }) {
    const text = `
      INSERT INTO incident_evidence (incident_id, evidence_type, raw_payload, file_url, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      incident_id,
      evidence_type,
      JSON.stringify(raw_payload),
      file_url
    ]);
    return res.rows[0];
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM incident_evidence
      WHERE incident_id = $1
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  }
};

module.exports = IncidentEvidence;
