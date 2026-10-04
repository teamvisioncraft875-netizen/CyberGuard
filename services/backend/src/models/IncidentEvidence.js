const db = require('../config/db');

/**
 * IncidentEvidence Model — CRUD operations on the 'incident_evidence' table
 */
const IncidentEvidence = {
  async create({
    incident_id,
    evidence_type,
    evidence_data = null,
    metadata = null,
    raw_payload = {},
    file_url = null
  }) {
    const payloadObj = typeof raw_payload === 'object' && raw_payload !== null ? raw_payload : {};
    const textData = evidence_data 
      ? String(evidence_data) 
      : JSON.stringify(payloadObj);

    const metaObj = metadata 
      ? (typeof metadata === 'object' ? metadata : { raw: metadata }) 
      : { ...payloadObj, ...(file_url ? { file_url } : {}) };

    const text = `
      INSERT INTO incident_evidence (incident_id, evidence_type, evidence_data, metadata, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await db.query(text, [
      incident_id,
      evidence_type,
      textData,
      JSON.stringify(metaObj)
    ]);

    const row = res.rows[0];
    if (row) {
      row.raw_payload = row.metadata || {};
    }
    return row;
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM incident_evidence
      WHERE incident_id = $1
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows.map(row => {
      row.raw_payload = row.metadata || {};
      return row;
    });
  }
};

module.exports = IncidentEvidence;
