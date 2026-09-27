const db = require('../config/db');

/**
 * Centralized mapping from CYBERGUARD threat types to MITRE ATT&CK techniques.
 * Covers all threat types supported by the database enum and detection engines:
 * - phishing: T1566 (Phishing)
 * - malicious_url: T1204 (User Execution - Malicious URL)
 * - deepfake: T1586.002 (Compromise Accounts: Synthetic Persona)
 * - impersonation: T1585 (Establish Accounts / Impersonation)
 * - account_takeover: T1110 (Brute Force / Credential Stuffing)
 * - technical_threat: T1071 (Application Layer Protocol Anomaly)
 */
const THREAT_TO_MITRE = Object.freeze({
  phishing: Object.freeze({
    technique_id: 'T1566',
    technique_name: 'Phishing'
  }),
  malicious_url: Object.freeze({
    technique_id: 'T1204',
    technique_name: 'User Execution - Malicious URL'
  }),
  deepfake: Object.freeze({
    technique_id: 'T1586.002',
    technique_name: 'Compromise Accounts: Synthetic Persona'
  }),
  impersonation: Object.freeze({
    technique_id: 'T1585',
    technique_name: 'Establish Accounts / Impersonation'
  }),
  account_takeover: Object.freeze({
    technique_id: 'T1110',
    technique_name: 'Brute Force / Credential Stuffing'
  }),
  technical_threat: Object.freeze({
    technique_id: 'T1071',
    technique_name: 'Application Layer Protocol Anomaly'
  })
});

/**
 * MitreMapping Model — CRUD operations on the 'mitre_mappings' table
 */
const MitreMapping = {
  THREAT_TO_MITRE,

  getTechniqueForThreat(threatType) {
    if (!threatType) return THREAT_TO_MITRE.phishing;
    const key = String(threatType).toLowerCase().trim();
    return THREAT_TO_MITRE[key] || THREAT_TO_MITRE.phishing;
  },

  async create({ incident_id, technique_id, technique_name }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const res = await dbClient.query(text, [incident_id, technique_id, technique_name]);
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

  async findByIncidentIds(incident_ids) {
    if (!incident_ids || incident_ids.length === 0) return [];
    const text = `
      SELECT * FROM mitre_mappings
      WHERE incident_id = ANY($1::uuid[]);
    `;
    const res = await db.query(text, [incident_ids]);
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
