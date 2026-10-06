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
  }),
  exposed_secret: Object.freeze({
    technique_id: 'T1552',
    technique_name: 'Unsecured Credentials'
  }),
  attack_surface_exposure: Object.freeze({
    technique_id: 'T1046',
    technique_name: 'Network Service Discovery'
  }),
  ddos: Object.freeze({
    technique_id: 'T1498',
    technique_name: 'Network Denial of Service'
  })
});

/**
 * MitreMapping Model — CRUD operations on the 'mitre_mappings' table
 */
const MitreMapping = {
  THREAT_TO_MITRE,

  getTechniqueForAttackSurface(ruleId) {
    const cleanRule = String(ruleId || '').toUpperCase().trim();
    if (cleanRule === 'EXP-CRIT-RDP') {
      return {
        technique_id: 'T1021.001',
        technique_name: 'Remote Services: Remote Desktop Protocol'
      };
    }
    if (cleanRule === 'EXP-HIGH-SSH') {
      return {
        technique_id: 'T1133',
        technique_name: 'External Remote Services'
      };
    }
    if (
      cleanRule.startsWith('EXP-CRIT-') ||
      cleanRule.startsWith('EXP-HIGH-') ||
      cleanRule === 'EXP-MED-HTTP'
    ) {
      return {
        technique_id: 'T1190',
        technique_name: 'Exploit Public-Facing Application'
      };
    }
    return {
      technique_id: 'T1046',
      technique_name: 'Network Service Discovery'
    };
  },

  getTechniqueForThreat(threatType, ruleId = null) {
    if (ruleId) {
      const cleanRule = String(ruleId).toUpperCase().trim();
      if (cleanRule === 'SIEM-BURST-BRUTE' || cleanRule === 'SIEM-AUTH-BRUTE' || cleanRule === 'SIEM-RULE-BRUTE' || cleanRule === 'SIEM-RULE-1') {
        return { technique_id: 'T1110', technique_name: 'Brute Force' };
      }
      if (cleanRule === 'SIEM-RULE-SPRAY' || cleanRule === 'SIEM-RULE-2') {
        return { technique_id: 'T1110.003', technique_name: 'Password Spraying' };
      }
      if (cleanRule === 'SIEM-BURST-PRV' || cleanRule === 'SIEM-PRV-ESCALATION' || cleanRule === 'SIEM-RULE-PRV' || cleanRule === 'SIEM-RULE-3') {
        return { technique_id: 'T1068', technique_name: 'Exploitation for Privilege Escalation' };
      }
      if (cleanRule === 'SIEM-RULE-PWSH' || cleanRule === 'SIEM-RULE-4') {
        return { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter: PowerShell' };
      }
      if (cleanRule === 'SIEM-LM-DEVICE' || cleanRule === 'SIEM-LATERAL-MOVEMENT') {
        return { technique_id: 'T1021', technique_name: 'Remote Services' };
      }
      if (cleanRule === 'SIEM-LM-IP' || cleanRule === 'SIEM-CREDENTIAL-REUSE') {
        return { technique_id: 'T1078', technique_name: 'Valid Accounts' };
      }
      if (cleanRule === 'SIEM-DEF-1102' || cleanRule === 'SIEM-RULE-LOGCLEAR' || cleanRule === 'SIEM-RULE-5') {
        return { technique_id: 'T1070', technique_name: 'Indicator Removal on Host' };
      }
      if (cleanRule === 'SIEM-RULE-REG' || cleanRule === 'SIEM-RULE-6') {
        return { technique_id: 'T1547', technique_name: 'Boot or Logon Autostart Execution' };
      }
      if (cleanRule === 'SIEM-PROC-SUSP') {
        return { technique_id: 'TA0002', technique_name: 'Execution' };
      }
      if (cleanRule === 'SIEM-NET-C2' || cleanRule === 'SIEM-RULE-BEACON' || cleanRule === 'SIEM-RULE-7') {
        return { technique_id: 'T1071', technique_name: 'Application Layer Protocol' };
      }
    }
    if (!threatType) return THREAT_TO_MITRE.phishing;
    const key = String(threatType).toLowerCase().trim();
    if (key === 'attack_surface_exposure' && ruleId) {
      return this.getTechniqueForAttackSurface(ruleId);
    }
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
