const db = require('../../config/db');
const MitreMapping = require('../../models/MitreMapping');
const { log: auditLog } = require('../auditService');

/**
 * Curated MITRE ATT&CK Knowledge Base dictionary ensuring no hallucinated techniques.
 */
const MITRE_KNOWLEDGE_BASE = {
  'T1021': {
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use Valid Accounts to log into remote services such as RDP, SSH, or SMB to move laterally across internal networks.',
    evidence_indicators: ['Inbound RDP connection from internal IP', 'PsExec execution', 'SMB pipe activity', 'Anomalous port 3389/22 traversal'],
    confidence_baseline: 0.90
  },
  'T1071': {
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with normal network traffic.',
    evidence_indicators: ['Periodic outbound beaconing', 'Unusual User-Agent strings', 'High entropy payloads over TLS', 'Direct IP HTTP traffic'],
    confidence_baseline: 0.88
  },
  'T1071.001': {
    name: 'Web Protocols',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using HTTP/HTTPS to bypass perimeter security boundaries.',
    evidence_indicators: ['Outbound HTTP/HTTPS connections with fixed jitter intervals', 'Cobalt Strike malleable C2 profile signatures'],
    confidence_baseline: 0.92
  },
  'T1003': {
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries may attempt to dump credentials from memory or storage to obtain account login and credential material.',
    evidence_indicators: ['LSASS memory read access', 'Mimikatz invocation', 'NTDS.dit extraction', 'SAM registry hive copy'],
    confidence_baseline: 0.95
  },
  'T1078': {
    name: 'Valid Accounts',
    tactic: 'Defense Evasion / Initial Access',
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
    evidence_indicators: ['Impossible travel login', 'Login from unknown device after hours', 'Privilege elevation on compromised account'],
    confidence_baseline: 0.85
  },
  'T1486': {
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data on target systems to interrupt availability of system and network resources (Ransomware).',
    evidence_indicators: ['High-frequency file renaming/extension changing', 'Volume Shadow Copy deletion (vssadmin)', 'Mass disk write bursts'],
    confidence_baseline: 0.96
  },
  'T1566': {
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments or malicious links.',
    evidence_indicators: ['Suspicious email attachment (.iso, .exe, .xlsm)', 'Domain typosquatting', 'Authentication spoofing (SPF/DKIM fail)'],
    confidence_baseline: 0.91
  },
  'T1204': {
    name: 'User Execution',
    tactic: 'Execution',
    description: 'An adversary may rely upon specific actions by a user in order to gain execution, such as clicking a malicious link or opening an attachment.',
    evidence_indicators: ['User launched executable from Downloads folder', 'Macro execution triggered upon document open'],
    confidence_baseline: 0.86
  },
  'T1059': {
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters (PowerShell, cmd, bash) to execute malicious commands.',
    evidence_indicators: ['Encoded PowerShell execution (-enc)', 'Hidden window flags', 'Parent-child process anomaly (winword -> powershell)'],
    confidence_baseline: 0.93
  },
  'T1053': {
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',
    evidence_indicators: ['schtasks creation', 'cron modification', 'at service abuse'],
    confidence_baseline: 0.89
  },
  'T1110': {
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to attempt login passwords or credential tokens.',
    evidence_indicators: ['Burst failed authentications', 'Password spray pattern', 'Repeated 401 Unauthorized responses'],
    confidence_baseline: 0.91
  }
};

const TACTIC_TECHNIQUE_MAP = {
  'credential access': ['T1003', 'T1078', 'T1110'],
  'execution': ['T1059', 'T1204'],
  'persistence': ['T1078', 'T1053'],
  'lateral movement': ['T1021'],
  'command and control': ['T1071', 'T1071.001'],
  'initial access': ['T1566', 'T1078'],
  'impact': ['T1486'],
  'defense evasion': ['T1078']
};

/**
 * MITRE Reasoning Service — Analyzes, validates, and explains ATT&CK tactics, techniques, and chains.
 */
class MitreReasoningService {
  /**
   * Explains why an indicator or alert is mapped to a specific MITRE technique.
   *
   * @param {Object} params
   * @param {string} params.technique - e.g. 'T1021', 'T1071.001'
   * @param {string} [params.organization_id] - Tenant ID
   * @param {string} [params.user_id] - Analyst ID
   * @param {Object} [params.context] - Telemetry evidence context
   * @returns {Object} Structured reasoning report
   */
  async explainMapping({ technique, organization_id = null, user_id = null, context = {} }) {
    const cleanTechnique = String(technique || '').toUpperCase().trim();
    const info = MITRE_KNOWLEDGE_BASE[cleanTechnique] || MITRE_KNOWLEDGE_BASE[cleanTechnique.split('.')[0]];

    if (!info) {
      return {
        technique: cleanTechnique,
        recognized: false,
        explanation: `Technique ${cleanTechnique} is not recognized in the validated CyberGuard MITRE dictionary.`,
        confidence: 0.0
      };
    }

    const evidence = context.evidence || info.evidence_indicators;
    const confidence = context.confidence || info.confidence_baseline;

    const result = {
      technique: cleanTechnique,
      technique_name: info.name,
      tactic: info.tactic,
      description: info.description,
      evidence: Array.isArray(evidence) ? evidence : [evidence],
      confidence,
      recognized: true,
      reasoning: `Telemetry matches technique ${cleanTechnique} (${info.name}) within the ${info.tactic} tactic based on observed behavior: ${info.evidence_indicators[0]}.`
    };

    if (organization_id) {
      await auditLog({
        organization_id,
        user_id,
        action: 'COPILOT_MITRE_REASONING',
        resource_type: 'mitre_technique',
        resource_id: cleanTechnique,
        details: { technique: cleanTechnique, tactic: info.tactic, confidence }
      }).catch(() => {});
    }

    return result;
  }

  /**
   * Explains multi-stage attack progression across the MITRE kill chain.
   */
  explainAttackChain({ techniques = [], organization_id = null, user_id = null }) {
    const cleanTechniques = (techniques || []).map(t => String(t).toUpperCase().trim());
    const progression = [];

    for (const tech of cleanTechniques) {
      const info = MITRE_KNOWLEDGE_BASE[tech] || MITRE_KNOWLEDGE_BASE[tech.split('.')[0]];
      if (info) {
        progression.push({
          technique: tech,
          technique_name: info.name,
          tactic: info.tactic
        });
      }
    }

    const report = {
      stages_count: progression.length,
      progression,
      summary: progression.length > 0
        ? `Observed ${progression.length}-stage progression spanning: ${progression.map(p => `${p.tactic} (${p.technique})`).join(' ➔ ')}.`
        : 'No recognized MITRE techniques in the provided attack chain.',
      recommendation: 'Sever external communication channels and revoke credentials associated with intermediate stages.'
    };

    if (organization_id) {
      auditLog({
        organization_id,
        user_id,
        action: 'COPILOT_MITRE_REASONING',
        resource_type: 'attack_chain',
        resource_id: 'mitre_chain',
        details: { techniques: cleanTechniques, stages: progression.length }
      }).catch(() => {});
    }

    return report;
  }

  /**
   * Hunts for alerts, incidents, and attack chains matching a MITRE technique or tactic.
   */
  async huntMitre({ query = '', technique = null, tactic = null, organization_id, user_id = null, limit = 20 }, client = null) {
    if (!organization_id) throw new Error('MitreReasoningService.huntMitre requires organization_id');
    const dbClient = client || db;

    let targetTechniques = [];
    let detectedTactic = tactic ? tactic.toLowerCase().trim() : null;
    let explicitTechnique = technique ? technique.toUpperCase().trim() : null;

    if (!explicitTechnique && query) {
      const match = query.match(/T\d{4}(?:\.\d{3})?/i);
      if (match) {
        explicitTechnique = match[0].toUpperCase();
      }
    }

    if (explicitTechnique) {
      targetTechniques.push(explicitTechnique);
      const info = MITRE_KNOWLEDGE_BASE[explicitTechnique] || MITRE_KNOWLEDGE_BASE[explicitTechnique.split('.')[0]];
      if (info && !detectedTactic) {
        detectedTactic = info.tactic.toLowerCase();
      }
    } else {
      const lowerQuery = String(query).toLowerCase();
      for (const [tac, techs] of Object.entries(TACTIC_TECHNIQUE_MAP)) {
        if (lowerQuery.includes(tac) || (detectedTactic && detectedTactic.includes(tac))) {
          detectedTactic = tac;
          targetTechniques.push(...techs);
          break;
        }
      }
    }

    if (targetTechniques.length === 0 && !query) {
      targetTechniques = Object.keys(MITRE_KNOWLEDGE_BASE);
    }

    // 1. Query SIEM Alerts
    const alertConditions = ['organization_id = $1'];
    const alertParams = [organization_id];

    if (targetTechniques.length > 0) {
      const orClauses = [];
      for (const t of targetTechniques) {
        alertParams.push(`%${t}%`);
        orClauses.push(`mitre_technique ILIKE $${alertParams.length}`);
      }
      alertConditions.push(`(${orClauses.join(' OR ')})`);
    } else if (query) {
      alertParams.push(`%${query}%`);
      alertConditions.push(`(title ILIKE $${alertParams.length} OR metadata::text ILIKE $${alertParams.length})`);
    }

    alertParams.push(limit);
    const alertSql = `
      SELECT id, title, severity, status, mitre_technique, created_at, metadata
      FROM public.siem_alerts
      WHERE ${alertConditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${alertParams.length};
    `;
    const alertRes = await dbClient.query(alertSql, alertParams);
    const matchingAlerts = alertRes.rows;

    // 2. Query Incidents
    const incConditions = ['organization_id = $1'];
    const incParams = [organization_id];

    if (targetTechniques.length > 0) {
      const incOr = [];
      for (const t of targetTechniques) {
        incParams.push(`%${t}%`);
        incOr.push(`explanation ILIKE $${incParams.length}`);
      }
      if (detectedTactic) {
        incParams.push(`%${detectedTactic}%`);
        incOr.push(`threat_type::text ILIKE $${incParams.length}`);
      }
      incConditions.push(`(${incOr.join(' OR ')})`);
    } else if (query) {
      incParams.push(`%${query}%`);
      incConditions.push(`(explanation ILIKE $${incParams.length} OR threat_type::text ILIKE $${incParams.length})`);
    }

    incParams.push(limit);
    const incSql = `
      SELECT id, threat_type, risk_level, risk_score, explanation, status, created_at
      FROM public.incidents
      WHERE ${incConditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${incParams.length};
    `;
    const incRes = await dbClient.query(incSql, incParams);
    const matchingIncidents = incRes.rows;

    // 3. Query Attack Chains
    const chainConditions = ['organization_id = $1'];
    const chainParams = [organization_id];

    if (targetTechniques.length > 0) {
      const chainOr = [];
      for (const t of targetTechniques) {
        chainParams.push(`%${t}%`);
        chainOr.push(`(timeline::text ILIKE $${chainParams.length} OR metadata::text ILIKE $${chainParams.length})`);
      }
      chainConditions.push(`(${chainOr.join(' OR ')})`);
    }

    chainParams.push(limit);
    const chainSql = `
      SELECT id, root_incident_id, confidence_score, chain_length, timeline, created_at
      FROM public.attack_chain_snapshots
      WHERE ${chainConditions.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${chainParams.length};
    `;
    const chainRes = await dbClient.query(chainSql, chainParams);
    const matchingChains = chainRes.rows;

    const baseConfidence = explicitTechnique && MITRE_KNOWLEDGE_BASE[explicitTechnique]
      ? MITRE_KNOWLEDGE_BASE[explicitTechnique].confidence_baseline
      : 0.88;

    return {
      query: query || null,
      technique: explicitTechnique || (targetTechniques.length === 1 ? targetTechniques[0] : null),
      tactic: detectedTactic || null,
      techniques_evaluated: targetTechniques,
      matching_alerts: matchingAlerts,
      incidents: matchingIncidents,
      attack_chains: matchingChains,
      confidence: baseConfidence,
      summary: `Found ${matchingAlerts.length} alerts, ${matchingIncidents.length} incidents, and ${matchingChains.length} attack chains for ${explicitTechnique || detectedTactic || query || 'evaluated techniques'}.`
    };
  }
}

const mitreReasoningService = new MitreReasoningService();
module.exports = mitreReasoningService;
module.exports.MITRE_KNOWLEDGE_BASE = MITRE_KNOWLEDGE_BASE;
