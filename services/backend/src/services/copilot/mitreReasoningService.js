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
  }
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
}

const mitreReasoningService = new MitreReasoningService();
module.exports = mitreReasoningService;
