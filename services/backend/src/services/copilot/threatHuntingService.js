const db = require('../../config/db');
const { log: auditLog } = require('../auditService');
const CopilotInvestigation = require('../../models/CopilotInvestigation');
const CopilotMessage = require('../../models/CopilotMessage');

/**
 * Knowledge patterns for common threat hunting queries
 */
const HUNT_PATTERNS = [
  {
    category: 'powershell_abuse',
    match: /powershell|scripting|interpreter|encoded/i,
    technique: 'T1059',
    keywords: ['powershell', 'pwsh', '-enc', 'encodedcommand', 'executionpolicy', 't1059'],
    defaultSeverity: 'high',
    defaultRecommendation: 'Audit PowerShell script block logging (Event ID 4104), restrict execution policies via AppLocker, and isolate offending host.'
  },
  {
    category: 'ransomware_activity',
    match: /ransomware|encrypt|vssadmin|shadow\s*copy/i,
    technique: 'T1486',
    keywords: ['ransom', 'encrypt', 'vssadmin', 'delete shadows', 'wmic shadowcopy', 't1486'],
    defaultSeverity: 'critical',
    defaultRecommendation: 'Immediately isolate affected endpoints from the network, verify offsite immutable backups, and block known ransomware C2 domains.'
  },
  {
    category: 'suspicious_authentication',
    match: /auth|login|brute\s*force|impossible\s*travel|credential\s*stuffing/i,
    technique: 'T1110',
    keywords: ['failed login', 'brute force', 'impossible travel', 'spray', 't1110', 't1078'],
    defaultSeverity: 'high',
    defaultRecommendation: 'Enforce MFA step-up verification, reset affected user credentials, and terminate active web/OAuth sessions.'
  },
  {
    category: 'credential_theft',
    match: /credential\s*theft|mimikatz|lsass|dump|sam\s*hive/i,
    technique: 'T1003',
    keywords: ['mimikatz', 'lsass', 'procdump', 'comsvcs', 'sekurlsa', 't1003'],
    defaultSeverity: 'critical',
    defaultRecommendation: 'Enable LSA RunAsPPL protection, revoke Kerberos KRBTGT keys if domain compromised, and isolate compromised hosts.'
  },
  {
    category: 'persistence_techniques',
    match: /persistence|scheduled\s*task|run\s*key|registry\s*autorun/i,
    technique: 'T1053',
    keywords: ['schtasks', 'cron', 'currentversion\\run', 'startup', 't1053'],
    defaultSeverity: 'medium',
    defaultRecommendation: 'Audit system autoruns and scheduled tasks using Sysinternals, remove illegitimate startup items, and inspect parent process lineages.'
  }
];

class ThreatHuntingService {
  /**
   * Executes a natural-language threat hunt across SIEM alerts, incidents, IOCs, and attack chains.
   *
   * @param {Object} params
   * @param {string} params.query - Hunt prompt (e.g. "Hunt for PowerShell abuse")
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.session_id] - Optional session ID to attach investigation memory
   * @param {string} [params.user_id]
   * @param {number} [params.limit=25]
   * @returns {Promise<Object>} Hunt results report
   */
  async hunt({ query, organization_id, session_id = null, user_id = null, limit = 25 }, client = null) {
    if (!organization_id) throw new Error('ThreatHuntingService Error: organization_id is required');
    if (!query) throw new Error('ThreatHuntingService Error: query is required');

    const dbClient = client || db;
    const cleanQuery = query.trim();

    // 1. Identify category and search keywords
    let matchedPattern = HUNT_PATTERNS.find(p => p.match.test(cleanQuery));
    let searchKeywords = matchedPattern ? matchedPattern.keywords : [cleanQuery.toLowerCase()];
    let primaryTechnique = matchedPattern ? matchedPattern.technique : null;
    let baseSeverity = matchedPattern ? matchedPattern.defaultSeverity : 'medium';

    // 2. Query SIEM Alerts
    const alertParams = [organization_id];
    const alertOrClauses = [];
    for (const kw of searchKeywords) {
      alertParams.push(`%${kw}%`);
      const idx = alertParams.length;
      alertOrClauses.push(`(title ILIKE $${idx} OR mitre_technique ILIKE $${idx} OR metadata::text ILIKE $${idx})`);
    }
    alertParams.push(limit);
    const alertSql = `
      SELECT id, title, severity, status, mitre_technique, metadata, created_at
      FROM public.siem_alerts
      WHERE organization_id = $1 AND (${alertOrClauses.join(' OR ')})
      ORDER BY created_at DESC
      LIMIT $${alertParams.length};
    `;
    const alertRes = await dbClient.query(alertSql, alertParams);
    const alerts = alertRes.rows;

    // 3. Query Incidents
    const incParams = [organization_id];
    const incOrClauses = [];
    for (const kw of searchKeywords) {
      incParams.push(`%${kw}%`);
      const idx = incParams.length;
      incOrClauses.push(`(threat_type::text ILIKE $${idx} OR explanation ILIKE $${idx} OR fingerprint ILIKE $${idx})`);
    }
    incParams.push(limit);
    const incSql = `
      SELECT id, threat_type, risk_level, risk_score, explanation, status, device_id, user_id, created_at
      FROM public.incidents
      WHERE organization_id = $1 AND (${incOrClauses.join(' OR ')})
      ORDER BY created_at DESC
      LIMIT $${incParams.length};
    `;
    const incRes = await dbClient.query(incSql, incParams);
    const incidents = incRes.rows;

    // 4. Query Threat IOCs
    const iocParams = [organization_id];
    const iocOrClauses = [];
    for (const kw of searchKeywords) {
      iocParams.push(`%${kw}%`);
      const idx = iocParams.length;
      iocOrClauses.push(`(ioc_value ILIKE $${idx} OR threat_actor ILIKE $${idx} OR malware_family ILIKE $${idx} OR campaign_name ILIKE $${idx} OR tags::text ILIKE $${idx})`);
    }
    iocParams.push(limit);
    const iocSql = `
      SELECT id, ioc_type, ioc_value, confidence, risk_score, threat_actor, malware_family, campaign_name, tags
      FROM public.threat_iocs
      WHERE organization_id = $1 AND (${iocOrClauses.join(' OR ')})
      ORDER BY risk_score DESC
      LIMIT $${iocParams.length};
    `;
    const iocRes = await dbClient.query(iocSql, iocParams);
    const iocs = iocRes.rows;

    // 5. Query Attack Chains
    const chainParams = [organization_id];
    const chainOrClauses = [];
    for (const kw of searchKeywords) {
      chainParams.push(`%${kw}%`);
      const idx = chainParams.length;
      chainOrClauses.push(`(timeline::text ILIKE $${idx} OR metadata::text ILIKE $${idx})`);
    }
    chainParams.push(limit);
    const chainSql = `
      SELECT id, root_incident_id, confidence_score, chain_length, timeline, created_at
      FROM public.attack_chain_snapshots
      WHERE organization_id = $1 AND (${chainOrClauses.join(' OR ')})
      ORDER BY created_at DESC
      LIMIT $${chainParams.length};
    `;
    const chainRes = await dbClient.query(chainSql, chainParams);
    const attackChains = chainRes.rows;

    // Build findings
    const findings = [];
    const evidence = [];

    if (alerts.length > 0) {
      findings.push({
        type: 'siem_alerts',
        count: alerts.length,
        summary: `Identified ${alerts.length} matching SIEM alerts in tenant environment.`,
        items: alerts.map(a => ({ id: a.id, title: a.title, severity: a.severity, technique: a.mitre_technique }))
      });
      alerts.forEach(a => evidence.push({ type: 'alert', id: a.id, title: a.title, severity: a.severity }));
    }

    if (incidents.length > 0) {
      findings.push({
        type: 'incidents',
        count: incidents.length,
        summary: `Identified ${incidents.length} related security incidents.`,
        items: incidents.map(i => ({ id: i.id, threat_type: i.threat_type, risk_level: i.risk_level, score: i.risk_score }))
      });
      incidents.forEach(i => evidence.push({ type: 'incident', id: i.id, threat_type: i.threat_type, risk_score: i.risk_score }));
    }

    if (iocs.length > 0) {
      findings.push({
        type: 'threat_iocs',
        count: iocs.length,
        summary: `Matched ${iocs.length} correlated indicators of compromise.`,
        items: iocs.map(ioc => ({ type: ioc.ioc_type, value: ioc.ioc_value, actor: ioc.threat_actor, family: ioc.malware_family }))
      });
      iocs.forEach(ioc => evidence.push({ type: 'ioc', value: ioc.ioc_value, ioc_type: ioc.ioc_type, risk_score: ioc.risk_score }));
    }

    if (attackChains.length > 0) {
      findings.push({
        type: 'attack_chains',
        count: attackChains.length,
        summary: `Discovered ${attackChains.length} correlated multi-stage attack chains.`,
        items: attackChains.map(c => ({ id: c.id, root_incident: c.root_incident_id, chain_length: c.chain_length }))
      });
      attackChains.forEach(c => evidence.push({ type: 'attack_chain', id: c.id, chain_length: c.chain_length }));
    }

    // Determine overall severity
    let calculatedSeverity = baseSeverity;
    const allSeverities = [
      ...alerts.map(a => (a.severity || '').toLowerCase()),
      ...incidents.map(i => (i.risk_level || '').toLowerCase())
    ];
    if (allSeverities.includes('critical')) calculatedSeverity = 'critical';
    else if (allSeverities.includes('high')) calculatedSeverity = 'high';
    else if (allSeverities.includes('medium')) calculatedSeverity = 'medium';

    const confidence = matchedPattern ? 0.94 : (findings.length > 0 ? 0.88 : 0.75);

    const recommendations = [];
    if (matchedPattern && matchedPattern.defaultRecommendation) {
      recommendations.push(matchedPattern.defaultRecommendation);
    }
    if (iocs.length > 0) {
      recommendations.push(`Block or isolate ${iocs.length} identified threat indicator(s) at network edge/firewall.`);
    }
    if (alerts.length > 0) {
      recommendations.push(`Triage and initiate containment playbooks for ${alerts.length} matching SIEM alert(s).`);
    }
    if (recommendations.length === 0) {
      recommendations.push('Maintain continuous monitoring and baseline telemetry for recurring anomalous patterns.');
    }

    const huntResult = {
      hunt_query: cleanQuery,
      category: matchedPattern ? matchedPattern.category : 'custom_hunt',
      technique: primaryTechnique,
      findings,
      evidence,
      severity: calculatedSeverity,
      confidence,
      recommendations
    };

    // Audit logging
    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_HUNT_EXECUTED',
      resource_type: 'threat_hunt',
      resource_id: cleanQuery.slice(0, 50),
      details: { query: cleanQuery, findings_count: findings.length, severity: calculatedSeverity }
    }).catch(() => {});

    // Session Memory Persistence
    if (session_id) {
      await CopilotInvestigation.create({
        session_id,
        organization_id,
        investigation_type: 'hunt',
        title: cleanQuery,
        target_type: 'query',
        target_id: cleanQuery,
        findings,
        evidence,
        recommendations,
        severity: calculatedSeverity,
        confidence,
        created_by: user_id
      }, dbClient).catch(() => {});

      await CopilotMessage.create({
        session_id,
        role: 'assistant',
        content: `Executed threat hunt: "${cleanQuery}". Discovered ${findings.length} finding categories with ${evidence.length} evidence items (Severity: ${calculatedSeverity.toUpperCase()}).`,
        metadata: { hunt_result: huntResult }
      }, dbClient).catch(() => {});
    }

    return huntResult;
  }
}

module.exports = new ThreatHuntingService();
