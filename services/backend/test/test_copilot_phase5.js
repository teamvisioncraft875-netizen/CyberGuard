process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const Organization = require('../src/models/Organization');
const User = require('../src/models/User');
const SiemAlert = require('../src/models/SiemAlert');
const Incident = require('../src/models/Incident');
const ThreatIOC = require('../src/models/ThreatIOC');
const AttackChainSnapshot = require('../src/models/AttackChainSnapshot');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotInvestigation = require('../src/models/CopilotInvestigation');
const AuditLog = require('../src/models/AuditLog');

const threatHuntingService = require('../src/services/copilot/threatHuntingService');
const iocInvestigationService = require('../src/services/copilot/iocInvestigationService');
const incidentCorrelationService = require('../src/services/copilot/incidentCorrelationService');
const autonomousInvestigationService = require('../src/services/copilot/autonomousInvestigationService');
const investigationGraphService = require('../src/services/copilot/investigationGraphService');
const mitreReasoningService = require('../src/services/copilot/mitreReasoningService');
const investigationReportService = require('../src/services/copilot/investigationReportService');
const copilotService = require('../src/services/copilot/copilotService');

const { createOrganizationFixture, createUserFixture, cleanupFixtures } = require('./fixtures');

let passed = 0;
let failed = 0;

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  [✅] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [❌] ${name}: ${err.message}`);
    failed++;
  }
}

function createToken(user, roleOverride = null, orgOverride = undefined) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: roleOverride || user.jwt_role || user.role,
      organization_id: orgOverride !== undefined ? orgOverride : (user.organization_id || null)
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runCopilotPhase5Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 5: Threat Hunting & Autonomous Investigation');
  console.log('========================================================================\n');

  let server;
  let baseUrl;

  try {
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    // 1. Fixtures Setup
    const orgA = await createOrganizationFixture({ name: 'Tenant Copilot Alpha P5' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Copilot Beta P5' });

    const adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    const analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    const employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });

    const analystB = await createUserFixture({ organization_id: orgB.id, role: 'analyst' });

    const tokenAdminA = createToken(adminA);
    const tokenAnalystA = createToken(analystA);
    const tokenEmployeeA = createToken(employeeA);
    const tokenAnalystB = createToken(analystB);
    const tokenNoOrg = createToken(analystA, 'analyst', null);

    // 2. Seed Data for Tenant A
    const alertPowerShell = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Encoded PowerShell Execution on WORKSTATION-9',
      severity: 'high',
      status: 'new',
      mitre_technique: 'T1059',
      metadata: { source_ip: '198.51.100.22', hostname: 'WORKSTATION-9', command: 'powershell.exe -enc JAB' }
    });

    const alertMimikatz = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'LSASS Memory Credential Dumping via Mimikatz on DC-01',
      severity: 'critical',
      status: 'investigating',
      mitre_technique: 'T1003',
      metadata: { source_ip: '185.220.101.5', host: 'DC-01', user: 'Administrator' }
    });

    const devRes = await db.query(
      `INSERT INTO devices (organization_id, user_id, device_name, status) VALUES ($1, $2, $3, 'active') RETURNING *;`,
      [orgA.id, employeeA.id, 'WORKSTATION-SEC-01']
    );
    const deviceA = devRes.rows[0];

    const incidentRansomware = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'technical_threat',
      explanation: 'Ransomware encryptor triggered Volume Shadow Copy deletion via vssadmin',
      fingerprint: '185.220.101.5',
      risk_level: 'critical',
      risk_score: 95,
      device_id: deviceA.id,
      user_id: employeeA.id
    });

    const incidentPhish = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'phishing',
      explanation: 'Targeted spearphishing delivery with macro attachment contacting evil-c2-beacon.com',
      fingerprint: 'evil-c2-beacon.com',
      risk_level: 'high',
      risk_score: 80,
      user_id: employeeA.id
    });

    const iocA = await ThreatIOC.createIOC({
      organization_id: orgA.id,
      ioc_type: 'ip',
      ioc_value: '185.220.101.5',
      confidence: 90,
      risk_score: 95,
      threat_actor: 'APT29',
      malware_family: 'CobaltStrike',
      campaign_name: 'SolarStorm',
      tags: ['T1003', 'c2_node', 'ransomware_feeder']
    });

    const iocDomain = await ThreatIOC.createIOC({
      organization_id: orgA.id,
      ioc_type: 'domain',
      ioc_value: 'evil-c2-beacon.com',
      confidence: 85,
      risk_score: 88,
      threat_actor: 'APT29',
      campaign_name: 'SolarStorm',
      tags: ['T1071', 'phishing_c2']
    });

    const chainA = await AttackChainSnapshot.create({
      organization_id: orgA.id,
      root_incident_id: incidentRansomware.id,
      chain_length: 3,
      confidence_score: 0.92,
      timeline: [
        { stage: 1, technique: 'T1566', name: 'Spearphishing' },
        { stage: 2, technique: 'T1059', name: 'PowerShell Execution' },
        { stage: 3, technique: 'T1003', name: 'OS Credential Dumping' }
      ]
    });

    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: analystA.id,
      title: 'Investigation Alpha: APT29 Campaign Hunt'
    });

    // 3. Seed Data for Tenant B (Isolation verification)
    const alertB = await SiemAlert.create({
      organization_id: orgB.id,
      title: 'Tenant B Isolated Secret Alert',
      severity: 'low',
      status: 'new',
      metadata: { source_ip: '203.0.113.99' }
    });

    const sessionB = await CopilotSession.create({
      organization_id: orgB.id,
      created_by: analystB.id,
      title: 'Tenant B Private Session'
    });

    // ========================================================================
    // Group 1: Threat Hunting (Tests 1–6)
    // ========================================================================
    console.log('--- Group 1: Threat Hunting ---');

    await testAsync('1. Threat Hunting: "Hunt for PowerShell abuse" identifies category, T1059, recommendations', async () => {
      const res = await threatHuntingService.hunt({
        query: 'Hunt for PowerShell abuse',
        organization_id: orgA.id,
        user_id: analystA.id
      });
      assert.strictEqual(res.category, 'powershell_abuse');
      assert.strictEqual(res.technique, 'T1059');
      assert.ok(res.findings.length > 0);
      assert.ok(res.evidence.length > 0);
      assert.ok(res.recommendations.some(r => r.toLowerCase().includes('powershell')));
    });

    await testAsync('2. Threat Hunting: "Hunt ransomware activity" identifies category, T1486, critical severity', async () => {
      const res = await threatHuntingService.hunt({
        query: 'Hunt ransomware activity',
        organization_id: orgA.id,
        user_id: analystA.id
      });
      assert.strictEqual(res.category, 'ransomware_activity');
      assert.strictEqual(res.technique, 'T1486');
      assert.strictEqual(res.severity, 'critical');
      assert.ok(res.findings.some(f => f.type === 'incidents'));
    });

    await testAsync('3. Threat Hunting: "Hunt suspicious authentication activity" identifies T1110', async () => {
      const res = await threatHuntingService.hunt({
        query: 'Hunt suspicious authentication activity',
        organization_id: orgA.id
      });
      assert.strictEqual(res.category, 'suspicious_authentication');
      assert.strictEqual(res.technique, 'T1110');
      assert.ok(Array.isArray(res.recommendations));
    });

    await testAsync('4. Threat Hunting: "Hunt credential theft indicators" identifies T1003 and Mimikatz alert', async () => {
      const res = await threatHuntingService.hunt({
        query: 'Hunt credential theft indicators',
        organization_id: orgA.id
      });
      assert.strictEqual(res.category, 'credential_theft');
      assert.strictEqual(res.technique, 'T1003');
      assert.strictEqual(res.severity, 'critical');
      assert.ok(res.findings.some(f => f.type === 'siem_alerts'));
    });

    await testAsync('5. Threat Hunting: "Hunt persistence techniques" identifies T1053 category', async () => {
      const res = await threatHuntingService.hunt({
        query: 'Hunt persistence techniques',
        organization_id: orgA.id
      });
      assert.strictEqual(res.category, 'persistence_techniques');
      assert.strictEqual(res.technique, 'T1053');
    });

    await testAsync('6. Threat Hunting: API POST /api/v1/copilot/hunt returns structured findings and evidence', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/hunt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          query: 'Hunt for PowerShell abuse',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.findings));
      assert.ok(Array.isArray(data.evidence));
      assert.ok(data.confidence >= 0.80);
    });

    // ========================================================================
    // Group 2: IOC Investigation (Tests 7–11)
    // ========================================================================
    console.log('--- Group 2: IOC Investigation ---');

    await testAsync('7. IOC Investigation: detectType classifies IP, domain, URL, hash, email', () => {
      assert.strictEqual(iocInvestigationService.detectType('185.220.101.5'), 'ip');
      assert.strictEqual(iocInvestigationService.detectType('evil-c2-beacon.com'), 'domain');
      assert.strictEqual(iocInvestigationService.detectType('https://phishing.site/login'), 'url');
      assert.strictEqual(iocInvestigationService.detectType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'sha256');
      assert.strictEqual(iocInvestigationService.detectType('d41d8cd98f00b204e9800998ecf8427e'), 'md5');
      assert.strictEqual(iocInvestigationService.detectType('attacker@malicious.org'), 'email');
    });

    await testAsync('8. IOC Investigation: IP pivots across ThreatIOC, SIEM Alerts, and Incidents', async () => {
      const res = await iocInvestigationService.investigate({
        ioc: '185.220.101.5',
        organization_id: orgA.id,
        user_id: analystA.id
      });
      assert.strictEqual(res.ioc, '185.220.101.5');
      assert.strictEqual(res.ioc_type, 'ip');
      assert.strictEqual(res.threat_intel.found, true);
      assert.strictEqual(res.threat_intel.threat_actor, 'APT29');
      assert.ok(res.related_alerts.length > 0);
      assert.ok(res.related_incidents.length > 0);
    });

    await testAsync('9. IOC Investigation: identifies affected assets (devices/hosts)', async () => {
      const res = await iocInvestigationService.investigate({
        ioc: '185.220.101.5',
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.affected_assets));
      assert.ok(res.affected_assets.some(a => a.asset_identifier === deviceA.id || a.asset_identifier === 'DC-01'));
    });

    await testAsync('10. IOC Investigation: identifies affected users', async () => {
      const res = await iocInvestigationService.investigate({
        ioc: '185.220.101.5',
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.affected_users));
      assert.ok(res.affected_users.some(u => u.user_identifier === employeeA.id || u.user_identifier === 'Administrator'));
    });

    await testAsync('11. IOC Investigation: API POST /api/v1/copilot/investigate/ioc succeeds with MITRE pivots', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/investigate/ioc`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          ioc: 'evil-c2-beacon.com',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.ioc, 'evil-c2-beacon.com');
      assert.strictEqual(data.threat_intel.threat_actor, 'APT29');
      assert.ok(Array.isArray(data.mitre));
    });

    // ========================================================================
    // Group 3: Incident Correlation (Tests 12–16)
    // ========================================================================
    console.log('--- Group 3: Incident Correlation ---');

    await testAsync('12. Incident Correlation: calculates correlation_score bounded between 0.0 and 1.0', async () => {
      const res = await incidentCorrelationService.correlate({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(typeof res.correlation_score === 'number');
      assert.ok(res.correlation_score >= 0.50 && res.correlation_score <= 1.0);
    });

    await testAsync('13. Incident Correlation: identifies common infrastructure (185.220.101.5)', async () => {
      const res = await incidentCorrelationService.correlate({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(res.related_entities.infrastructure.includes('185.220.101.5'));
    });

    await testAsync('14. Incident Correlation: identifies common threat actor (APT29)', async () => {
      const res = await incidentCorrelationService.correlate({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(res.related_entities.actors.includes('APT29'));
    });

    await testAsync('15. Incident Correlation: identifies shared MITRE techniques across alerts', async () => {
      const res = await incidentCorrelationService.correlate({
        alert_id: alertMimikatz.id,
        organization_id: orgA.id
      });
      assert.ok(res.related_entities.techniques.some(t => t.includes('T1003')));
    });

    await testAsync('16. Incident Correlation: API POST /api/v1/copilot/correlate returns evidence list', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/correlate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          incident_id: incidentRansomware.id,
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.evidence));
      assert.ok(data.evidence.length > 0);
    });

    // ========================================================================
    // Group 4: Autonomous Investigation (Tests 17–20)
    // ========================================================================
    console.log('--- Group 4: Autonomous Investigation ---');

    await testAsync('17. Autonomous Investigation: Alert ID triggers multi-source context gathering', async () => {
      const res = await autonomousInvestigationService.investigate({
        alert_id: alertMimikatz.id,
        organization_id: orgA.id,
        user_id: analystA.id
      });
      assert.strictEqual(res.target.type, 'alert');
      assert.ok(res.findings.length >= 2);
      assert.ok(res.evidence.length >= 2);
      assert.ok(res.confidence >= 0.85);
    });

    await testAsync('18. Autonomous Investigation: Incident ID triggers linked alert and asset aggregation', async () => {
      const res = await autonomousInvestigationService.investigate({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.strictEqual(res.target.type, 'incident');
      assert.ok(res.affected_assets.some(a => a.asset_identifier === deviceA.id));
      assert.ok(res.affected_users.some(u => u.user_identifier === employeeA.id));
    });

    await testAsync('19. Autonomous Investigation: IOC input triggers threat intelligence and pivot', async () => {
      const res = await autonomousInvestigationService.investigate({
        ioc: '185.220.101.5',
        organization_id: orgA.id
      });
      assert.strictEqual(res.target.type, 'ioc');
      assert.ok(res.threat_intel.length > 0);
      assert.strictEqual(res.threat_intel[0].threat_actor, 'APT29');
    });

    await testAsync('20. Autonomous Investigation: API POST /api/v1/copilot/investigate/incident returns summary and recommendations', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/investigate/incident`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          incident_id: incidentRansomware.id,
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(typeof data.summary === 'string');
      assert.ok(Array.isArray(data.recommendations));
      assert.ok(data.recommendations.length > 0);
    });

    // ========================================================================
    // Group 5: Investigation Graph (Tests 21–25)
    // ========================================================================
    console.log('--- Group 5: Investigation Graph ---');

    await testAsync('21. Investigation Graph: generates valid nodes and edges schema', async () => {
      const graph = await investigationGraphService.generateGraph({
        target_type: 'incident',
        target_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(graph.nodes));
      assert.ok(Array.isArray(graph.edges));
      assert.ok(graph.nodes.length >= 2);
    });

    await testAsync('22. Investigation Graph: correctly links IOC -> Alert node', () => {
      const graph = investigationGraphService.buildGraphFromEntities({
        organization_id: orgA.id,
        alerts: [alertMimikatz],
        iocs: [{ ioc_value: '185.220.101.5', ioc_type: 'ip' }]
      });
      const nodeTypes = graph.nodes.map(n => n.type);
      assert.ok(nodeTypes.includes('alert'));
      assert.ok(nodeTypes.includes('ioc'));
    });

    await testAsync('23. Investigation Graph: correctly links Alert -> MITRE Technique node', () => {
      const graph = investigationGraphService.buildGraphFromEntities({
        organization_id: orgA.id,
        alerts: [alertPowerShell]
      });
      const mitreNode = graph.nodes.find(n => n.type === 'mitre');
      assert.ok(mitreNode);
      assert.strictEqual(mitreNode.label, 'T1059');
      const edge = graph.edges.find(e => e.relationship === 'maps_to');
      assert.ok(edge);
    });

    await testAsync('24. Investigation Graph: correctly links Incident -> User and Incident -> Asset', () => {
      const graph = investigationGraphService.buildGraphFromEntities({
        organization_id: orgA.id,
        incidents: [incidentRansomware]
      });
      const userNode = graph.nodes.find(n => n.type === 'user');
      const assetNode = graph.nodes.find(n => n.type === 'asset');
      assert.ok(userNode);
      assert.ok(assetNode);
      assert.ok(graph.edges.some(e => e.relationship === 'compromised_user'));
      assert.ok(graph.edges.some(e => e.relationship === 'affected_asset'));
    });

    await testAsync('25. Investigation Graph: maintains deterministic structure for investigation replay', () => {
      const g1 = investigationGraphService.buildGraphFromEntities({
        organization_id: orgA.id,
        alerts: [alertPowerShell, alertMimikatz],
        iocs: ['185.220.101.5']
      });
      const g2 = investigationGraphService.buildGraphFromEntities({
        organization_id: orgA.id,
        alerts: [alertPowerShell, alertMimikatz],
        iocs: ['185.220.101.5']
      });
      assert.strictEqual(g1.nodes.length, g2.nodes.length);
      assert.strictEqual(g1.edges.length, g2.edges.length);
    });

    // ========================================================================
    // Group 6: MITRE Hunting (Tests 26–29)
    // ========================================================================
    console.log('--- Group 6: MITRE Hunting ---');

    await testAsync('26. MITRE Hunting: "Show T1059 activity" returns matching PowerShell alerts', async () => {
      const res = await mitreReasoningService.huntMitre({
        query: 'Show T1059 activity',
        organization_id: orgA.id
      });
      assert.strictEqual(res.technique, 'T1059');
      assert.ok(res.matching_alerts.length > 0);
      assert.ok(res.matching_alerts.some(a => a.mitre_technique === 'T1059'));
    });

    await testAsync('27. MITRE Hunting: "Show credential access techniques" returns T1003 alerts', async () => {
      const res = await mitreReasoningService.huntMitre({
        query: 'Show credential access techniques',
        organization_id: orgA.id
      });
      assert.strictEqual(res.tactic, 'credential access');
      assert.ok(res.matching_alerts.some(a => a.mitre_technique === 'T1003'));
    });

    await testAsync('28. MITRE Hunting: "Show persistence activity" resolves persistence tactic and T1053', async () => {
      const res = await mitreReasoningService.huntMitre({
        query: 'Show persistence activity',
        organization_id: orgA.id
      });
      assert.strictEqual(res.tactic, 'persistence');
      assert.ok(res.techniques_evaluated.includes('T1053'));
    });

    await testAsync('29. MITRE Hunting: returns attack chains matching technique in timeline', async () => {
      const res = await mitreReasoningService.huntMitre({
        technique: 'T1059',
        organization_id: orgA.id
      });
      assert.ok(res.attack_chains.length > 0);
      assert.ok(res.confidence >= 0.85);
    });

    // ========================================================================
    // Group 7: Report Generation (Tests 30–33)
    // ========================================================================
    console.log('--- Group 7: Report Generation ---');

    await testAsync('30. Report Generator: produces strictly JSON report format', async () => {
      const report = await investigationReportService.generateReport({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(typeof report === 'object');
      assert.ok(report.report_id);
      assert.ok(report.generated_at);
    });

    await testAsync('31. Report Generator: includes Executive Summary and Technical Summary', async () => {
      const report = await investigationReportService.generateReport({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(typeof report.executive_summary === 'string');
      assert.ok(typeof report.technical_summary === 'string');
      assert.ok(report.executive_summary.length > 30);
    });

    await testAsync('32. Report Generator: includes Affected Assets, Users, Indicators, and MITRE Mapping', async () => {
      const report = await investigationReportService.generateReport({
        incident_id: incidentRansomware.id,
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(report.affected_assets));
      assert.ok(Array.isArray(report.affected_users));
      assert.ok(Array.isArray(report.indicators));
      assert.ok(Array.isArray(report.mitre_mapping));
    });

    await testAsync('33. Report Generator: API POST /api/v1/copilot/report returns complete risk assessment', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          incident_id: incidentRansomware.id,
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      const r = data.report;
      assert.ok(r.risk_assessment.overall_risk);
      assert.ok(r.risk_assessment.risk_score >= 50);
      assert.ok(Array.isArray(r.recommended_actions));
    });

    // ========================================================================
    // Group 8: Session Investigation Memory (Tests 34–36)
    // ========================================================================
    console.log('--- Group 8: Session Investigation Memory ---');

    await testAsync('34. Session Investigation: operations persist records to CopilotInvestigation', async () => {
      const invs = await CopilotInvestigation.findBySession(sessionA.id, orgA.id);
      assert.ok(invs.length >= 3, `Expected at least 3 investigations, found ${invs.length}`);
      const types = invs.map(i => i.investigation_type);
      assert.ok(types.includes('hunt') || types.includes('ioc') || types.includes('report'));
    });

    await testAsync('35. Session Investigation: GET /api/v1/copilot/investigations/:sessionId returns recorded items', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/investigations/${sessionA.id}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.session_id, sessionA.id);
      assert.ok(data.count >= 3);
      assert.ok(Array.isArray(data.investigations));
    });

    await testAsync('36. Session Investigation: Copilot answers "What investigations have we performed?" and "What hunts were executed this week?"', async () => {
      const resInvs = await copilotService.query({
        organization_id: orgA.id,
        user_id: analystA.id,
        type: 'session_chat',
        question: 'What investigations have we performed?'
      });
      assert.ok(resInvs.answer.includes('[INVESTIGATION HISTORY]'));

      const resHunts = await copilotService.query({
        organization_id: orgA.id,
        user_id: analystA.id,
        type: 'session_chat',
        question: 'What hunts were executed this week?'
      });
      assert.ok(resHunts.answer.includes('[HUNT EXECUTION HISTORY]'));
    });

    // ========================================================================
    // Group 9: Audit Logging (Tests 37–41)
    // ========================================================================
    console.log('--- Group 9: Audit Logging ---');

    await testAsync('37. Audit: COPILOT_HUNT_EXECUTED logged on threat hunt', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_HUNT_EXECUTED', limit: 10 });
      assert.ok(logs.length > 0, 'COPILOT_HUNT_EXECUTED must be present in audit logs');
    });

    await testAsync('38. Audit: COPILOT_IOC_INVESTIGATED logged on IOC investigation', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_IOC_INVESTIGATED', limit: 10 });
      assert.ok(logs.length > 0, 'COPILOT_IOC_INVESTIGATED must be present in audit logs');
    });

    await testAsync('39. Audit: COPILOT_CORRELATION_EXECUTED logged on incident correlation', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_CORRELATION_EXECUTED', limit: 10 });
      assert.ok(logs.length > 0, 'COPILOT_CORRELATION_EXECUTED must be present in audit logs');
    });

    await testAsync('40. Audit: COPILOT_AUTONOMOUS_INVESTIGATION logged on autonomous investigation', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_AUTONOMOUS_INVESTIGATION', limit: 10 });
      assert.ok(logs.length > 0, 'COPILOT_AUTONOMOUS_INVESTIGATION must be present in audit logs');
    });

    await testAsync('41. Audit: COPILOT_REPORT_GENERATED logged on report generation', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_REPORT_GENERATED', limit: 10 });
      assert.ok(logs.length > 0, 'COPILOT_REPORT_GENERATED must be present in audit logs');
    });

    // ========================================================================
    // Group 10: RBAC (Tests 42–44)
    // ========================================================================
    console.log('--- Group 10: RBAC ---');

    await testAsync('42. RBAC: Employee role receives HTTP 403 on POST /api/v1/copilot/hunt', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/hunt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ query: 'Hunt for PowerShell abuse' })
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('43. RBAC: Employee role receives HTTP 403 on POST /api/v1/copilot/investigate/ioc and /report', async () => {
      const resIoc = await fetch(`${baseUrl}/api/v1/copilot/investigate/ioc`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ ioc: '185.220.101.5' })
      });
      assert.strictEqual(resIoc.status, 403);

      const resRep = await fetch(`${baseUrl}/api/v1/copilot/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ incident_id: incidentRansomware.id })
      });
      assert.strictEqual(resRep.status, 403);
    });

    await testAsync('44. RBAC: Analyst and Admin roles succeed with HTTP 200', async () => {
      const resAdmin = await fetch(`${baseUrl}/api/v1/copilot/hunt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({ query: 'Hunt ransomware activity' })
      });
      assert.strictEqual(resAdmin.status, 200);
    });

    // ========================================================================
    // Group 11: Tenant Isolation (Tests 45–46)
    // ========================================================================
    console.log('--- Group 11: Tenant Isolation ---');

    await testAsync('45. Tenant Isolation: Threat hunt in Tenant B never surfaces Tenant A alerts, incidents, or IOCs', async () => {
      const resB = await threatHuntingService.hunt({
        query: 'Hunt for PowerShell abuse',
        organization_id: orgB.id,
        user_id: analystB.id
      });
      // Should find zero Tenant A items in Tenant B
      const alertIds = resB.evidence.filter(e => e.type === 'alert').map(e => e.id);
      assert.strictEqual(alertIds.includes(alertPowerShell.id), false);
      assert.strictEqual(alertIds.includes(alertMimikatz.id), false);

      const incIds = resB.evidence.filter(e => e.type === 'incident').map(e => e.id);
      assert.strictEqual(incIds.includes(incidentRansomware.id), false);
    });

    await testAsync('46. Tenant Isolation: Tenant B cannot access Tenant A session investigations (HTTP 404)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/investigations/${sessionA.id}`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(res.status, 404);
    });

  } finally {
    if (server) {
      server.close();
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runCopilotPhase5Suite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test Suite Fatal Error:', err);
    process.exit(1);
  });
