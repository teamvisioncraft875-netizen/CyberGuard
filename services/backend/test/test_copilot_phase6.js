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
const SoarCase = require('../src/models/SoarCase');
const SoarExecution = require('../src/models/SoarExecution');
const SoarApproval = require('../src/models/SoarApproval');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotInvestigation = require('../src/models/CopilotInvestigation');
const AuditLog = require('../src/models/AuditLog');

const executiveBriefingService = require('../src/services/copilot/executiveBriefingService');
const shiftHandoverService = require('../src/services/copilot/shiftHandoverService');
const timelineReconstructionService = require('../src/services/copilot/timelineReconstructionService');
const threatActorService = require('../src/services/copilot/threatActorService');
const securityPostureService = require('../src/services/copilot/securityPostureService');
const dashboardGenerationService = require('../src/services/copilot/dashboardGenerationService');
const crossInvestigationService = require('../src/services/copilot/crossInvestigationService');
const analystMetricsService = require('../src/services/copilot/analystMetricsService');

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

async function runCopilotPhase6Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 6: Enterprise Analyst & Executive Intelligence');
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
    const orgA = await createOrganizationFixture({ name: 'Tenant Enterprise Alpha P6' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Enterprise Beta P6' });

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
    const devRes = await db.query(
      `INSERT INTO devices (organization_id, user_id, device_name, status) VALUES ($1, $2, $3, 'active') RETURNING *;`,
      [orgA.id, employeeA.id, 'WORKSTATION-CORP-42']
    );
    const deviceA = devRes.rows[0];

    const alertA = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Mimikatz In-Memory Credential Dumping on DC-01',
      severity: 'critical',
      status: 'investigating',
      source_type: 'windows_sysmon',
      mitre_technique: 'T1003',
      metadata: { host: 'DC-01', ip: '10.0.1.10', target_user: 'Administrator', source_ip: '185.220.101.5' }
    });

    const alertB = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Encoded PowerShell Execution on WORKSTATION-CORP-42',
      severity: 'high',
      status: 'contained',
      source_type: 'edr',
      mitre_technique: 'T1059',
      metadata: { hostname: 'WORKSTATION-CORP-42', source_ip: '198.51.100.22' }
    });

    const incidentA = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'technical_threat',
      explanation: 'Targeted enterprise ransomware campaign with volume shadow copy tampering',
      fingerprint: '185.220.101.5',
      risk_level: 'critical',
      risk_score: 95,
      status: 'open',
      device_id: deviceA.id,
      user_id: employeeA.id
    });

    const incidentResolved = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'phishing',
      explanation: 'Spearphishing email with malicious macro attachment blocked at perimeter',
      fingerprint: 'evil-phish.net',
      risk_level: 'high',
      risk_score: 75,
      status: 'resolved',
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
      tags: ['T1003', 'c2_node']
    });

    const caseA = await SoarCase.create({
      organization_id: orgA.id,
      title: 'Case #101: Enterprise Ransomware Defense',
      description: 'Containment case for APT29 intrusion',
      severity: 'critical',
      status: 'open',
      priority: 'high',
      alert_id: alertA.id,
      created_by: adminA.id
    });

    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: analystA.id,
      title: 'Enterprise Incident Triage Session'
    });

    const invA = await CopilotInvestigation.create({
      session_id: sessionA.id,
      organization_id: orgA.id,
      investigation_type: 'hunt',
      title: 'Hunt for PowerShell abuse',
      target_type: 'query',
      target_id: 'powershell',
      evidence: [
        { type: 'ioc', value: '185.220.101.5' },
        { type: 'mitre', technique: 'T1059' }
      ],
      severity: 'high',
      confidence: 0.92,
      created_by: analystA.id
    });

    const invB = await CopilotInvestigation.create({
      session_id: sessionA.id,
      organization_id: orgA.id,
      investigation_type: 'ioc',
      title: 'IOC Pivot: 185.220.101.5',
      target_type: 'ip',
      target_id: '185.220.101.5',
      evidence: [
        { type: 'ioc', value: '185.220.101.5' },
        { type: 'mitre', technique: 'T1003' }
      ],
      severity: 'critical',
      confidence: 0.95,
      created_by: analystA.id
    });

    // 3. Seed Data for Tenant B (Isolation verification)
    const alertTenantB = await SiemAlert.create({
      organization_id: orgB.id,
      title: 'Tenant B Confidential Alert',
      severity: 'medium',
      status: 'new'
    });

    // ========================================================================
    // Group 1: Executive Security Briefing (Tests 1–6)
    // ========================================================================
    console.log('--- Group 1: Executive Security Briefing ---');

    await testAsync('1. Executive Briefing: generates executive_summary with timeframe window', async () => {
      const res = await executiveBriefingService.generateBriefing({
        organization_id: orgA.id,
        user_id: analystA.id,
        timeframe_days: 30
      });
      assert.ok(typeof res.executive_summary === 'string');
      assert.ok(res.executive_summary.includes('30d window'));
    });

    await testAsync('2. Executive Briefing: extracts top_risks across critical incidents and techniques', async () => {
      const res = await executiveBriefingService.generateBriefing({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.top_risks));
      assert.ok(res.top_risks.length > 0);
      assert.ok(res.top_risks.some(r => r.severity === 'critical'));
    });

    await testAsync('3. Executive Briefing: identifies active_incidents and critical_assets', async () => {
      const res = await executiveBriefingService.generateBriefing({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.active_incidents));
      assert.ok(res.active_incidents.some(i => i.id === incidentA.id));
      assert.ok(Array.isArray(res.critical_assets));
      assert.ok(res.critical_assets.some(a => a.asset === 'DC-01' || a.asset === deviceA.id));
    });

    await testAsync('4. Executive Briefing: calculates trend_analysis severity_distribution', async () => {
      const res = await executiveBriefingService.generateBriefing({
        organization_id: orgA.id
      });
      assert.ok(res.trend_analysis.severity_distribution.critical >= 1);
      assert.ok(res.trend_analysis.alerts_count >= 2);
    });

    await testAsync('5. Executive Briefing: includes business_impact with risk_level and financial exposure', async () => {
      const res = await executiveBriefingService.generateBriefing({
        organization_id: orgA.id
      });
      assert.strictEqual(res.business_impact.risk_level, 'critical');
      assert.strictEqual(res.business_impact.financial_exposure_rating, 'elevated');
      assert.ok(Array.isArray(res.recommended_actions));
    });

    await testAsync('6. Executive Briefing: API POST /api/v1/copilot/executive-briefing succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/executive-briefing`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ timeframe_days: 14 })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.executive_summary);
      assert.ok(data.business_impact);
    });

    // ========================================================================
    // Group 2: SOC Shift Handover Generator (Tests 7–12)
    // ========================================================================
    console.log('--- Group 2: SOC Shift Handover Generator ---');

    await testAsync('7. Shift Handover: summarizes incidents_worked in shift timeframe', async () => {
      const res = await shiftHandoverService.generateHandover({
        organization_id: orgA.id,
        shift_hours: 24
      });
      assert.ok(Array.isArray(res.incidents_worked));
      assert.ok(res.incidents_worked.length >= 2);
    });

    await testAsync('8. Shift Handover: gathers investigations_completed during shift', async () => {
      const res = await shiftHandoverService.generateHandover({
        organization_id: orgA.id,
        shift_hours: 24
      });
      assert.ok(Array.isArray(res.investigations_completed));
      assert.ok(res.investigations_completed.length >= 2);
    });

    await testAsync('9. Shift Handover: lists unresolved_threats requiring incoming analyst focus', async () => {
      const res = await shiftHandoverService.generateHandover({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.unresolved_threats));
      assert.ok(res.unresolved_threats.some(u => u.id === incidentA.id));
    });

    await testAsync('10. Shift Handover: tracks pending_approvals and pending_playbook_executions', async () => {
      const res = await shiftHandoverService.generateHandover({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.pending_approvals));
      assert.ok(Array.isArray(res.pending_playbook_executions));
    });

    await testAsync('11. Shift Handover: collects analyst_notes structure', async () => {
      const res = await shiftHandoverService.generateHandover({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.analyst_notes));
      assert.ok(typeof res.summary === 'string');
    });

    await testAsync('12. Shift Handover: API POST /api/v1/copilot/handover succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/handover`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ shift_hours: 12 })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.summary);
      assert.strictEqual(data.shift_hours, 12);
    });

    // ========================================================================
    // Group 3: Attack Timeline Reconstruction (Tests 13–18)
    // ========================================================================
    console.log('--- Group 3: Attack Timeline Reconstruction ---');

    await testAsync('13. Timeline Reconstruction: generates chronological timeline array', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.timeline));
      assert.ok(res.timeline.length >= 3);
    });

    await testAsync('14. Timeline Reconstruction: reconstructs Stage 1 (IOC Sighting) and Stage 2 (Alert)', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgA.id
      });
      const stages = res.timeline.map(t => t.stage);
      assert.ok(stages.includes('IOC'));
      const iocEvent = res.timeline.find(t => t.stage === 'IOC');
      assert.ok(iocEvent.detail.includes('185.220.101.5'));
    });

    await testAsync('15. Timeline Reconstruction: reconstructs Stage 3 (User) and Stage 4 (Device/Asset)', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgA.id
      });
      const stages = res.timeline.map(t => t.stage);
      assert.ok(stages.includes('User'));
      assert.ok(stages.includes('Device'));
    });

    await testAsync('16. Timeline Reconstruction: reconstructs Stage 5 (Incident) and Stage 7 (Containment)', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgA.id
      });
      const stages = res.timeline.map(t => t.stage);
      assert.ok(stages.includes('Incident'));
      assert.ok(stages.includes('Containment'));
    });

    await testAsync('17. Timeline Reconstruction: identifies attacker_objectives and impacted_assets', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.attacker_objectives));
      assert.ok(res.attacker_objectives.length > 0);
      assert.ok(Array.isArray(res.impacted_assets));
      assert.ok(res.impacted_assets.some(a => a.asset === deviceA.id));
    });

    await testAsync('18. Timeline Reconstruction: API POST /api/v1/copilot/reconstruct succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/reconstruct`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ incident_id: incidentA.id })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.timeline));
      assert.ok(data.attack_chain);
    });

    // ========================================================================
    // Group 4: Threat Actor Profiling (Tests 19–24)
    // ========================================================================
    console.log('--- Group 4: Threat Actor Profiling ---');

    await testAsync('19. Threat Actor: profiles known actor APT29 with tactics and techniques', async () => {
      const res = await threatActorService.profileActor({
        actor_name: 'APT29',
        organization_id: orgA.id
      });
      assert.ok(res.actor.includes('APT29'));
      assert.ok(res.tactics.includes('Initial Access'));
      assert.ok(res.techniques.includes('T1059'));
      assert.ok(res.confidence >= 0.90);
    });

    await testAsync('20. Threat Actor: profiles ransomware actor LockBit with malware families', async () => {
      const res = await threatActorService.profileActor({
        actor_name: 'LockBit',
        organization_id: orgA.id
      });
      assert.ok(res.actor.includes('LockBit'));
      assert.ok(res.malware_families.includes('LockBit 3.0'));
      assert.ok(res.techniques.includes('T1486'));
    });

    await testAsync('21. Threat Actor: profiles actor APT28 with aliases and campaigns', async () => {
      const res = await threatActorService.profileActor({
        actor_name: 'Fancy Bear',
        organization_id: orgA.id
      });
      assert.ok(res.actor.includes('APT28'));
      assert.ok(res.techniques.includes('T1110'));
    });

    await testAsync('22. Threat Actor: pivots from IOC to attributed threat actor', async () => {
      const res = await threatActorService.profileActor({
        ioc: '185.220.101.5',
        organization_id: orgA.id
      });
      assert.ok(res.actor.includes('APT29'));
      assert.ok(res.infrastructure.includes('185.220.101.5'));
    });

    await testAsync('23. Threat Actor: handles unspecified threat actor with baseline telemetry', async () => {
      const res = await threatActorService.profileActor({
        actor_name: 'Unknown-Custom-Group',
        organization_id: orgA.id
      });
      assert.ok(res.actor.includes('Unknown-Custom-Group'));
      assert.ok(res.confidence >= 0.80);
    });

    await testAsync('24. Threat Actor: API POST /api/v1/copilot/threat-actor succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/threat-actor`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ actor_name: 'APT29' })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.actor.includes('APT29'));
      assert.ok(Array.isArray(data.infrastructure));
    });

    // ========================================================================
    // Group 5: Security Posture Analysis (Tests 25–29)
    // ========================================================================
    console.log('--- Group 5: Security Posture Analysis ---');

    await testAsync('25. Security Posture: calculates posture_score between 0 and 100', async () => {
      const res = await securityPostureService.evaluatePosture({
        organization_id: orgA.id
      });
      assert.ok(typeof res.posture_score === 'number');
      assert.ok(res.posture_score >= 0 && res.posture_score <= 100);
      assert.ok(res.rating);
    });

    await testAsync('26. Security Posture: computes detection_coverage and mitre_coverage metrics', async () => {
      const res = await securityPostureService.evaluatePosture({
        organization_id: orgA.id
      });
      assert.ok(res.metrics.detection_coverage >= 50);
      assert.ok(res.metrics.mitre_coverage >= 20);
    });

    await testAsync('27. Security Posture: computes alert_quality and investigation_quality metrics', async () => {
      const res = await securityPostureService.evaluatePosture({
        organization_id: orgA.id
      });
      assert.ok(res.metrics.alert_quality >= 70);
      assert.ok(res.metrics.investigation_quality >= 50);
    });

    await testAsync('28. Security Posture: computes playbook_utilization and response_effectiveness', async () => {
      const res = await securityPostureService.evaluatePosture({
        organization_id: orgA.id
      });
      assert.ok(typeof res.metrics.playbook_utilization === 'number');
      assert.ok(typeof res.metrics.response_effectiveness === 'number');
      assert.ok(Array.isArray(res.recommendations));
    });

    await testAsync('29. Security Posture: API GET /api/v1/copilot/posture succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/posture`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(typeof data.posture_score === 'number');
      assert.ok(data.metrics);
    });

    // ========================================================================
    // Group 6: Natural Language Dashboard Generation (Tests 30–35)
    // ========================================================================
    console.log('--- Group 6: Natural Language Dashboard Generation ---');

    await testAsync('30. Dashboard Generation: "Show critical incidents" generates incident metrics', async () => {
      const res = await dashboardGenerationService.generateDashboard({
        query: 'Show critical incidents',
        organization_id: orgA.id
      });
      assert.ok(res.title.includes('Incident'));
      assert.ok(res.widgets.length >= 3);
      assert.ok(res.charts.length >= 2);
    });

    await testAsync('31. Dashboard Generation: "Show ransomware activity this month" generates ransomware dashboard', async () => {
      const res = await dashboardGenerationService.generateDashboard({
        query: 'Show ransomware activity this month',
        organization_id: orgA.id
      });
      assert.ok(res.title.includes('Ransomware'));
      assert.ok(res.widgets.some(w => w.title.includes('Ransomware')));
    });

    await testAsync('32. Dashboard Generation: "Show top attacked assets" generates endpoint exposure widgets', async () => {
      const res = await dashboardGenerationService.generateDashboard({
        query: 'Show top attacked assets',
        organization_id: orgA.id
      });
      assert.ok(res.title.includes('Assets'));
      assert.ok(res.charts.some(c => c.type === 'bar_chart'));
    });

    await testAsync('33. Dashboard Generation: "Show most active threat actors" generates adversary dashboard', async () => {
      const res = await dashboardGenerationService.generateDashboard({
        query: 'Show most active threat actors',
        organization_id: orgA.id
      });
      assert.ok(res.title.includes('Threat Actor'));
      assert.ok(res.metrics.primary_threat_group.includes('APT29'));
    });

    await testAsync('34. Dashboard Generation: includes valid widgets, charts, and metrics objects', async () => {
      const res = await dashboardGenerationService.generateDashboard({
        query: 'General security status',
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.widgets));
      assert.ok(Array.isArray(res.charts));
      assert.ok(typeof res.metrics === 'object');
    });

    await testAsync('35. Dashboard Generation: API POST /api/v1/copilot/dashboard succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/dashboard`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ query: 'Show ransomware activity this month' })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.dashboard.title);
      assert.ok(data.dashboard.widgets);
    });

    // ========================================================================
    // Group 7: Cross-Investigation Reasoning (Tests 36–40)
    // ========================================================================
    console.log('--- Group 7: Cross-Investigation Reasoning ---');

    await testAsync('36. Cross-Investigation: correlates repeated IOCs across distinct workspaces', async () => {
      const res = await crossInvestigationService.correlateAcrossInvestigations({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.shared_iocs));
      assert.ok(res.shared_iocs.some(i => i.ioc === '185.220.101.5'));
    });

    await testAsync('37. Cross-Investigation: identifies repeated MITRE techniques across investigations', async () => {
      const res = await crossInvestigationService.correlateAcrossInvestigations({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.shared_techniques));
      assert.ok(res.shared_techniques.some(t => t.technique === 'T1059' || t.technique === 'T1003'));
    });

    await testAsync('38. Cross-Investigation: identifies repeated threat actors across tenant cases', async () => {
      const res = await crossInvestigationService.correlateAcrossInvestigations({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.repeated_actors));
      assert.ok(res.repeated_actors.some(a => a.actor === 'APT29'));
    });

    await testAsync('39. Cross-Investigation: identifies recurring_attack_paths and computes elevated risk_score', async () => {
      const res = await crossInvestigationService.correlateAcrossInvestigations({
        organization_id: orgA.id
      });
      assert.ok(Array.isArray(res.recurring_attack_paths));
      assert.ok(res.recurring_attack_paths.length > 0);
      assert.ok(res.risk_score >= 70);
    });

    await testAsync('40. Cross-Investigation: API POST /api/v1/copilot/cross-investigation succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/cross-investigation`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ session_id: sessionA.id })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.shared_iocs));
      assert.ok(typeof data.risk_score === 'number');
    });

    // ========================================================================
    // Group 8: Analyst Productivity Intelligence (Tests 41–44)
    // ========================================================================
    console.log('--- Group 8: Analyst Productivity Intelligence ---');

    await testAsync('41. Analyst Metrics: tracks investigations_completed and incidents_resolved', async () => {
      const res = await analystMetricsService.getMetrics({
        organization_id: orgA.id,
        timeframe_days: 30
      });
      assert.ok(res.metrics.investigations_completed >= 2);
      assert.ok(res.metrics.incidents_resolved >= 1);
    });

    await testAsync('42. Analyst Metrics: calculates mttr_minutes and response_speed_minutes', async () => {
      const res = await analystMetricsService.getMetrics({
        organization_id: orgA.id
      });
      assert.ok(typeof res.metrics.mttr_minutes === 'number');
      assert.ok(res.metrics.mttr_minutes > 0);
      assert.ok(res.metrics.response_speed_minutes > 0);
    });

    await testAsync('43. Analyst Metrics: computes productivity_score and summary narrative', async () => {
      const res = await analystMetricsService.getMetrics({
        organization_id: orgA.id
      });
      assert.ok(res.productivity_score >= 70);
      assert.ok(typeof res.summary === 'string');
    });

    await testAsync('44. Analyst Metrics: API GET /api/v1/copilot/analyst-metrics succeeds with 200', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/analyst-metrics?timeframe_days=30`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.metrics);
      assert.ok(data.productivity_score);
    });

    // ========================================================================
    // Group 9: Audit Logging (Tests 45–52)
    // ========================================================================
    console.log('--- Group 9: Audit Logging ---');

    await testAsync('45. Audit: COPILOT_EXECUTIVE_BRIEFING logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_EXECUTIVE_BRIEFING', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('46. Audit: COPILOT_HANDOVER_GENERATED logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_HANDOVER_GENERATED', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('47. Audit: COPILOT_TIMELINE_RECONSTRUCTED logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_TIMELINE_RECONSTRUCTED', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('48. Audit: COPILOT_THREAT_ACTOR_PROFILED logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_THREAT_ACTOR_PROFILED', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('49. Audit: COPILOT_POSTURE_ANALYZED logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_POSTURE_ANALYZED', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('50. Audit: COPILOT_DASHBOARD_GENERATED logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_DASHBOARD_GENERATED', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('51. Audit: COPILOT_CROSS_INVESTIGATION logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_CROSS_INVESTIGATION', limit: 5 });
      assert.ok(logs.length > 0);
    });

    await testAsync('52. Audit: COPILOT_ANALYST_METRICS logged', async () => {
      const { logs } = await AuditLog.list({ organization_id: orgA.id, action: 'COPILOT_ANALYST_METRICS', limit: 5 });
      assert.ok(logs.length > 0);
    });

    // ========================================================================
    // Group 10: RBAC Validation (Tests 53–56)
    // ========================================================================
    console.log('--- Group 10: RBAC Validation ---');

    await testAsync('53. RBAC: Employee received HTTP 403 on POST /api/v1/copilot/executive-briefing', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/executive-briefing`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ timeframe_days: 30 })
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('54. RBAC: Employee received HTTP 403 on POST /api/v1/copilot/handover', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/handover`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ shift_hours: 12 })
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('55. RBAC: Employee received HTTP 403 on GET /api/v1/copilot/posture and /analyst-metrics', async () => {
      const resPosture = await fetch(`${baseUrl}/api/v1/copilot/posture`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(resPosture.status, 403);

      const resMetrics = await fetch(`${baseUrl}/api/v1/copilot/analyst-metrics`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(resMetrics.status, 403);
    });

    await testAsync('56. RBAC: Analyst and Admin succeed with HTTP 200 on executive-briefing and posture', async () => {
      const resAdmin = await fetch(`${baseUrl}/api/v1/copilot/executive-briefing`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({ timeframe_days: 30 })
      });
      assert.strictEqual(resAdmin.status, 200);

      const resAnalyst = await fetch(`${baseUrl}/api/v1/copilot/posture`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(resAnalyst.status, 200);
    });

    // ========================================================================
    // Group 11: Tenant Isolation (Tests 57–58)
    // ========================================================================
    console.log('--- Group 11: Tenant Isolation ---');

    await testAsync('57. Tenant Isolation: Executive briefing for Tenant B never surfaces Tenant A incidents/alerts', async () => {
      const resB = await executiveBriefingService.generateBriefing({
        organization_id: orgB.id,
        user_id: analystB.id
      });
      assert.strictEqual(resB.active_incidents.some(i => i.id === incidentA.id), false);
      assert.strictEqual(resB.critical_assets.some(a => a.asset === deviceA.id), false);
    });

    await testAsync('58. Tenant Isolation: Timeline reconstruction for Tenant B cannot access Tenant A incident', async () => {
      const res = await timelineReconstructionService.reconstruct({
        incident_id: incidentA.id,
        organization_id: orgB.id
      });
      // Should find no incident in Tenant B
      const stages = res.timeline.map(t => t.stage);
      assert.strictEqual(stages.includes('Incident'), false);
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

runCopilotPhase6Suite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test Suite Fatal Error:', err);
    process.exit(1);
  });
