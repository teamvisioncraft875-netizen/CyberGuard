process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const ThreatIOC = require('../src/models/ThreatIOC');
const SiemAlert = require('../src/models/SiemAlert');
const SoarCase = require('../src/models/SoarCase');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarExecution = require('../src/models/SoarExecution');
const SoarResponseRecommendation = require('../src/models/SoarResponseRecommendation');
const SoarKnowledgeBase = require('../src/models/SoarKnowledgeBase');

const iocResponseAutomationService = require('../src/services/soar/iocResponseAutomationService');
const threatEnrichmentService = require('../src/services/soar/threatEnrichmentService');
const recommendationEngine = require('../src/services/soar/recommendationEngine');
const soarAnalyticsService = require('../src/services/soar/soarAnalyticsService');
const knowledgeBaseService = require('../src/services/soar/knowledgeBaseService');
const soarDashboardService = require('../src/services/soar/soarDashboardService');

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

async function runSoarThreatIntelligenceSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint B Phase 4: SOAR Threat Intelligence Automation Tests');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;

  let orgA;
  let orgB;
  let adminA;
  let seniorAnalystA;
  let analystA;
  let employeeA;
  let adminB;

  let tokenAdminA;
  let tokenSeniorAnalystA;
  let tokenAnalystA;
  let tokenEmployeeA;
  let tokenAdminB;

  try {
    // 1. Setup Test Server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    // 2. Setup Fixtures
    orgA = await createOrganizationFixture({ name: `SOAR Phase 4 Org A ${Date.now()}` });
    orgB = await createOrganizationFixture({ name: `SOAR Phase 4 Org B ${Date.now()}` });

    adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    seniorAnalystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });
    adminB = await createUserFixture({ organization_id: orgB.id, role: 'admin' });

    tokenAdminA = createToken(adminA, 'admin');
    tokenSeniorAnalystA = createToken(seniorAnalystA, 'senior_analyst');
    tokenAnalystA = createToken(analystA, 'analyst');
    tokenEmployeeA = createToken(employeeA, 'employee');
    tokenAdminB = createToken(adminB, 'admin');

    // Fixture Data for Testing
    let testCaseA;
    let testAlertA;
    let testPlaybookA;

    testCaseA = await SoarCase.create({
      organization_id: orgA.id,
      title: 'Active Cobalt Strike Beaconing in DMZ',
      description: 'C2 beacon traffic detected from web server 192.168.1.50',
      severity: 'critical',
      priority: 'high',
      created_by: adminA.id
    });

    testAlertA = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Outbound C2 Connection to 185.220.101.5',
      severity: 'critical',
      status: 'new',
      mitre_technique: 'T1071.001',
      metadata: {
        source_ip: '192.168.1.50',
        destination_ip: '185.220.101.5',
        domain: 'malicious-c2-node.xyz',
        file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      }
    });

    testPlaybookA = await SoarPlaybook.create({
      organization_id: orgA.id,
      name: 'Automated Malware Containment Playbook',
      description: 'Quarantines host and blocks associated IP IOCs',
      enabled: true,
      trigger_type: 'alert',
      steps: [
        {
          step_order: 1,
          action_type: 'block_ip',
          action_config: { ip: '185.220.101.5' },
          requires_approval: false
        },
        {
          step_order: 2,
          action_type: 'isolate_endpoint',
          action_config: { host: 'dmz-web-01' },
          requires_approval: false
        }
      ],
      created_by: adminA.id
    });

    // =========================================================================
    // GROUP 1: IOC Response Automation (Tests 1–11)
    // =========================================================================
    console.log('--- Group 1: IOC Response Automation (IP, Domain, Hash) ---');

    await testAsync('1.1 Malicious IP IOC: Automatic firewall block recommendation generated', async () => {
      const res = await iocResponseAutomationService.automateIpResponse({
        organization_id: orgA.id,
        ioc_value: '198.51.100.99',
        case_id: testCaseA.id,
        threat_actor: 'APT29',
        confidence: 90
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.ioc_type, 'ip');
      assert.ok(res.recommendation);
      assert.strictEqual(res.recommendation.action_type, 'block_ip');
      assert.strictEqual(res.recommendation.action_payload.ip, '198.51.100.99');
      assert.ok(res.recommendation.confidence_score >= 80);
    });

    await testAsync('1.2 Malicious IP IOC: Threat severity scoring calculated accurately', async () => {
      const res = await iocResponseAutomationService.automateIpResponse({
        organization_id: orgA.id,
        ioc_value: '198.51.100.100',
        threat_actor: 'FIN7',
        confidence: 95
      });

      assert.strictEqual(res.success, true);
      assert.ok(res.severity_score >= 85);
      assert.strictEqual(res.severity_category, 'critical');
    });

    await testAsync('1.3 Malicious IP IOC: Historical sighting tracking recorded in database', async () => {
      const res = await iocResponseAutomationService.automateIpResponse({
        organization_id: orgA.id,
        ioc_value: '198.51.100.101',
        confidence: 80
      });

      assert.strictEqual(res.success, true);
      assert.ok(res.sightings_count >= 1);
      assert.ok(Array.isArray(res.sightings));
    });

    await testAsync('1.4 Malicious IP IOC: Case linkage attaches IOC to SOAR case', async () => {
      const res = await iocResponseAutomationService.automateIpResponse({
        organization_id: orgA.id,
        ioc_value: '198.51.100.102',
        case_id: testCaseA.id
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.case_id, testCaseA.id);

      const updatedCase = await SoarCase.findById(testCaseA.id, orgA.id);
      assert.ok(updatedCase.ioc_ids.includes(res.ioc.id));
    });

    await testAsync('1.5 Malicious Domain IOC: DNS sinkhole recommendation generated', async () => {
      const res = await iocResponseAutomationService.automateDomainResponse({
        organization_id: orgA.id,
        ioc_value: 'evil-c2-node.net',
        confidence: 85
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.ioc_type, 'domain');
      assert.ok(res.recommendation);
      assert.strictEqual(res.recommendation.action_type, 'dns_sinkhole');
      assert.strictEqual(res.recommendation.action_payload.domain, 'evil-c2-node.net');
    });

    await testAsync('1.6 Malicious Domain IOC: Domain reputation tracking computed', async () => {
      const res = await iocResponseAutomationService.automateDomainResponse({
        organization_id: orgA.id,
        ioc_value: 'phishing-login-portal.org',
        confidence: 90
      });

      assert.strictEqual(res.success, true);
      assert.ok(res.reputation);
      assert.strictEqual(res.reputation.domain, 'phishing-login-portal.org');
      assert.strictEqual(res.reputation.threat_level, 'HIGH_RISK');
    });

    await testAsync('1.7 Malicious Domain IOC: Related incident correlation identified', async () => {
      const res = await iocResponseAutomationService.automateDomainResponse({
        organization_id: orgA.id,
        ioc_value: 'malicious-c2-node.xyz',
        confidence: 85
      });

      assert.strictEqual(res.success, true);
      assert.ok(Array.isArray(res.related_incidents));
      assert.ok(res.related_incidents.some(inc => inc.id === testAlertA.id));
    });

    await testAsync('1.8 Malicious Hash IOC: Endpoint quarantine recommendation generated', async () => {
      const res = await iocResponseAutomationService.automateHashResponse({
        organization_id: orgA.id,
        ioc_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        malware_family: 'LockBit'
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.ioc_type, 'sha256');
      assert.ok(res.recommendation);
      assert.strictEqual(res.recommendation.action_type, 'isolate_endpoint');
      assert.strictEqual(res.recommendation.action_payload.malware_family, 'LockBit');
    });

    await testAsync('1.9 Malicious Hash IOC: Malware family tracking persisted', async () => {
      const res = await iocResponseAutomationService.automateHashResponse({
        organization_id: orgA.id,
        ioc_value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        malware_family: 'BlackCat'
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.malware_family, 'BlackCat');
      assert.strictEqual(res.ioc.malware_family, 'BlackCat');
    });

    await testAsync('1.10 Malicious Hash IOC: Related IOC clustering identifies family cluster', async () => {
      // Create a second hash in same malware family to test clustering
      await ThreatIOC.upsertIOC({
        organization_id: orgA.id,
        ioc_type: 'sha256',
        ioc_value: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
        malware_family: 'BlackCat',
        risk_score: 90
      });

      const res = await iocResponseAutomationService.automateHashResponse({
        organization_id: orgA.id,
        ioc_value: '222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111',
        malware_family: 'BlackCat'
      });

      assert.strictEqual(res.success, true);
      assert.ok(Array.isArray(res.related_cluster));
      assert.ok(res.related_cluster.length > 0);
    });

    await testAsync('1.11 API POST /api/v1/soar/ioc/automate executes automation endpoint', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/ioc/automate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          ioc_type: 'ip',
          ioc_value: '198.51.100.222',
          confidence: 88
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.ioc_type, 'ip');
      assert.ok(data.data.recommendation);
    });

    // =========================================================================
    // GROUP 2: Threat Intel Enrichment Pipeline (Tests 12–19)
    // =========================================================================
    console.log('\n--- Group 2: Threat Intel Enrichment Pipeline ---');

    await testAsync('2.1 Enrich Alert: IOC intelligence matched and attached', async () => {
      // Seed matching IOC for destination_ip
      await ThreatIOC.upsertIOC({
        organization_id: orgA.id,
        ioc_type: 'ip',
        ioc_value: '185.220.101.5',
        confidence: 92,
        risk_score: 95,
        threat_actor: 'Sandworm',
        malware_family: 'Industroyer'
      });

      const res = await threatEnrichmentService.enrichAlert(testAlertA.id, orgA.id);
      assert.strictEqual(res.alert_id, testAlertA.id);
      assert.ok(res.enrichment);
      assert.ok(Array.isArray(res.enrichment.matched_iocs));
      assert.ok(res.enrichment.matched_iocs.some(i => i.value === '185.220.101.5'));
    });

    await testAsync('2.2 Enrich Alert: Reputation data and verdict attached', async () => {
      const res = await threatEnrichmentService.enrichAlert(testAlertA.id, orgA.id);
      assert.ok(res.enrichment.reputation);
      assert.strictEqual(res.enrichment.reputation.highest_risk_score, 95);
      assert.strictEqual(res.enrichment.reputation.reputation_verdict, 'MALICIOUS');
      assert.ok(res.enrichment.reputation.threat_actors.includes('Sandworm'));
    });

    await testAsync('2.3 Enrich Alert: Related incidents correlated by MITRE technique', async () => {
      // Seed a second alert with same MITRE technique T1071.001
      const alert2 = await SiemAlert.create({
        organization_id: orgA.id,
        title: 'Secondary C2 Beacon to External Gateway',
        severity: 'high',
        mitre_technique: 'T1071.001'
      });

      const res = await threatEnrichmentService.enrichAlert(testAlertA.id, orgA.id);
      assert.ok(Array.isArray(res.enrichment.related_incidents));
      assert.ok(res.enrichment.related_incidents.some(i => i.id === alert2.id));
    });

    await testAsync('2.4 Enrich Alert: Related cases correlated', async () => {
      // Link testAlertA to testCaseA
      await db.query(
        `UPDATE public.soar_cases SET alert_id = $1 WHERE id = $2;`,
        [testAlertA.id, testCaseA.id]
      );

      const res = await threatEnrichmentService.enrichAlert(testAlertA.id, orgA.id);
      assert.ok(Array.isArray(res.enrichment.related_cases));
      assert.ok(res.enrichment.related_cases.some(c => c.id === testCaseA.id));
    });

    await testAsync('2.5 Enrich Alert: Previous detections count computed', async () => {
      const res = await threatEnrichmentService.enrichAlert(testAlertA.id, orgA.id);
      assert.ok(res.enrichment.previous_detections >= 1);
    });

    await testAsync('2.6 API POST /api/v1/soar/enrich/alert/:id updates alert metadata', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/enrich/alert/${testAlertA.id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.data.enrichment.reputation);

      // Verify DB record updated
      const alertDb = await SiemAlert.findById(testAlertA.id, orgA.id);
      assert.ok(alertDb.metadata.enrichment);
    });

    await testAsync('2.7 Enrich Case: Linked IOCs, similar attacks, and threat actors attached', async () => {
      const res = await threatEnrichmentService.enrichCase(testCaseA.id, orgA.id);
      assert.strictEqual(res.case_id, testCaseA.id);
      assert.ok(res.findings);
      assert.ok(Array.isArray(res.findings.linked_iocs));
      assert.ok(Array.isArray(res.findings.threat_actors));
      assert.ok(Array.isArray(res.findings.similar_attacks));
      assert.ok(res.findings.risk_assessment);
    });

    await testAsync('2.8 API POST /api/v1/soar/enrich/case/:id updates case findings in DB', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/enrich/case/${testCaseA.id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.data.findings.risk_assessment);

      const caseDb = await SoarCase.findById(testCaseA.id, orgA.id);
      assert.ok(caseDb.threat_intel_findings.risk_assessment);
    });

    // =========================================================================
    // GROUP 3: Automated Response Recommendations (Tests 20–25)
    // =========================================================================
    console.log('\n--- Group 3: Automated Response Recommendations ---');

    let createdRecId;

    await testAsync('3.1 Generate recommendations based on alert severity and MITRE techniques', async () => {
      const recs = await recommendationEngine.generateRecommendations({
        organization_id: orgA.id,
        alert_id: testAlertA.id,
        case_id: testCaseA.id,
        alert_severity: 'critical',
        mitre_techniques: ['T1071.001', 'T1486'],
        ioc_risk_score: 90,
        context: {
          ip: '198.51.100.55',
          host: 'srv-db-prod-01'
        }
      });

      assert.ok(Array.isArray(recs));
      assert.ok(recs.length >= 3);
      createdRecId = recs[0].id;
    });

    await testAsync('3.2 Recommendation confidence score computed accurately', async () => {
      const rec = await SoarResponseRecommendation.findById(createdRecId, orgA.id);
      assert.ok(rec);
      assert.ok(Number(rec.confidence_score) >= 70 && Number(rec.confidence_score) <= 100);
      assert.ok(rec.rationale.length > 10);
    });

    await testAsync('3.3 Multi-action recommendations cover perimeter, host, and ticketing', async () => {
      const recs = await SoarResponseRecommendation.findMany({
        organization_id: orgA.id,
        alert_id: testAlertA.id
      });

      const actionTypes = recs.map(r => r.action_type);
      assert.ok(actionTypes.includes('block_ip'));
      assert.ok(actionTypes.includes('isolate_endpoint'));
      assert.ok(actionTypes.includes('create_ticket'));
      assert.ok(actionTypes.includes('escalate_approval'));
    });

    await testAsync('3.4 API GET /api/v1/soar/recommendations lists recommendations', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/recommendations?status=pending`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.data));
      assert.ok(data.data.length > 0);
    });

    await testAsync('3.5 API POST /api/v1/soar/recommendations/:id/apply executes action & updates status', async () => {
      // Find a block_ip recommendation to apply
      const recs = await SoarResponseRecommendation.findMany({
        organization_id: orgA.id,
        action_type: 'block_ip',
        status: 'pending'
      });
      assert.ok(recs.length > 0);
      const targetRec = recs[0];

      const res = await fetch(`${baseUrl}/api/v1/soar/recommendations/${targetRec.id}/apply`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenSeniorAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.recommendation.status, 'applied');
      assert.ok(data.data.recommendation.applied_at);
      assert.ok(data.data.execution_result);
      assert.strictEqual(data.data.execution_result.action, 'block_ip');
    });

    await testAsync('3.6 API POST /api/v1/soar/recommendations/:id/dismiss dismisses recommendation with reason', async () => {
      const recs = await SoarResponseRecommendation.findMany({
        organization_id: orgA.id,
        status: 'pending'
      });
      assert.ok(recs.length > 0);
      const targetRec = recs[0];

      const res = await fetch(`${baseUrl}/api/v1/soar/recommendations/${targetRec.id}/dismiss`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ reason: 'Known internal penetration test exercise' })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.status, 'dismissed');
      assert.strictEqual(data.data.dismissed_reason, 'Known internal penetration test exercise');
    });

    // =========================================================================
    // GROUP 4: Playbook Effectiveness Analytics (Tests 26–32)
    // =========================================================================
    console.log('\n--- Group 4: Playbook Effectiveness Analytics ---');

    await testAsync('4.1 Track per-playbook success rate & failure rate', async () => {
      // Create completed & failed executions for testPlaybookA
      await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: testPlaybookA.id,
        status: 'completed',
        started_at: new Date(Date.now() - 5000),
        completed_at: new Date()
      });
      await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: testPlaybookA.id,
        status: 'completed',
        started_at: new Date(Date.now() - 4000),
        completed_at: new Date()
      });

      const metrics = await soarAnalyticsService.getPlaybookEffectiveness(testPlaybookA.id, orgA.id);
      assert.strictEqual(metrics.playbook_id, testPlaybookA.id);
      assert.ok(metrics.total_executions >= 2);
      assert.ok(metrics.success_rate >= 80);
      assert.strictEqual(metrics.failure_rate, 0);
    });

    await testAsync('4.2 Track per-playbook average execution time in milliseconds', async () => {
      const metrics = await soarAnalyticsService.getPlaybookEffectiveness(testPlaybookA.id, orgA.id);
      assert.ok(typeof metrics.average_execution_time_ms === 'number');
      assert.ok(metrics.average_execution_time_ms >= 0);
    });

    await testAsync('4.3 Track per-playbook approval bottlenecks', async () => {
      const metrics = await soarAnalyticsService.getPlaybookEffectiveness(testPlaybookA.id, orgA.id);
      assert.ok(metrics.approval_bottlenecks);
      assert.ok(typeof metrics.approval_bottlenecks.total_approvals === 'number');
      assert.ok(typeof metrics.approval_bottlenecks.average_approval_wait_ms === 'number');
    });

    await testAsync('4.4 Track per-playbook retry frequency', async () => {
      const metrics = await soarAnalyticsService.getPlaybookEffectiveness(testPlaybookA.id, orgA.id);
      assert.ok(typeof metrics.retry_frequency === 'number');
      assert.ok(typeof metrics.total_retries === 'number');
    });

    await testAsync('4.5 Track per-action execution frequency, failure rate, and mean duration', async () => {
      const actions = await soarAnalyticsService.getActionEffectiveness(orgA.id);
      assert.ok(Array.isArray(actions));
      if (actions.length > 0) {
        const action = actions[0];
        assert.ok(action.action_type);
        assert.ok(typeof action.execution_frequency === 'number');
        assert.ok(typeof action.failure_rate === 'number');
        assert.ok(typeof action.mean_completion_time_ms === 'number');
      }
    });

    await testAsync('4.6 Track organization metrics: Top performing playbooks', async () => {
      const orgMetrics = await soarAnalyticsService.getOrganizationMetrics(orgA.id);
      assert.ok(Array.isArray(orgMetrics.top_performing_playbooks));
      assert.ok(orgMetrics.top_performing_playbooks.length > 0);
      assert.ok(orgMetrics.top_performing_playbooks.some(p => p.playbook_id === testPlaybookA.id));
    });

    await testAsync('4.7 Track organization metrics: MTTR improvement trend comparison', async () => {
      const orgMetrics = await soarAnalyticsService.getOrganizationMetrics(orgA.id);
      assert.ok(orgMetrics.mttr_improvement_trends);
      assert.ok(orgMetrics.mttr_improvement_trends.baseline_mttr_minutes > 0);
      assert.ok(orgMetrics.mttr_improvement_trends.automated_mttr_minutes > 0);
      assert.ok(typeof orgMetrics.mttr_improvement_trends.improvement_percentage === 'number');
    });

    // =========================================================================
    // GROUP 5: Response Knowledge Base (Tests 33–39)
    // =========================================================================
    console.log('\n--- Group 5: Response Knowledge Base ---');

    let createdKbId;

    await testAsync('5.1 Create knowledge base article with procedures, notes, MITRE mappings, tags', async () => {
      const article = await knowledgeBaseService.createArticle({
        organization_id: orgA.id,
        title: 'Ransomware Containment & Key Isolation Standard Procedure',
        summary: 'Standard operating procedure for rapid containment of ransomware outbreaks.',
        procedures: [
          { step: 1, action: 'Sever WAN connectivity on infected subnet' },
          { step: 2, action: 'Extract memory dump and preserve shadow copies' },
          { step: 3, action: 'Disable affected service accounts across Active Directory' }
        ],
        investigation_notes: 'Ransomware typically drops .lock extension and deletes VSS shadow copies.',
        resolution_summary: 'Quarantine host, restore clean snapshot from immutable backup.',
        lessons_learned: 'Enforce MFA on local admin accounts and disable SMBv1 across perimeter.',
        mitre_mappings: ['T1486', 'T1059'],
        tags: ['ransomware', 'containment', 'sop', 'critical'],
        created_by: adminA.id
      });

      assert.ok(article.id);
      assert.strictEqual(article.title, 'Ransomware Containment & Key Isolation Standard Procedure');
      assert.strictEqual(article.procedures.length, 3);
      createdKbId = article.id;
    });

    await testAsync('5.2 List and keyword search articles by query', async () => {
      const articles = await knowledgeBaseService.listArticles(orgA.id, { search: 'Ransomware' });
      assert.ok(articles.length > 0);
      assert.ok(articles.some(a => a.id === createdKbId));
    });

    await testAsync('5.3 Filter knowledge base articles by tag and MITRE technique', async () => {
      const byTag = await knowledgeBaseService.listArticles(orgA.id, { tag: 'ransomware' });
      assert.ok(byTag.length > 0);

      const byMitre = await knowledgeBaseService.listArticles(orgA.id, { mitre: 'T1486' });
      assert.ok(byMitre.length > 0);
    });

    await testAsync('5.4 Update knowledge base article resolution summary', async () => {
      const updated = await knowledgeBaseService.updateArticle(createdKbId, orgA.id, {
        resolution_summary: 'Updated: Host quarantined, network isolated, immutable backup restored.'
      }, adminA.id);

      assert.strictEqual(updated.id, createdKbId);
      assert.ok(updated.resolution_summary.includes('Updated: Host quarantined'));
    });

    await testAsync('5.5 Link case to knowledge base article', async () => {
      const linked = await knowledgeBaseService.linkCase(createdKbId, orgA.id, testCaseA.id);
      assert.ok(linked.linked_case_ids.includes(testCaseA.id));
    });

    await testAsync('5.6 Link playbook to knowledge base article', async () => {
      const linked = await knowledgeBaseService.linkPlaybook(createdKbId, orgA.id, testPlaybookA.id);
      assert.ok(linked.linked_playbook_ids.includes(testPlaybookA.id));
    });

    await testAsync('5.7 Delete knowledge base article via API', async () => {
      // Create a temporary article to delete
      const tempArt = await knowledgeBaseService.createArticle({
        organization_id: orgA.id,
        title: 'Temporary Outdated Procedure',
        created_by: adminA.id
      });

      const res = await fetch(`${baseUrl}/api/v1/soar/knowledge-base/${tempArt.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);

      const check = await knowledgeBaseService.getArticleById(tempArt.id, orgA.id);
      assert.strictEqual(check, null);
    });

    // =========================================================================
    // GROUP 6: SOAR Dashboard APIs (Tests 40–42)
    // =========================================================================
    console.log('\n--- Group 6: SOAR Dashboard APIs ---');

    await testAsync('6.1 Executive Dashboard: cases resolved, responses executed, mean response time, threat categories', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/dashboard/executive`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(typeof data.data.cases_resolved === 'number');
      assert.ok(typeof data.data.responses_executed === 'number');
      assert.ok(typeof data.data.mean_response_time_ms === 'number');
      assert.ok(typeof data.data.hours_saved_estimate === 'number');
      assert.ok(Array.isArray(data.data.threat_categories));
    });

    await testAsync('6.2 Analyst Dashboard: active cases, pending approvals, recommended actions, response queue', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/dashboard/analyst`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(typeof data.data.active_cases_count === 'number');
      assert.ok(typeof data.data.pending_approvals_count === 'number');
      assert.ok(typeof data.data.recommended_actions_count === 'number');
      assert.ok(typeof data.data.response_queue_count === 'number');
      assert.ok(Array.isArray(data.data.recommended_actions));
    });

    await testAsync('6.3 Engineering Dashboard: playbook health, connector health, failed executions, recovery stats', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/dashboard/engineering`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.data.playbook_health));
      assert.ok(Array.isArray(data.data.connector_health));
      assert.ok(Array.isArray(data.data.failed_executions));
      assert.ok(data.data.recovery_statistics);
      assert.ok(typeof data.data.recovery_statistics.recovery_success_rate === 'number');
    });

    // =========================================================================
    // GROUP 7: Security, Tenant Isolation, RBAC & Audit Trails (Tests 43–45)
    // =========================================================================
    console.log('\n--- Group 7: Security, Tenant Isolation, RBAC & Audit Trails ---');

    await testAsync('7.1 Multi-Tenant Isolation: Tenant B cannot access Tenant A recommendations or KB', async () => {
      // Tenant B requests Tenant A's KB article
      const resKb = await fetch(`${baseUrl}/api/v1/soar/knowledge-base/${createdKbId}`, {
        headers: { Authorization: `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(resKb.status, 404);

      // Tenant B requests Tenant A's recommendation
      const resRec = await fetch(`${baseUrl}/api/v1/soar/recommendations/${createdRecId}/apply`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(resRec.status, 404);
    });

    await testAsync('7.2 RBAC: Analyst role cannot delete knowledge base article (admin only)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/knowledge-base/${createdKbId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    await testAsync('7.3 Audit Trails: Phase 4 audit actions recorded in audit_logs table', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type FROM public.audit_logs
         WHERE organization_id = $1
         ORDER BY created_at DESC
         LIMIT 50;`,
        [orgA.id]
      );

      assert.ok(auditRes.rows.length > 0);
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(
        actions.includes('SOAR_IOC_AUTOMATION_TRIGGERED') ||
        actions.includes('SOAR_ALERT_ENRICHED') ||
        actions.includes('SOAR_CASE_ENRICHED') ||
        actions.includes('SOAR_RECOMMENDATION_GENERATED') ||
        actions.includes('SOAR_KNOWLEDGE_BASE_CREATED') ||
        actions.includes('SOAR_DASHBOARD_VIEWED')
      );
    });

  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
    // Cleanup test fixtures
    await cleanupFixtures().catch(() => {});
    if (db.pool && typeof db.pool.end === 'function') {
      await db.pool.end().catch(() => {});
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSoarThreatIntelligenceSuite().catch((err) => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
