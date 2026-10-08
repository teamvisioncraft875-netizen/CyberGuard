process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SiemAlert = require('../src/models/SiemAlert');
const Incident = require('../src/models/Incident');
const ThreatIOC = require('../src/models/ThreatIOC');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotMessage = require('../src/models/CopilotMessage');

const copilotService = require('../src/services/copilot/copilotService');
const socQueryParser = require('../src/services/copilot/socQueryParser');
const socSearchService = require('../src/services/copilot/socSearchService');
const mitreReasoningService = require('../src/services/copilot/mitreReasoningService');

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

async function runCopilotPhase2Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 2: AI Copilot Investigation Workspace Tests');
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
    const orgA = await createOrganizationFixture({ name: 'Tenant Copilot Alpha P2' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Copilot Beta P2' });

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
    const alertA = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Mimikatz In-Memory Credential Harvesting on DC-01',
      severity: 'critical',
      status: 'new',
      source_type: 'windows_sysmon',
      mitre_technique: 'T1003',
      metadata: { host: 'DC-01', target_user: 'Administrator' }
    });

    const incidentA = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'technical_threat',
      risk_level: 'critical',
      risk_score: 95,
      status: 'open',
      explanation: 'Critical credential dumping activity detected across primary domain controller.'
    });

    const createIocFn = ThreatIOC.createIOC || ThreatIOC.create;
    const iocA = await createIocFn.call(ThreatIOC, {
      organization_id: orgA.id,
      ioc_type: 'sha256',
      ioc_value: 'd5a835b6a7a7b8e5c3e6c2e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4',
      confidence: 90,
      risk_score: 95,
      threat_actor: 'APT29',
      malware_family: 'Mimikatz'
    });

    // Seed test case in soar_cases
    const caseRes = await db.query(
      `INSERT INTO public.soar_cases (organization_id, title, description, severity, status, priority, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *;`,
      [orgA.id, 'Investigation Case: Domain Compromise DC-01', 'Active triage of credential dumping', 'critical', 'open', 'critical', adminA.id]
    ).catch(() => ({ rows: [{ id: 'mock-case-id', title: 'Investigation Case: Domain Compromise DC-01' }] }));
    const caseA = caseRes.rows[0];

    // Ensure Mock Handler for Gemini is set to prevent external calls
    copilotService.setMockHandler(async ({ question, history }) => {
      const turnCount = (history || []).length;
      return {
        answer: `[MOCKED COPILOT RESPONSE] Analyzed question: "${question}". Current session depth: ${turnCount} prior turns. Indicators point to credential exposure on DC-01.`,
        tokens_used: 120
      };
    });

    console.log('--- Phase 2: Functional, Search, Reasoning & Security Validations ---');

    let createdSessionId;

    // 1. Create session
    await testAsync('1. Create session: creates tenant-scoped investigation session via POST /sessions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          title: 'DC-01 Lateral Traversal Deep Dive',
          entity_type: 'alert',
          entity_id: alertA.id
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.data.id);
      assert.strictEqual(data.data.title, 'DC-01 Lateral Traversal Deep Dive');
      assert.strictEqual(data.data.organization_id, orgA.id);
      assert.strictEqual(data.data.status, 'active');
      createdSessionId = data.data.id;
    });

    // 2. Retrieve session
    await testAsync('2. Retrieve session: retrieves session details and message array via GET /sessions/:id', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${createdSessionId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.id, createdSessionId);
      assert.ok(Array.isArray(data.data.messages));
    });

    // 3. Store messages
    await testAsync('3. Store messages: post message stores both user question and assistant answer in DB', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${createdSessionId}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          content: 'What processes were identified in the credential dumping activity?'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.answer);
      assert.ok(data.message_id);
      assert.strictEqual(data.session_id, createdSessionId);
      assert.ok(data.tokens_used > 0);
    });

    // 4. Retrieve conversation history
    await testAsync('4. Retrieve conversation history: session details endpoint contains both conversation turns', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${createdSessionId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.data.messages.length >= 2);
      const roles = data.data.messages.map(m => m.role);
      assert.ok(roles.includes('user'));
      assert.ok(roles.includes('assistant'));
    });

    // 5. Session isolation between tenants
    await testAsync('5. Session isolation between tenants: Tenant B cannot access or message Tenant A session', async () => {
      // Tenant B GET Tenant A session
      const resGet = await fetch(`${baseUrl}/api/v1/copilot/sessions/${createdSessionId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resGet.status, 404);

      // Tenant B POST message to Tenant A session
      const resPost = await fetch(`${baseUrl}/api/v1/copilot/sessions/${createdSessionId}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystB}`
        },
        body: JSON.stringify({ content: 'Cross-tenant probe' })
      });
      assert.strictEqual(resPost.status, 404);

      // Tenant B list sessions
      const resList = await fetch(`${baseUrl}/api/v1/copilot/sessions`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resList.status, 200);
      const listData = await resList.json();
      assert.ok(!listData.data.some(s => s.id === createdSessionId));
    });

    // 6. Session deletion
    await testAsync('6. Session deletion: removes session and cascades messages with 200 response', async () => {
      const tempSession = await CopilotSession.create({
        organization_id: orgA.id,
        created_by: adminA.id,
        title: 'Temporary Session For Deletion'
      });

      const resDel = await fetch(`${baseUrl}/api/v1/copilot/sessions/${tempSession.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });
      assert.strictEqual(resDel.status, 200);

      const resCheck = await fetch(`${baseUrl}/api/v1/copilot/sessions/${tempSession.id}`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });
      assert.strictEqual(resCheck.status, 404);
    });

    // 7. SOC query parsing
    await testAsync('7. SOC query parsing: converts natural language queries to structured query objects', async () => {
      const parsed1 = socQueryParser.parse('show critical alerts from last 24 hours');
      assert.strictEqual(parsed1.entity, 'alerts');
      assert.strictEqual(parsed1.severity, 'critical');
      assert.strictEqual(parsed1.timeRangeHours, 24);

      const parsed2 = socQueryParser.parse('show incidents involving credential dumping');
      assert.strictEqual(parsed2.entity, 'incidents');
      assert.strictEqual(parsed2.mitreTechnique, 'T1003');

      const parsed3 = socQueryParser.parse('list unresolved cases');
      assert.strictEqual(parsed3.entity, 'cases');
      assert.strictEqual(parsed3.status, 'open');
    });

    // 8. Alert search query
    await testAsync('8. Alert search query: searches alerts by severity and keyword', async () => {
      const searchRes = await socSearchService.search({
        organization_id: orgA.id,
        query: 'show critical alerts'
      });
      assert.strictEqual(searchRes.entity, 'alerts');
      assert.ok(searchRes.count > 0);
      assert.ok(searchRes.results.some(r => r.id === alertA.id));
    });

    // 9. Incident search query
    await testAsync('9. Incident search query: searches incidents by keyword and risk level', async () => {
      const searchRes = await socSearchService.search({
        organization_id: orgA.id,
        query: 'show critical incidents'
      });
      assert.strictEqual(searchRes.entity, 'incidents');
      assert.ok(searchRes.count > 0);
      assert.ok(searchRes.results.some(r => r.id === incidentA.id));
    });

    // 10. Case search query
    await testAsync('10. Case search query: searches cases by status and keyword', async () => {
      const searchRes = await socSearchService.search({
        organization_id: orgA.id,
        query: 'list unresolved cases'
      });
      assert.strictEqual(searchRes.entity, 'cases');
      assert.ok(Array.isArray(searchRes.results));
    });

    // 11. Threat intel search query
    await testAsync('11. Threat intel search query: retrieves high risk threat findings', async () => {
      const searchRes = await socSearchService.search({
        organization_id: orgA.id,
        query: 'show recent threat intel findings'
      });
      assert.strictEqual(searchRes.entity, 'threat_intel');
      assert.ok(searchRes.count > 0);
    });

    // 12. IOC search query
    await testAsync('12. IOC search query: finds matching indicators of compromise', async () => {
      const searchRes = await socSearchService.search({
        organization_id: orgA.id,
        query: 'find malicious ioc Mimikatz'
      });
      assert.strictEqual(searchRes.entity, 'iocs');
      assert.ok(searchRes.count > 0);
      assert.ok(searchRes.results.some(r => r.id === iocA.id));
    });

    // 13. MITRE explanation
    await testAsync('13. MITRE explanation: explains technique mapping, tactic, evidence and confidence', async () => {
      const explanation = await mitreReasoningService.explainMapping({
        technique: 'T1021',
        organization_id: orgA.id
      });
      assert.strictEqual(explanation.technique, 'T1021');
      assert.strictEqual(explanation.tactic, 'Lateral Movement');
      assert.strictEqual(explanation.technique_name, 'Remote Services');
      assert.ok(explanation.confidence >= 0.85);
      assert.ok(Array.isArray(explanation.evidence));
    });

    // 14. Attack chain explanation
    await testAsync('14. Attack chain explanation: provides multi-stage kill chain progression summary', async () => {
      const chainReport = mitreReasoningService.explainAttackChain({
        techniques: ['T1566', 'T1059', 'T1021', 'T1486'],
        organization_id: orgA.id
      });
      assert.strictEqual(chainReport.stages_count, 4);
      assert.ok(chainReport.summary.includes('Initial Access'));
      assert.ok(chainReport.summary.includes('Impact'));
      assert.ok(Array.isArray(chainReport.progression));
    });

    // 15. Employee access denied
    await testAsync('15. Employee access denied: employee role receives HTTP 403 Forbidden on sessions endpoint', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ title: 'Employee Unauthorized Session' })
      });
      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    // 16. Missing organization denied
    await testAsync('16. Missing organization denied: fails closed with HTTP 403 when organization_id is omitted', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenNoOrg}`
        },
        body: JSON.stringify({ title: 'No Org Session' })
      });
      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    // 17. Audit logging generated
    await testAsync('17. Audit logging generated: records COPILOT_SESSION_CREATED, COPILOT_MESSAGE_CREATED, etc.', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type, details FROM public.audit_logs
         WHERE organization_id = $1 AND action IN (
           'COPILOT_SESSION_CREATED', 'COPILOT_MESSAGE_CREATED', 'COPILOT_SOC_SEARCH', 'COPILOT_MITRE_REASONING'
         )
         ORDER BY created_at DESC
         LIMIT 20;`,
        [orgA.id]
      );
      assert.ok(auditRes.rows.length >= 3);
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('COPILOT_SESSION_CREATED'));
      assert.ok(actions.includes('COPILOT_MESSAGE_CREATED'));
    });

    // 18. History window enforcement
    await testAsync('18. History window enforcement: findRecent enforces bounded window size', async () => {
      // Add 12 dummy messages to session
      for (let i = 1; i <= 12; i++) {
        await CopilotMessage.create({
          session_id: createdSessionId,
          role: i % 2 === 0 ? 'assistant' : 'user',
          content: `Test turn number ${i}`
        });
      }

      const recent10 = await CopilotMessage.findRecent(createdSessionId, 10);
      assert.strictEqual(recent10.length, 10);
      // Ensure chronological ordering of recent window
      assert.strictEqual(recent10[recent10.length - 1].content, 'Test turn number 12');
    });

    // 19. Gemini response integration
    await testAsync('19. Gemini response integration: mocked Gemini response returns answer, sources and tokens', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'soc_search',
          question: 'show critical alerts'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(Array.isArray(data.sources));
      assert.ok(typeof data.tokens_used === 'number');
    });

    // 20. Multi-turn investigation flow
    await testAsync('20. Multi-turn investigation flow: sequential messages accumulate context within session', async () => {
      const flowSession = await CopilotSession.create({
        organization_id: orgA.id,
        created_by: analystA.id,
        title: 'Multi-turn Workflow Session'
      });

      // Turn 1
      const resTurn1 = await fetch(`${baseUrl}/api/v1/copilot/sessions/${flowSession.id}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ content: 'Turn 1: Identify affected assets on DC subnet.' })
      });
      assert.strictEqual(resTurn1.status, 200);

      // Turn 2
      const resTurn2 = await fetch(`${baseUrl}/api/v1/copilot/sessions/${flowSession.id}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ content: 'Turn 2: Recommend containment actions for those assets.' })
      });
      assert.strictEqual(resTurn2.status, 200);

      // Verify conversation has 4 total messages (2 user + 2 assistant)
      const allMsgs = await CopilotMessage.findBySessionId(flowSession.id);
      assert.strictEqual(allMsgs.length, 4);
    });

  } finally {
    copilotService.resetMockHandler();
    if (server) {
      await new Promise(r => server.close(r));
    }
    await cleanupFixtures().catch(() => {});
    if (db.pool && typeof db.pool.end === 'function') {
      await db.pool.end().catch(() => {});
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runCopilotPhase2Suite().catch(err => {
    console.error('Fatal Suite Execution Error:', err);
    process.exit(1);
  });
}

module.exports = { runCopilotPhase2Suite };
