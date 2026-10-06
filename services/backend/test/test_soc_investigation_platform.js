process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const Incident = require('../src/models/Incident');
const IncidentNote = require('../src/models/IncidentNote');
const IncidentRecommendation = require('../src/models/IncidentRecommendation');
const AttackChainSnapshot = require('../src/models/AttackChainSnapshot');

const riskScoringService = require('../src/services/riskScoringService');
const incidentPrioritizationService = require('../src/services/incidentPrioritizationService');
const recommendationEngine = require('../src/services/recommendationEngine');
const investigationWorkspaceService = require('../src/services/investigationWorkspaceService');
const dashboardAggregationService = require('../src/services/dashboardAggregationService');
const commandCenterService = require('../src/services/commandCenterService');
const incidentWorkflowService = require('../src/services/incidentWorkflowService');

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

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      organization_id: user.organization_id || null
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Master Phase: SOC Investigation & Response Platform Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgAId = null;
  let testOrgBId = null;
  let testAdminA = null;
  let testAnalystA = null;
  let testAnalystB = null;
  let testEmployeeA = null;

  let tokenAdminA = null;
  let tokenAnalystA = null;
  let tokenAnalystB = null;
  let tokenEmployeeA = null;

  const createdIncidentIds = [];
  const createdOrgIds = [];
  const createdUserIds = [];

  try {
    // 0. Start ephemeral HTTP server for API controller tests
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // Setup Test Organizations & Users
    const orgARes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test SOC Org A ${Date.now()}`]
    );
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test SOC Org B ${Date.now()}`]
    );
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    // Users in Org A
    const adminARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id, email, role, organization_id;`,
      [`admin_a_${Date.now()}@cyberguard.test`, 'dummy_hash', testOrgAId]
    );
    testAdminA = adminARes.rows[0];
    createdUserIds.push(testAdminA.id);
    tokenAdminA = createToken({ ...testAdminA, role: 'admin' });

    const analystARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id, email, role, organization_id;`,
      [`analyst_a_${Date.now()}@cyberguard.test`, 'dummy_hash', testOrgAId]
    );
    testAnalystA = analystARes.rows[0];
    createdUserIds.push(testAnalystA.id);
    tokenAnalystA = createToken({ ...testAnalystA, role: 'analyst' });

    const empARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING id, email, role, organization_id;`,
      [`emp_a_${Date.now()}@cyberguard.test`, 'dummy_hash', testOrgAId]
    );
    testEmployeeA = empARes.rows[0];
    createdUserIds.push(testEmployeeA.id);
    tokenEmployeeA = createToken({ ...testEmployeeA, role: 'employee' });

    // User in Org B
    const analystBRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id, email, role, organization_id;`,
      [`analyst_b_${Date.now()}@cyberguard.test`, 'dummy_hash', testOrgBId]
    );
    testAnalystB = analystBRes.rows[0];
    createdUserIds.push(testAnalystB.id);
    tokenAnalystB = createToken({ ...testAnalystB, role: 'analyst' });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 1: MIGRATION & SCHEMA VALIDATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP 1: MIGRATION & SCHEMA VALIDATION ---');

    await testAsync('1.1: Migration file 029_soc_investigation_platform.sql exists', async () => {
      const migPath = path.resolve(__dirname, '../sql/029_soc_investigation_platform.sql');
      assert.ok(fs.existsSync(migPath), 'Migration 029 must exist on disk');
    });

    await testAsync('1.2: incident_notes and incident_recommendations tables exist in DB', async () => {
      const res = await db.query(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name IN ('incident_notes', 'incident_recommendations');
      `);
      const names = res.rows.map(r => r.table_name);
      assert.ok(names.includes('incident_notes'), 'incident_notes table must exist');
      assert.ok(names.includes('incident_recommendations'), 'incident_recommendations table must exist');
    });

    await testAsync('1.3: incidents table has priority, assigned_to, assigned_at, escalated_at columns', async () => {
      const res = await db.query(`
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'incidents' AND column_name IN ('priority', 'assigned_to', 'assigned_at', 'escalated_at');
      `);
      const cols = res.rows.map(r => r.column_name);
      assert.ok(cols.includes('priority'), 'incidents must have priority column');
      assert.ok(cols.includes('assigned_to'), 'incidents must have assigned_to column');
      assert.ok(cols.includes('assigned_at'), 'incidents must have assigned_at column');
      assert.ok(cols.includes('escalated_at'), 'incidents must have escalated_at column');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 2: RISK SCORING ENGINE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 2: RISK SCORING ENGINE ---');

    let testIncident1 = null;
    let testIncident2 = null;

    await testAsync('2.1: Creates baseline incidents for scoring and prioritization', async () => {
      testIncident1 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testAnalystA.id,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 40,
        explanation: 'Suspicious credential harvester email detected',
        status: 'open',
        priority: 'P2'
      });
      createdIncidentIds.push(testIncident1.id);
      assert.ok(testIncident1.id, 'Incident 1 created');

      testIncident2 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testAnalystA.id,
        threat_type: 'technical_threat',
        source_type: 'system',
        risk_level: 'critical',
        risk_score: 85,
        explanation: 'Cobalt Strike payload execution on workstation',
        status: 'open',
        priority: 'P1'
      });
      createdIncidentIds.push(testIncident2.id);
      assert.ok(testIncident2.id, 'Incident 2 created');
    });

    await testAsync('2.2: Calculates multi-factor risk score and updates DB record', async () => {
      const scoreResult = await riskScoringService.calculateRiskScore(testIncident1.id, testOrgAId, {
        actorUserId: testAnalystA.id
      });

      assert.ok(typeof scoreResult.risk_score === 'number', 'Score should be numeric');
      assert.ok(scoreResult.risk_score >= 0 && scoreResult.risk_score <= 100, 'Score clamped 0-100');
      assert.ok(['low', 'medium', 'high', 'critical'].includes(scoreResult.risk_level), 'Valid risk level');
      assert.ok(scoreResult.breakdown.severity_weight > 0, 'Severity weight included');

      // Verify DB update
      const updated = await Incident.findById(testIncident1.id);
      assert.strictEqual(parseFloat(updated.risk_score), scoreResult.risk_score, 'DB risk_score must match calculated');
      assert.strictEqual(updated.risk_level, scoreResult.risk_level, 'DB risk_level must match calculated');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 3: INCIDENT PRIORITIZATION ENGINE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 3: INCIDENT PRIORITIZATION ENGINE ---');

    await testAsync('3.1: Evaluates and persists priority (P1-P4)', async () => {
      const prio1 = await incidentPrioritizationService.evaluateAndPersist(testIncident1.id, testOrgAId);
      assert.ok(['P1', 'P2', 'P3', 'P4'].includes(prio1), 'Priority must be P1-P4');

      const prio2 = await incidentPrioritizationService.evaluateAndPersist(testIncident2.id, testOrgAId);
      assert.strictEqual(prio2, 'P1', 'Critical risk incident must evaluate to P1');
    });

    await testAsync('3.2: GET /api/v1/incidents/prioritized returns ordered incidents', async () => {
      const res = await fetch(`${baseUrl}/incidents/prioritized`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(Array.isArray(data.incidents), 'incidents must be an array');
      assert.ok(data.incidents.length >= 2, 'Should include created incidents');
      assert.strictEqual(data.incidents[0].priority, 'P1', 'First incident in prioritized list should be P1');
    });

    await testAsync('3.3: GET /api/v1/incidents/queue returns SOC action queue', async () => {
      const res = await fetch(`${baseUrl}/incidents/queue`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(Array.isArray(data.queue), 'queue must be an array');
      assert.ok(data.queue.length >= 2, 'Queue should list open incidents');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 4: AUTOMATED RESPONSE RECOMMENDATION ENGINE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 4: AUTOMATED RESPONSE RECOMMENDATION ENGINE ---');

    await testAsync('4.1: Generates tailored phishing recommendations', async () => {
      const recs = await recommendationEngine.getRecommendations(testIncident1.id, testOrgAId);
      assert.ok(Array.isArray(recs), 'Recommendations should be an array');
      assert.ok(recs.length >= 2, 'Phishing incident should generate multiple recommendations');

      const titles = recs.map(r => r.title);
      assert.ok(titles.some(t => t.includes('Session') || t.includes('Password') || t.includes('Block')), 'Contains phishing actions');

      const automatableRec = recs.find(r => r.automatable === true);
      assert.ok(automatableRec, 'At least one recommendation should be automatable');
    });

    await testAsync('4.2: Generates tailored malware recommendations for Incident 2', async () => {
      const recs = await recommendationEngine.getRecommendations(testIncident2.id, testOrgAId);
      assert.ok(recs.length >= 2, 'Malware incident should generate multiple recommendations');
      const titles = recs.map(r => r.title);
      assert.ok(titles.some(t => t.includes('Isolate') || t.includes('Process') || t.includes('Scan') || t.includes('Tier-3')), 'Contains malware actions');
    });

    await testAsync('4.3: GET /api/v1/incidents/:id/recommendations API returns persisted recommendations', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/recommendations`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.incident_id, testIncident1.id);
      assert.ok(data.recommendations.length >= 2);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 5: INCIDENT INVESTIGATION WORKSPACE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 5: INCIDENT INVESTIGATION WORKSPACE ---');

    await testAsync('5.1: POST /api/v1/incidents/:id/notes adds an analyst investigation note', async () => {
      const noteText = 'Initial triage confirmed spoofed SPF/DKIM headers. Malicious link identified.';
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ note: noteText })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.note.note, noteText);
      assert.strictEqual(data.note.user_id, testAnalystA.id);
    });

    await testAsync('5.2: GET /api/v1/incidents/:id/workspace returns unified timeline and notes', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/workspace`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(data.incident, 'Should contain incident object');
      assert.strictEqual(data.incident.id, testIncident1.id);
      assert.ok(Array.isArray(data.timeline), 'Should contain timeline array');
      assert.ok(data.timeline.length >= 2, 'Timeline should contain created event + note');
      assert.ok(Array.isArray(data.notes), 'Should contain notes array');
      assert.strictEqual(data.notes.length, 1, 'Should contain 1 note');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 6: SOC DASHBOARD AGGREGATION ENGINE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 6: SOC DASHBOARD AGGREGATION ENGINE ---');

    await testAsync('6.1: GET /api/v1/dashboard/overview returns aggregated SOC metrics', async () => {
      const res = await fetch(`${baseUrl}/dashboard/overview`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(data.open_incidents >= 2, 'Should report open incidents');
      assert.ok(typeof data.mttd_hours === 'number', 'mttd_hours must be a number');
      assert.ok(Array.isArray(data.top_threat_types), 'top_threat_types must be array');
    });

    await testAsync('6.2: GET /api/v1/dashboard/trends returns daily trend series', async () => {
      const res = await fetch(`${baseUrl}/dashboard/trends?days=7`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(Array.isArray(data.trends), 'trends must be array');
      assert.ok(data.trends.length >= 1, 'Should contain at least current day trend');
    });

    await testAsync('6.3: GET /api/v1/dashboard/metrics returns operational breakdowns', async () => {
      const res = await fetch(`${baseUrl}/dashboard/metrics`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(Array.isArray(data.priority_distribution), 'priority_distribution must be array');
      assert.ok(data.total_incidents >= 2, 'Total incidents tracked');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 7: INCIDENT COMMAND CENTER
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 7: INCIDENT COMMAND CENTER ---');

    await testAsync('7.1: GET /api/v1/incidents/:id/command-center returns full consolidated intelligence', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/command-center`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');

      // Verify all required command center contract fields
      assert.ok(data.incident, 'Must contain incident');
      assert.ok(typeof data.risk_score === 'number', 'Must contain risk_score');
      assert.ok(['P1', 'P2', 'P3', 'P4'].includes(data.priority), 'Must contain priority');
      assert.ok(Array.isArray(data.timeline), 'Must contain timeline');
      assert.ok(Array.isArray(data.notes), 'Must contain notes');
      assert.ok(Array.isArray(data.recommendations), 'Must contain recommendations');
      assert.ok('attack_chain' in data, 'Must contain attack_chain');
      assert.ok('campaign' in data, 'Must contain campaign');
      assert.ok(Array.isArray(data.related_incidents), 'Must contain related_incidents');
      assert.ok(Array.isArray(data.indicators), 'Must contain indicators');
      assert.ok(Array.isArray(data.audit_history), 'Must contain audit_history');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 8: ANALYST WORKFLOW ENGINE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 8: ANALYST WORKFLOW ENGINE ---');

    await testAsync('8.1: POST /api/v1/incidents/:id/assign assigns incident to analyst', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ user_id: testAnalystA.id })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.incident.assigned_to, testAnalystA.id);
      assert.ok(data.incident.assigned_at, 'assigned_at must be populated');
    });

    await testAsync('8.2: POST /api/v1/incidents/:id/escalate escalates incident to P1', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/escalate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ reason: 'Executive VIP mailbox targeted' })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.incident.priority, 'P1');
      assert.ok(data.incident.escalated_at, 'escalated_at must be populated');
    });

    await testAsync('8.3: POST /api/v1/incidents/:id/resolve resolves incident', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.incident.status, 'resolved');
      assert.ok(data.incident.resolved_at, 'resolved_at must be populated');
    });

    await testAsync('8.4: POST /api/v1/incidents/:id/reopen reopens resolved incident', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/reopen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({ reason: 'Follow-up secondary callback detected' })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.incident.status, 'open');
      assert.strictEqual(data.incident.resolved_at, null);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 9: TENANT ISOLATION & RBAC SECURITY
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 9: MULTI-TENANT ISOLATION & RBAC SECURITY ---');

    await testAsync('9.1: Cross-tenant access blocked: Org B analyst cannot view Org A workspace', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/workspace`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(res.status, 404, 'Must return 404 cleanly when accessing incident of another tenant');
    });

    await testAsync('9.2: Cross-tenant access blocked: Org B analyst cannot view Org A command center', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/command-center`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(res.status, 404, 'Command center must enforce tenant boundary');
    });

    await testAsync('9.3: RBAC enforced: Employee without analyst/admin role is rejected with 403', async () => {
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/command-center`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res.status, 403, 'Non-analyst must receive 403 Forbidden');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // MODULE 10: AUDIT LOGGING & PERFORMANCE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 10: AUDIT LOGGING & PERFORMANCE ---');

    await testAsync('10.1: Verifies audit log entries recorded for SOC actions', async () => {
      const auditRes = await db.query(
        `SELECT DISTINCT action FROM public.audit_logs 
         WHERE organization_id = $1;`,
        [testOrgAId]
      );
      const recordedActions = auditRes.rows.map(r => r.action);

      assert.ok(recordedActions.includes('INVESTIGATION_WORKSPACE_VIEWED'), 'INVESTIGATION_WORKSPACE_VIEWED logged');
      assert.ok(recordedActions.includes('INCIDENT_ASSIGNED'), 'INCIDENT_ASSIGNED logged');
      assert.ok(recordedActions.includes('INCIDENT_ESCALATED'), 'INCIDENT_ESCALATED logged');
      assert.ok(recordedActions.includes('INCIDENT_REOPENED'), 'INCIDENT_REOPENED logged');
      assert.ok(recordedActions.includes('RECOMMENDATION_GENERATED'), 'RECOMMENDATION_GENERATED logged');
      assert.ok(recordedActions.includes('COMMAND_CENTER_VIEWED'), 'COMMAND_CENTER_VIEWED logged');
      assert.ok(recordedActions.includes('DASHBOARD_VIEWED'), 'DASHBOARD_VIEWED logged');
    });

    await testAsync('10.2: Performance SLA check: Command Center API responds under 500ms', async () => {
      // Warm-up query to eliminate JIT/connection setup overhead
      await fetch(`${baseUrl}/incidents/${testIncident1.id}/command-center`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      const start = Date.now();
      const res = await fetch(`${baseUrl}/incidents/${testIncident1.id}/command-center`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      const duration = Date.now() - start;
      assert.strictEqual(res.status, 200);
      assert.ok(duration < 500, `Expected duration < 500ms, actual: ${duration}ms`);
      console.log(`      (Command Center latency: ${duration}ms)`);
    });

  } finally {
    // Teardown test artifacts
    if (server) {
      server.close();
    }

    try {
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.incident_notes WHERE incident_id = ANY($1);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incident_recommendations WHERE incident_id = ANY($1);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1);`, [createdIncidentIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.audit_logs WHERE user_id = ANY($1);`, [createdUserIds]);
        await db.query(`DELETE FROM public.users WHERE id = ANY($1);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [createdOrgIds]);
      }
    } catch (cleanupErr) {
      console.warn('[Cleanup Warning]:', cleanupErr.message);
    }
  }

  console.log('\n========================================================================');
  console.log(`TEST SUITE RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite()
  .then(() => {
    console.log('[COMPLETE] SOC Investigation & Response Platform test run finished successfully.');
    process.exit(0);
  })
  .catch((err) => {
    console.error('[FATAL TEST SUITE ERROR]:', err);
    process.exit(1);
  });
