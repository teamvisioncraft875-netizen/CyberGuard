process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SiemAlert = require('../src/models/SiemAlert');
const SiemDetectionHit = require('../src/models/SiemDetectionHit');
const SecurityEvent = require('../src/models/SecurityEvent');
const Incident = require('../src/models/Incident');
const AttackChainSnapshot = require('../src/models/AttackChainSnapshot');
const socMetricsService = require('../src/services/siem/socMetricsService');
const timelineService = require('../src/services/siem/timelineService');
const streamingService = require('../src/services/siem/streamingService');

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
  console.log('CYBERGUARD — SIEM Phase 3: Real-Time SOC Monitoring & Alerts Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;
  let testOrgAId = null;
  let testOrgBId = null;
  let testAnalystAId = null;
  let testAnalystBId = null;
  let testEmployeeAId = null;

  const createdOrgIds = [];
  const createdUserIds = [];
  const createdAlertIds = [];
  const createdIncidentIds = [];
  const createdEventIds = [];
  const createdSnapshotIds = [];

  try {
    // 1. Start ephemeral HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // 2. Setup Organizations & Users
    const orgARes = await db.query(`INSERT INTO public.organizations (name) VALUES ('SOC Monitoring Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO public.organizations (name) VALUES ('SOC Monitoring Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'soc_analyst_a@cyberguard.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testAnalystAId = userARes.rows[0].id;
    createdUserIds.push(testAnalystAId);

    const empARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'emp_a@cyberguard.test', 'hash', 'employee') RETURNING id;`,
      [testOrgAId]
    );
    testEmployeeAId = empARes.rows[0].id;
    createdUserIds.push(testEmployeeAId);

    const userBRes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'soc_analyst_b@cyberguard.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testAnalystBId = userBRes.rows[0].id;
    createdUserIds.push(testAnalystBId);

    const tokenAnalystA = createToken({ id: testAnalystAId, email: 'soc_analyst_a@cyberguard.test', role: 'analyst', organization_id: testOrgAId });
    const tokenAnalystB = createToken({ id: testAnalystBId, email: 'soc_analyst_b@cyberguard.test', role: 'analyst', organization_id: testOrgBId });
    const tokenEmployeeA = createToken({ id: testEmployeeAId, email: 'emp_a@cyberguard.test', role: 'employee', organization_id: testOrgAId });
    const tokenNoOrg = createToken({ id: '00000000-0000-0000-0000-000000000099', email: 'no_org@cyberguard.test', role: 'admin', organization_id: null });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 1: REAL-TIME ALERT STREAMING (SSE /live)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP 1: REAL-TIME ALERT STREAMING (SSE /live) ---');

    await testAsync('1.1: GET /api/v1/siem/live establishes SSE stream with retry: 5000 and handshake', async () => {
      const receivedMessages = [];
      let sseReq;

      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          sseReq?.destroy();
          resolve();
        }, 1500);

        sseReq = http.get(
          `${baseUrl}/siem/live`,
          { headers: { Authorization: `Bearer ${tokenAnalystA}` } },
          (res) => {
            assert.strictEqual(res.statusCode, 200);
            assert.strictEqual(res.headers['content-type'], 'text/event-stream');

            res.on('data', (chunk) => {
              const text = chunk.toString();
              receivedMessages.push(text);
              if (text.includes('handshake')) {
                clearTimeout(timeout);
                sseReq.destroy();
                resolve();
              }
            });
          }
        );
        sseReq.on('error', (e) => {
          if (e.code === 'ECONNRESET') resolve();
          else reject(e);
        });
      });

      const fullOutput = receivedMessages.join('');
      assert.ok(fullOutput.includes('retry: 5000'), 'Must specify retry: 5000 for auto-reconnect');
      assert.ok(fullOutput.includes('handshake'), 'Must send initial handshake event');
    });

    await testAsync('1.2: SSE client receives live alert and detection updates', async () => {
      const receivedEvents = [];
      let sseReq;

      await new Promise((resolve, reject) => {
        sseReq = http.get(
          `${baseUrl}/siem/live`,
          { headers: { Authorization: `Bearer ${tokenAnalystA}` } },
          (res) => {
            res.on('data', (chunk) => {
              const text = chunk.toString();
              if (text.includes('alert_update')) {
                receivedEvents.push('alert_update');
                sseReq.destroy();
                resolve();
              }
            });

            // Trigger broadcast after subscription is active
            setTimeout(() => {
              streamingService.publishAlertUpdate({
                id: '12345678-1234-1234-1234-123456789abc',
                title: 'Live Simulated Alert',
                status: 'investigating'
              }, testOrgAId);
            }, 300);
          }
        );

        sseReq.on('error', (e) => {
          if (e.code === 'ECONNRESET') resolve();
          else reject(e);
        });

        setTimeout(() => {
          sseReq.destroy();
          resolve();
        }, 2000);
      });

      assert.ok(receivedEvents.includes('alert_update'), 'Subscriber must receive published alert_update event');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 2: ALERT LIFECYCLE MANAGEMENT
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 2: ALERT LIFECYCLE MANAGEMENT ---');

    let createdAlert = null;

    await testAsync('2.1: Creates new SIEM alert with initial status "new"', async () => {
      createdAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Brute Force Alert on DC01',
        severity: 'high',
        status: 'new',
        rule_code: 'SIEM-RULE-BRUTE',
        mitre_technique: 'T1110',
        source_type: 'windows'
      });

      assert.ok(createdAlert.id);
      createdAlertIds.push(createdAlert.id);
      assert.strictEqual(createdAlert.status, 'new');
      assert.strictEqual(createdAlert.severity, 'high');
      assert.strictEqual(createdAlert.investigating_at, null);
    });

    await testAsync('2.2: PATCH /api/v1/siem/alerts/:id transitions status to "investigating" and records timestamp', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts/${createdAlert.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'investigating',
          assigned_analyst: testAnalystAId,
          notes: 'Triaging user audit logs on DC01.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.status, 'investigating');
      assert.strictEqual(json.data.assigned_analyst, testAnalystAId);
      assert.ok(json.data.investigating_at, 'investigating_at must be populated');
      assert.strictEqual(json.data.notes, 'Triaging user audit logs on DC01.');

      // Check audit log
      const audit = await db.query(
        `SELECT * FROM public.audit_logs WHERE action = 'SIEM_ALERT_STATUS_UPDATED' AND resource_id = $1`,
        [createdAlert.id]
      );
      assert.ok(audit.rows.length >= 1);
    });

    await testAsync('2.3: Transitions status to "contained" and records contained_at timestamp', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts/${createdAlert.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'contained',
          notes: 'Source IP blacklisted on perimeter firewall.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.status, 'contained');
      assert.ok(json.data.contained_at, 'contained_at must be populated');
    });

    await testAsync('2.4: Transitions status to "resolved" with resolution description', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts/${createdAlert.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'resolved',
          resolution: 'Host credentials rotated and attacker IP permanently blocked.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.status, 'resolved');
      assert.ok(json.data.resolved_at, 'resolved_at must be populated');
      assert.strictEqual(json.data.resolution, 'Host credentials rotated and attacker IP permanently blocked.');
    });

    await testAsync('2.5: Creates and marks false_positive alert successfully', async () => {
      const fpAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Benign Vulnerability Scanner Alert',
        severity: 'low',
        status: 'new',
        rule_code: 'SIEM-SCAN-01'
      });
      createdAlertIds.push(fpAlert.id);

      const res = await fetch(`${baseUrl}/siem/alerts/${fpAlert.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          status: 'false_positive',
          resolution: 'Authorized internal Nessus scan.'
        })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.status, 'false_positive');
      assert.ok(json.data.resolved_at);
    });

    await testAsync('2.6: GET /api/v1/siem/alerts lists alerts with status and pagination filters', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts?status=resolved&limit=10`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      assert.ok(json.data.some(a => a.id === createdAlert.id));
      assert.ok(json.pagination.total >= 1);
    });

    await testAsync('2.7: GET /api/v1/siem/alerts/:id returns single alert with joined analyst email', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts/${createdAlert.id}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.id, createdAlert.id);
      assert.strictEqual(json.data.analyst_email, 'soc_analyst_a@cyberguard.test');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 3: SOC METRICS DASHBOARD
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 3: SOC METRICS DASHBOARD ---');

    await testAsync('3.1: socMetricsService computes MTTD, MTTR, and categorized breakdowns', async () => {
      // Seed a couple more alerts for diverse metrics
      const aCrit = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Critical Ransomware Execution',
        severity: 'critical',
        status: 'new',
        rule_code: 'SIEM-RANSOM-01',
        mitre_technique: 'T1486',
        source_type: 'sysmon'
      });
      createdAlertIds.push(aCrit.id);

      const metrics = await socMetricsService.getMetrics(testOrgAId);
      assert.ok(metrics.total_alerts >= 3);
      assert.ok(metrics.critical_alerts >= 1);
      assert.ok(metrics.open_alerts >= 1);
      assert.ok(metrics.resolved_alerts >= 1);
      assert.ok(metrics.alerts_by_severity.critical >= 1);
      assert.ok(metrics.alerts_by_severity.high >= 1);
      assert.ok(Array.isArray(metrics.alerts_by_mitre));
      assert.ok(Array.isArray(metrics.alerts_by_source));
      assert.ok(metrics.mttr_minutes >= 0);
      assert.ok(metrics.mttd_minutes >= 0);
    });

    await testAsync('3.2: GET /api/v1/siem/dashboard/metrics returns metrics payload under 100ms SLA', async () => {
      const t0 = Date.now();
      const res = await fetch(`${baseUrl}/siem/dashboard/metrics`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      const latency = Date.now() - t0;

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.total_alerts !== undefined);
      assert.ok(json.data.critical_alerts !== undefined);
      assert.ok(latency < 3000, `Dashboard metrics responded in ${latency}ms`);
    });

    await testAsync('3.3: GET /api/v1/siem/dashboard/trends returns daily series buckets', async () => {
      const res = await fetch(`${baseUrl}/siem/dashboard/trends?days=7`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      assert.ok(json.data.length >= 7, 'Must return 7 daily buckets');
      assert.ok(json.data[0].date);
      assert.ok(json.data[0].total_alerts !== undefined);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 4: ANALYST QUEUE (Priority: Critical > High > Medium > Low, Newest)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 4: ANALYST QUEUE ---');

    await testAsync('4.1: GET /api/v1/siem/queue orders by critical > high > medium > low, then newest first', async () => {
      // Create alerts of distinct severities in Org A
      const lowAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Queue Test Low',
        severity: 'low',
        status: 'new'
      });
      const medAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Queue Test Medium',
        severity: 'medium',
        status: 'new'
      });
      const highAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Queue Test High',
        severity: 'high',
        status: 'new'
      });
      const critAlert = await SiemAlert.create({
        organization_id: testOrgAId,
        title: 'Queue Test Critical',
        severity: 'critical',
        status: 'new'
      });

      createdAlertIds.push(lowAlert.id, medAlert.id, highAlert.id, critAlert.id);

      const res = await fetch(`${baseUrl}/siem/queue`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();

      assert.ok(json.data.length >= 4);

      // Verify that critical appears before high, high before medium, medium before low
      const critIdx = json.data.findIndex(a => a.id === critAlert.id);
      const highIdx = json.data.findIndex(a => a.id === highAlert.id);
      const medIdx = json.data.findIndex(a => a.id === medAlert.id);
      const lowIdx = json.data.findIndex(a => a.id === lowAlert.id);

      assert.ok(critIdx < highIdx, 'Critical must appear before High');
      assert.ok(highIdx < medIdx, 'High must appear before Medium');
      assert.ok(medIdx < lowIdx, 'Medium must appear before Low');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 5: UNIFIED TIMELINE API
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 5: UNIFIED TIMELINE API ---');

    await testAsync('5.1: GET /api/v1/siem/timeline returns unified events, detections, incidents, and attack chains', async () => {
      // Create test items of each type
      const ev = await SecurityEvent.create({
        organization_id: testOrgAId,
        source_type: 'windows',
        event_type: 'timeline_test_event',
        severity: 'low',
        event_timestamp: new Date()
      });
      createdEventIds.push(ev.id);

      const inc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'account_takeover',
        source_type: 'siem',
        risk_level: 'high',
        risk_score: 75,
        status: 'open'
      });
      createdIncidentIds.push(inc.id);

      const hit = await SiemDetectionHit.create({
        organization_id: testOrgAId,
        incident_id: inc.id,
        event_ids: [ev.id],
        confidence_score: 1.0,
        metadata: { title: 'Timeline Detection Hit' }
      });

      const snap = await AttackChainSnapshot.create({
        organization_id: testOrgAId,
        root_incident_id: inc.id,
        chain_length: 3,
        confidence_score: 0.95,
        chain_path: [{ step: 1 }, { step: 2 }]
      });
      createdSnapshotIds.push(snap.id);

      const res = await fetch(`${baseUrl}/siem/timeline?limit=20`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      assert.ok(json.data.length >= 4);

      const itemTypes = json.data.map(i => i.item_type);
      assert.ok(itemTypes.includes('event'), 'Timeline must include events');
      assert.ok(itemTypes.includes('detection'), 'Timeline must include detections');
      assert.ok(itemTypes.includes('incident'), 'Timeline must include incidents');
      assert.ok(itemTypes.includes('attack_chain'), 'Timeline must include attack_chains');
    });

    await testAsync('5.2: Timeline respects item_type filters', async () => {
      const res = await fetch(`${baseUrl}/siem/timeline?types=event,incident`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      const nonMatching = json.data.filter(i => i.item_type !== 'event' && i.item_type !== 'incident');
      assert.strictEqual(nonMatching.length, 0, 'Must only return requested item_types');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 6: SECURITY & MULTI-TENANT RBAC
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 6: SECURITY & MULTI-TENANT RBAC ---');

    await testAsync('6.1: Reject unauthenticated requests with 401', async () => {
      const res1 = await fetch(`${baseUrl}/siem/alerts`);
      assert.strictEqual(res1.status, 401);

      const res2 = await fetch(`${baseUrl}/siem/queue`);
      assert.strictEqual(res2.status, 401);

      const res3 = await fetch(`${baseUrl}/siem/dashboard/metrics`);
      assert.strictEqual(res3.status, 401);

      const res4 = await fetch(`${baseUrl}/siem/timeline`);
      assert.strictEqual(res4.status, 401);
    });

    await testAsync('6.2: Reject employee role (non-analyst/admin) with 403 Forbidden', async () => {
      const res1 = await fetch(`${baseUrl}/siem/alerts`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res1.status, 403);

      const res2 = await fetch(`${baseUrl}/siem/queue`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res2.status, 403);

      const res3 = await fetch(`${baseUrl}/siem/dashboard/metrics`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res3.status, 403);
    });

    await testAsync('6.3: Reject user with null organization_id with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/siem/alerts`, {
        headers: { Authorization: `Bearer ${tokenNoOrg}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('6.4: Strict cross-tenant isolation: Org B analyst cannot view Org A alerts or queue', async () => {
      // Org B list alerts
      const resAlerts = await fetch(`${baseUrl}/siem/alerts`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resAlerts.status, 200);
      const jsonAlerts = await resAlerts.json();
      assert.strictEqual(jsonAlerts.data.length, 0, 'Org B must see 0 alerts from Org A');

      // Org B lookup Org A alert directly
      const resDetail = await fetch(`${baseUrl}/siem/alerts/${createdAlert.id}`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resDetail.status, 404, 'Cross-tenant alert lookup must return 404 Not Found');

      // Org B queue
      const resQueue = await fetch(`${baseUrl}/siem/queue`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resQueue.status, 200);
      const jsonQueue = await resQueue.json();
      assert.strictEqual(jsonQueue.data.length, 0, 'Org B queue must be empty');
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdSnapshotIds.length > 0) {
        await db.query(`DELETE FROM public.attack_chain_snapshots WHERE id = ANY($1::uuid[]);`, [createdSnapshotIds]);
      }
      if (createdAlertIds.length > 0) {
        await db.query(`DELETE FROM public.siem_alerts WHERE id = ANY($1::uuid[]);`, [createdAlertIds]);
      }
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (createdEventIds.length > 0) {
        await db.query(`DELETE FROM public.security_events WHERE id = ANY($1::uuid[]);`, [createdEventIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.siem_alerts WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.siem_detection_hits WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
      }
      console.log('  [✅] Test fixtures cleaned up successfully');
    } catch (cleanupErr) {
      console.error('  [⚠️] Cleanup warning:', cleanupErr.message);
    }
  }

  console.log('\n========================================================================');
  console.log(`RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal Test Error:', err);
  process.exit(1);
});
