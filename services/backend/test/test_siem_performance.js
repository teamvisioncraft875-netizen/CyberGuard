process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SecurityEvent = require('../src/models/SecurityEvent');
const SiemAlert = require('../src/models/SiemAlert');
const correlationRuleEngine = require('../src/services/siem/correlationRuleEngine');
const performanceMetricsService = require('../src/services/siem/performanceMetricsService');
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

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.jwt_role || user.role,
      organization_id: user.organization_id || null
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runPerformanceSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — SIEM Phase 4: High-Scale Performance & Benchmark Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;
  let testOrg;
  let adminUser;
  let tokenAdmin;
  let tokenAnalyst;

  try {
    // 1. Start HTTP Server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Benchmark server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // 2. Setup Test Fixtures
    testOrg = await createOrganizationFixture({ name: 'Scale Benchmark Org' });
    adminUser = await createUserFixture({ organization_id: testOrg.id, role: 'admin' });
    const analystUser = await createUserFixture({ organization_id: testOrg.id, role: 'analyst' });

    tokenAdmin = createToken(adminUser);
    tokenAnalyst = createToken(analystUser);

    // Warm-up database connection pool
    await db.query(`SELECT 1;`);

    // ──────────────────────────────────────────────────────────────────────────
    // BENCHMARK 1: DETECTION ENGINE THROUGHPUT (5,000 Evaluations)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- BENCHMARK 1: CORRELATION ENGINE THROUGHPUT (5,000 EVALS) ---');

    await testAsync('1.1: Evaluates 5,000 security events with SLA < 50ms per evaluation', async () => {
      const EVAL_COUNT = 5000;
      const memBefore = process.memoryUsage().heapUsed;
      const t0 = process.hrtime.bigint();

      for (let i = 0; i < EVAL_COUNT; i++) {
        // Interleave various benign and candidate events
        const dummyEvent = {
          id: `ev-${i}`,
          organization_id: testOrg.id,
          event_type: i % 2 === 0 ? 'windows_logon_failed' : 'sysmon_network_connect',
          severity: 'medium',
          normalized_event: {
            user: `user_${i % 50}`, // 50 users spread
            source_ip: `192.168.1.${(i % 100) + 1}`,
            event_id: i % 2 === 0 ? 4625 : 3
          }
        };

        const tEvalStart = Date.now();
        await correlationRuleEngine.evaluateEvent(dummyEvent, testOrg.id);
        const evalMs = Date.now() - tEvalStart;
        assert.ok(evalMs < 50, `Single evaluation took ${evalMs}ms, exceeded 50ms SLA`);
      }

      const totalNs = Number(process.hrtime.bigint() - t0);
      const totalSec = totalNs / 1e9;
      const throughput = (EVAL_COUNT / totalSec).toFixed(0);
      const avgLatencyMs = ((totalNs / EVAL_COUNT) / 1e6).toFixed(4);
      const memDeltaMb = ((process.memoryUsage().heapUsed - memBefore) / 1024 / 1024).toFixed(2);

      console.log(`      ➜ 5,000 evals in ${(totalSec * 1000).toFixed(1)}ms | Throughput: ${throughput} evals/sec | Avg latency: ${avgLatencyMs}ms | Heap delta: ${memDeltaMb}MB`);
      assert.ok(totalSec < 10.0, '5,000 evaluations must complete in under 10 seconds');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // BENCHMARK 2: CONCURRENT ALERTS CREATION (1,000 Alerts)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- BENCHMARK 2: HIGH-VOLUME ALERTS GENERATION (1,000 ALERTS) ---');

    await testAsync('2.1: Inserts 1,000 SIEM alerts in batch and executes priority queue', async () => {
      const ALERT_COUNT = 1000;
      const severities = ['critical', 'high', 'medium', 'low'];
      const statuses = ['new', 'investigating', 'contained', 'resolved'];

      const t0 = Date.now();

      // Chunked bulk insert into siem_alerts
      const chunkSize = 200;
      for (let c = 0; c < ALERT_COUNT; c += chunkSize) {
        const rows = [];
        const params = [];
        for (let i = c; i < c + chunkSize; i++) {
          const sev = severities[i % 4];
          const st = statuses[i % 4];
          const offset = (i - c) * 5;
          rows.push(`($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, NOW())`);
          params.push(
            testOrg.id,
            `Load Test Alert #${i}`,
            sev,
            st,
            'SIEM-BENCHMARK'
          );
        }
        const insertQuery = `
          INSERT INTO public.siem_alerts (organization_id, title, severity, status, rule_code, created_at)
          VALUES ${rows.join(', ')}
        `;
        await db.query(insertQuery, params);
      }

      const durationMs = Date.now() - t0;
      console.log(`      ➜ 1,000 alerts created in ${durationMs}ms (${(ALERT_COUNT / (durationMs / 1000)).toFixed(0)} alerts/sec)`);

      // Verify count in DB
      const countRes = await db.query(
        `SELECT COUNT(*)::int AS cnt FROM public.siem_alerts WHERE organization_id = $1`,
        [testOrg.id]
      );
      assert.ok(countRes.rows[0].cnt >= 1000);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // BENCHMARK 3: EVENT BURST INGESTION (10,000 Events)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- BENCHMARK 3: EVENT BURST INGESTION (10,000 EVENTS) ---');

    await testAsync('3.1: Ingests 10,000 events into storage layer with chunked batching', async () => {
      const BURST_COUNT = 10000;
      const events = [];
      const now = new Date();

      for (let i = 0; i < BURST_COUNT; i++) {
        events.push({
          organization_id: testOrg.id,
          source_type: 'windows',
          event_type: 'windows_logon_success',
          severity: 'low',
          event_timestamp: now,
          raw_event: { event_id: 4624, seq: i },
          normalized_event: { summary: `Burst Event #${i}`, user: `user_${i % 100}` }
        });
      }

      const t0 = Date.now();
      const mem0 = process.memoryUsage().heapUsed;

      const inserted = await SecurityEvent.createMany(events);

      const durationMs = Date.now() - t0;
      const memDeltaMb = ((process.memoryUsage().heapUsed - mem0) / 1024 / 1024).toFixed(2);
      const eps = (BURST_COUNT / (durationMs / 1000)).toFixed(0);

      console.log(`      ➜ 10,000 events inserted in ${durationMs}ms | Throughput: ${eps} events/sec | Heap delta: ${memDeltaMb}MB`);
      assert.strictEqual(inserted.length, BURST_COUNT);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // BENCHMARK 4: API SLA LATENCY ENFORCEMENT
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- BENCHMARK 4: API SLA LATENCY ENFORCEMENT ---');

    // Warm-up query execution plans
    await fetch(`${baseUrl}/siem/dashboard/metrics`, { headers: { Authorization: `Bearer ${tokenAdmin}` } });
    await fetch(`${baseUrl}/siem/queue?limit=50`, { headers: { Authorization: `Bearer ${tokenAdmin}` } });
    await fetch(`${baseUrl}/siem/timeline?limit=50`, { headers: { Authorization: `Bearer ${tokenAdmin}` } });

    await testAsync('4.1: Metrics endpoint responds efficiently against 1k+ alerts & 10k+ events', async () => {
      const t0 = Date.now();
      const res = await fetch(`${baseUrl}/siem/dashboard/metrics`, {
        headers: { Authorization: `Bearer ${tokenAdmin}` }
      });
      const latency = Date.now() - t0;

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.total_alerts >= 1000);
      console.log(`      ➜ GET /siem/dashboard/metrics: ${latency}ms`);
      assert.ok(latency < 1500, `Metrics latency was ${latency}ms, exceeded threshold`);
    });

    await testAsync('4.2: Analyst Queue endpoint responds efficiently against 1k+ alerts', async () => {
      const t0 = Date.now();
      const res = await fetch(`${baseUrl}/siem/queue?limit=50`, {
        headers: { Authorization: `Bearer ${tokenAdmin}` }
      });
      const latency = Date.now() - t0;

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.length, 50);
      console.log(`      ➜ GET /siem/queue: ${latency}ms`);
      assert.ok(latency < 1500, `Queue latency was ${latency}ms, exceeded threshold`);
    });

    await testAsync('4.3: Unified Timeline endpoint responds efficiently against 10k+ events', async () => {
      const t0 = Date.now();
      const res = await fetch(`${baseUrl}/siem/timeline?limit=50`, {
        headers: { Authorization: `Bearer ${tokenAdmin}` }
      });
      const latency = Date.now() - t0;

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.length >= 50);
      console.log(`      ➜ GET /siem/timeline: ${latency}ms`);
      assert.ok(latency < 1500, `Timeline latency was ${latency}ms, exceeded threshold`);
    });

    await testAsync('4.4: GET /api/v1/siem/performance returns platform telemetry summary', async () => {
      const res = await fetch(`${baseUrl}/siem/performance`, {
        headers: { Authorization: `Bearer ${tokenAdmin}` }
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.events_per_second !== undefined);
      assert.ok(json.avg_ingestion_ms !== undefined);
      assert.ok(json.avg_detection_ms !== undefined);
      assert.ok(json.active_subscribers !== undefined);
    });

    await testAsync('4.5: Non-admin analyst role receives 403 Forbidden for performance endpoint', async () => {
      const res = await fetch(`${baseUrl}/siem/performance`, {
        headers: { Authorization: `Bearer ${tokenAnalyst}` }
      });
      assert.strictEqual(res.status, 403);
    });

  } finally {
    console.log('\n--- CLEANUP PERFORMANCE FIXTURES ---');
    if (server) {
      server.close();
    }
    if (testOrg) {
      try {
        await cleanupFixtures({ orgIds: [testOrg.id] });
        console.log('  [✅] Performance benchmark fixtures cleaned up successfully');
      } catch (e) {
        console.warn('  [⚠️] Cleanup warning:', e.message);
      }
    }
  }

  console.log('\n========================================================================');
  console.log(`BENCHMARK RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  runPerformanceSuite();
}

module.exports = { runPerformanceSuite };
