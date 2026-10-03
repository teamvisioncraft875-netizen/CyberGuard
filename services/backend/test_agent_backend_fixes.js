/**
 * CYBERGUARD Enterprise Agent Backend Fixes Validation Suite
 * Tests POST /admin/agents/tokens, agent telemetry dual-auth, device audit logging,
 * strict input validation, agent rate limiting (429), and regression integrity.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');
const db = require('./src/config/db');
const redis = require('./src/config/redis');
const config = require('./src/config');

const TEST_ORG_ID = '90000000-0000-4000-a000-000000000001';
const TEST_ADMIN_ID = '90000000-0000-4000-a000-000000000002';
const TEST_USER_ID = '90000000-0000-4000-a000-000000000003';

let adminToken;
let userToken;
let server;
let baseUrl;

async function setup() {
  if (!redis.isConnected()) {
    redis.enableMockRedis();
  }

  // Start HTTP server on dynamic port
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}/api/v1`;
      resolve();
    });
  });

  // Ensure test organization
  await db.query(`
    INSERT INTO public.organizations (id, name, created_at)
    VALUES ($1, 'Agent Fixes Test Org', NOW())
    ON CONFLICT (id) DO NOTHING;
  `, [TEST_ORG_ID]);

  // Ensure test admin user
  await db.query(`
    INSERT INTO public.users (id, organization_id, email, password_hash, role, created_at)
    VALUES ($1, $2, 'admin_fixes@cyberguard.test', 'testhash', 'admin', NOW())
    ON CONFLICT (id) DO UPDATE SET role = 'admin';
  `, [TEST_ADMIN_ID, TEST_ORG_ID]);

  // Ensure test standard user
  await db.query(`
    INSERT INTO public.users (id, organization_id, email, password_hash, role, created_at)
    VALUES ($1, $2, 'user_fixes@cyberguard.test', 'testhash', 'employee', NOW())
    ON CONFLICT (id) DO UPDATE SET role = 'employee';
  `, [TEST_USER_ID, TEST_ORG_ID]);

  adminToken = jwt.sign(
    { id: TEST_ADMIN_ID, organization_id: TEST_ORG_ID, role: 'admin' },
    config.JWT_SECRET,
    { expiresIn: '1h' }
  );

  userToken = jwt.sign(
    { id: TEST_USER_ID, organization_id: TEST_ORG_ID, role: 'employee' },
    config.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function cleanup() {
  try {
    await db.query('DELETE FROM public.audit_logs WHERE organization_id = $1;', [TEST_ORG_ID]);
    await db.query('DELETE FROM public.telemetry_events WHERE user_id IN ($1, $2);', [TEST_USER_ID, TEST_ADMIN_ID]);
    await db.query('DELETE FROM public.devices WHERE organization_id = $1;', [TEST_ORG_ID]);
    await db.query('DELETE FROM public.users WHERE organization_id = $1;', [TEST_ORG_ID]);
    await db.query('DELETE FROM public.organizations WHERE id = $1;', [TEST_ORG_ID]);
  } catch (err) {
    console.warn('[cleanup note]', err.message);
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  }
}

async function runTests() {
  console.log('\n============================================================');
  console.log('Running CYBERGUARD Enterprise Agent Backend Fixes Test Suite');
  console.log('============================================================\n');

  await setup();

  const results = [];
  function assertTest(name, condition, details = '') {
    results.push({ name, passed: Boolean(condition), details });
    console.log(`[${condition ? 'PASS' : 'FAIL'}] ${name} ${details}`);
    if (!condition) {
      throw new Error(`Test failed: ${name}`);
    }
  }

  let enrollmentToken = null;
  let deviceId = null;
  let credentialId = null;
  let credentialSecret = null;

  try {
    // 1. POST /api/v1/admin/agents/tokens (Admin generates token)
    const tokenHttpRes = await fetch(`${baseUrl}/admin/agents/tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ organization_id: TEST_ORG_ID, valid_for_hours: 12 })
    });
    const tokenBody = await tokenHttpRes.json();

    assertTest(
      '1. Admin generates enrollment token via POST /admin/agents/tokens',
      tokenHttpRes.status === 201 && tokenBody.token && tokenBody.organization_id === TEST_ORG_ID,
      `(HTTP ${tokenHttpRes.status}, token length=${tokenBody.token?.length})`
    );
    enrollmentToken = tokenBody.token;

    // 1b. Non-admin forbidden to generate tokens
    const nonAdminHttpRes = await fetch(`${baseUrl}/admin/agents/tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userToken}`
      },
      body: JSON.stringify({ organization_id: TEST_ORG_ID })
    });

    assertTest(
      '1b. Non-admin forbidden from generating enrollment tokens',
      nonAdminHttpRes.status === 403,
      `(HTTP ${nonAdminHttpRes.status})`
    );

    // 2. Input validation: Invalid hostname in enrollment returns 400
    const invalidEnrollRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollmentToken,
        hostname: '   ', // empty string
        os: 'Windows 11',
        platform: 'desktop'
      })
    });
    const invalidEnrollBody = await invalidEnrollRes.json();

    assertTest(
      '2. Enrollment rejects invalid/empty hostname with 400',
      invalidEnrollRes.status === 400 && invalidEnrollBody.error === 'INVALID_PAYLOAD',
      `(HTTP ${invalidEnrollRes.status}, msg="${invalidEnrollBody.message}")`
    );

    // 3. Agent successfully enrolls with valid token and inputs
    const validEnrollRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollmentToken,
        hostname: 'corp-laptop-01',
        os: 'Windows 11 Enterprise',
        platform: 'desktop',
        agent_version: '1.0.0'
      })
    });
    const validEnrollBody = await validEnrollRes.json();

    assertTest(
      '3. Agent enrolls with token and receives device_id + credentials',
      validEnrollRes.status === 201 && validEnrollBody.device_id && validEnrollBody.credential_secret,
      `(HTTP ${validEnrollRes.status}, device_id=${validEnrollBody.device_id})`
    );
    deviceId = validEnrollBody.device_id;
    credentialId = validEnrollBody.credential_id;
    credentialSecret = validEnrollBody.credential_secret;

    // 4. Agent sends telemetry via /telemetry/system-event with credential_id + secret
    const agentTelemetryRes = await fetch(`${baseUrl}/telemetry/system-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: deviceId,
        credential_id: credentialId,
        credential_secret: credentialSecret,
        timestamp: new Date().toISOString(),
        event_type: 'agent_telemetry',
        telemetry_type: 'agent_telemetry',
        source: 'enterprise_agent',
        details: {
          hostname: 'corp-laptop-01',
          open_sockets: 42,
          top_processes: [{ name: 'node.exe', pid: 1024, cpu_pct: 1.2, mem_pct: 0.8 }]
        }
      })
    });
    const agentTelemetryBody = await agentTelemetryRes.json();

    assertTest(
      '4. Agent submits telemetry with device credentials (dual-auth)',
      agentTelemetryRes.status === 201 && agentTelemetryBody.status === 'recorded',
      `(HTTP ${agentTelemetryRes.status})`
    );

    // 5. Backend sees actor_type='device' in audit log for the telemetry
    const auditRes = await db.query(`
      SELECT actor_type, action, resource_type, resource_id
      FROM public.audit_logs
      WHERE resource_id = $1
      ORDER BY created_at DESC
      LIMIT 1;
    `, [deviceId]);

    const auditRow = auditRes.rows[0];
    assertTest(
      '5. Telemetry creates audit log with actor_type="device"',
      auditRow && auditRow.actor_type === 'device' && auditRow.action === 'telemetry:system_event',
      `(actor_type=${auditRow?.actor_type}, action=${auditRow?.action}, resource_id=${auditRow?.resource_id})`
    );

    // 6. User still able to send telemetry with standard JWT (regression check)
    const userTelemetryRes = await fetch(`${baseUrl}/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userToken}`
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        event_type: 'network_spike',
        details: {
          remote_ip: '198.51.100.12',
          bytes: 500000
        }
      })
    });
    const userTelemetryBody = await userTelemetryRes.json();

    assertTest(
      '6. User JWT telemetry submission continues to function seamlessly',
      userTelemetryRes.status === 201 && userTelemetryBody.status === 'recorded',
      `(HTTP ${userTelemetryRes.status})`
    );

    // 7. Invalid credential_id to heartbeat returns 401
    const invalidCredHeartbeatRes = await fetch(`${baseUrl}/agents/${deviceId}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_id: '00000000-0000-0000-0000-000000000000',
        credential_secret: credentialSecret
      })
    });

    assertTest(
      '7. Invalid credential_id to heartbeat returns 401 UNAUTHORIZED',
      invalidCredHeartbeatRes.status === 401,
      `(HTTP ${invalidCredHeartbeatRes.status})`
    );

    // 8. Rate Limiting: agentLimiter enforces 100 req/15min per device_id
    process.env.SKIP_RATE_LIMIT = 'false';
    const rateLimitDeviceId = '99999999-9999-4000-a000-999999999999';
    let rateLimited = false;

    console.log('Sending requests to verify agentLimiter (100 max per device_id)...');
    // Send 100 requests in fast concurrent batches of 20
    for (let batch = 0; batch < 5; batch++) {
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(
          fetch(`${baseUrl}/agents/${rateLimitDeviceId}/heartbeat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}) // triggers quick 400 validation error without hitting remote DB
          })
        );
      }
      await Promise.all(promises);
    }

    // 101st request must trigger 429 Rate Limit Exceeded
    const blockedRes = await fetch(`${baseUrl}/agents/${rateLimitDeviceId}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const blockedBody = await blockedRes.json();
    rateLimited = (blockedRes.status === 429 && blockedBody.error === 'RATE_LIMIT_EXCEEDED');

    assertTest(
      '8. Rate limit: 101st heartbeat returns 429 RATE_LIMIT_EXCEEDED',
      rateLimited,
      `(HTTP ${blockedRes.status}, error="${blockedBody.error}")`
    );

  } finally {
    await cleanup();
  }

  console.log('\n============================================================');
  console.log('Enterprise Agent Backend Fixes: ALL 8 SCENARIOS PASSED!');
  console.log('============================================================\n');
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('[TEST FAILURE]', err);
    process.exit(1);
  });
