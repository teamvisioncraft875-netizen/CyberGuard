/**
 * CYBERGUARD Phase A: Enterprise Agent v1 Backend Foundation Test Suite
 *
 * Validates:
 * 1. Generate enrollment token, verify it exists and has future expiry
 * 2. Reject enrollment without token (400)
 * 3. Reject enrollment with expired token (401)
 * 4. Enroll device with token: returns device_id + credentials (secret returned ONLY once)
 * 5. Re-enrollment rejection with used token (401, single-use enforced)
 * 6. Heartbeat with invalid credentials rejected (401)
 * 7. Heartbeat with valid credentials updates status='online' and last_heartbeat
 * 8. Command queue polling (empty list initially)
 * 9. Command pickup by agent when admin creates a command
 * 10. Command result reporting updates status='completed' and executed_at
 * 11. Cross-tenant device status check: Org A admin sees device, Org B admin gets 404
 * 12. Agent model wrapper delegation verification
 */

process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { app } = require('./src');
const db = require('./src/config/db');
const redis = require('./src/config/redis');
const agentService = require('./src/services/agentService');
const Agent = require('./src/models/Agent');
const Device = require('./src/models/Device');

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

async function runEnterpriseAgentBackendTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE A ENTERPRISE AGENT BACKEND TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    console.log('[REDIS] Live Redis not connected, activating in-memory mock engine');
    redis.enableMockRedis();
  }

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];
  const createdCommandIds = [];

  const timestamp = Date.now();

  try {
    // 0. Start test HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}`);
        resolve();
      });
    });

    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Seed Organizations and Admin Users
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Setup: Seeding Organizations and Admin Users ---');
    const org1Res = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Enterprise Agent Org 1 ${timestamp}`]
    );
    const org1 = org1Res.rows[0];
    createdOrgIds.push(org1.id);

    const org2Res = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Enterprise Agent Org 2 ${timestamp}`]
    );
    const org2 = org2Res.rows[0];
    createdOrgIds.push(org2.id);

    const passwordHash = await bcrypt.hash('P@ssword123!', 10);

    const admin1Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin1_agent_${timestamp}@cyberguard.internal`, passwordHash, org1.id]
    );
    const admin1 = admin1Res.rows[0];
    createdUserIds.push(admin1.id);

    const admin2Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin2_agent_${timestamp}@cyberguard.internal`, passwordHash, org2.id]
    );
    const admin2 = admin2Res.rows[0];
    createdUserIds.push(admin2.id);

    const admin1Token = createToken(admin1);
    const admin2Token = createToken(admin2);

    console.log(`✔ Org 1: ${org1.id}, Admin 1: ${admin1.email}`);
    console.log(`✔ Org 2: ${org2.id}, Admin 2: ${admin2.email}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: Generate enrollment token & verify expiry in database
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: Generate Enrollment Token ---');
    const token = await agentService.generateEnrollmentToken(org1.id, 24);
    assert.ok(token && typeof token === 'string', 'Token should be a non-empty string');
    assert.strictEqual(token.length, 64, 'Token should be 32 bytes hex (64 chars)');

    const tokenRowRes = await db.query(`SELECT * FROM public.devices WHERE enrollment_token = $1;`, [token]);
    assert.strictEqual(tokenRowRes.rows.length, 1, 'Device row with enrollment token must exist');
    const tokenRow = tokenRowRes.rows[0];
    createdDeviceIds.push(tokenRow.id);

    assert.strictEqual(tokenRow.status, 'pending', 'Initial status must be pending');
    assert.strictEqual(tokenRow.organization_id, org1.id, 'Organization ID must match');
    assert.ok(new Date(tokenRow.token_expires_at) > new Date(), 'token_expires_at must be in the future');
    console.log(`✔ Passed: Enrollment token generated and verified in DB (device_id: ${tokenRow.id})`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Enroll device without token -> 400 Bad Request
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Enroll Without Token -> 400 ---');
    const enrollNoTokenRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname: 'test-host' })
    });
    assert.strictEqual(enrollNoTokenRes.status, 400, 'Must return 400 for missing token');
    const enrollNoTokenBody = await enrollNoTokenRes.json();
    assert.strictEqual(enrollNoTokenBody.error, 'INVALID_PAYLOAD');
    console.log('✔ Passed: Enrollment without token rejected with 400 Bad Request');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Enroll device with expired token -> 401 Unauthorized
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Enroll With Expired Token -> 401 ---');
    const expiredToken = await agentService.generateEnrollmentToken(org1.id, 1);
    const expRowRes = await db.query(`SELECT id FROM public.devices WHERE enrollment_token = $1;`, [expiredToken]);
    createdDeviceIds.push(expRowRes.rows[0].id);

    // Force expire in DB
    await db.query(
      `UPDATE public.devices SET token_expires_at = NOW() - INTERVAL '1 hour' WHERE enrollment_token = $1;`,
      [expiredToken]
    );

    const enrollExpiredRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollment_token: expiredToken, hostname: 'expired-host' })
    });
    assert.strictEqual(enrollExpiredRes.status, 401, 'Must return 401 for expired token');
    console.log('✔ Passed: Enrollment with expired token rejected with 401 Unauthorized');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Enroll device with valid token -> 201 Created & credentials
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Successful Device Enrollment ---');
    const enrollRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: token,
        hostname: 'ws-finance-01.corp.internal',
        os: 'Windows 11 Pro 23H2',
        platform: 'desktop',
        agent_version: '1.0.0'
      })
    });

    assert.strictEqual(enrollRes.status, 201, 'Must return 201 on successful enrollment');
    const enrolledBody = await enrollRes.json();
    assert.ok(enrolledBody.device_id, 'Must return device_id');
    assert.ok(enrolledBody.credential_id, 'Must return credential_id');
    assert.ok(enrolledBody.credential_secret, 'Must return plaintext credential_secret on enrollment');
    assert.strictEqual(enrolledBody.organization_id, org1.id, 'Organization ID must match');

    const enrolledDev = await Device.findById(enrolledBody.device_id);
    assert.strictEqual(enrolledDev.status, 'online', 'Status must transition to online');
    assert.strictEqual(enrolledDev.enrollment_token, null, 'Enrollment token must be cleared');
    assert.strictEqual(enrolledDev.token_expires_at, null, 'Token expiry must be cleared');
    assert.ok(enrolledDev.agent_credentials_hash, 'Bcrypt hash must be stored in DB');
    assert.notStrictEqual(enrolledDev.agent_credentials_hash, enrolledBody.credential_secret, 'Raw secret must never be stored in DB');
    console.log(`✔ Passed: Device enrolled: id=${enrolledBody.device_id}, status=online, credential_id=${enrolledBody.credential_id}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: Verify credential_secret is returned ONLY on enrollment (second call fails)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Re-Enrollment With Used Token Rejected (Single-Use) ---');
    const reEnrollRes = await fetch(`${baseUrl}/agents/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: token,
        hostname: 'ws-finance-01-clone'
      })
    });
    assert.strictEqual(reEnrollRes.status, 401, 'Re-enrollment with used token must return 401');
    console.log('✔ Passed: Single-use enrollment verified; second enrollment attempt rejected');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Heartbeat with invalid credentials -> 401
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Heartbeat with Invalid Credentials -> 401 ---');
    const badHeartbeatRes = await fetch(`${baseUrl}/agents/${enrolledBody.device_id}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_id: enrolledBody.credential_id,
        credential_secret: 'incorrect-secret-string',
        agent_version: '1.0.0'
      })
    });
    assert.strictEqual(badHeartbeatRes.status, 401, 'Must return 401 for wrong credential secret');
    console.log('✔ Passed: Invalid credential heartbeat rejected with 401');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 7: Heartbeat with valid credentials -> status='online', last_heartbeat updated
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 7: Successful Agent Heartbeat ---');
    const goodHeartbeatRes = await fetch(`${baseUrl}/agents/${enrolledBody.device_id}/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_id: enrolledBody.credential_id,
        credential_secret: enrolledBody.credential_secret,
        agent_version: '1.0.1',
        network_connections_count: 14
      })
    });
    assert.strictEqual(goodHeartbeatRes.status, 200, 'Must return 200 on valid heartbeat');
    const heartbeatBody = await goodHeartbeatRes.json();
    assert.strictEqual(heartbeatBody.status, 'online');
    assert.strictEqual(heartbeatBody.next_heartbeat_in_seconds, 60);
    assert.strictEqual(heartbeatBody.commands_pending, 0);

    const devAfterHb = await Device.findById(enrolledBody.device_id);
    assert.ok(devAfterHb.last_heartbeat, 'last_heartbeat must be updated');
    assert.strictEqual(devAfterHb.agent_version, '1.0.1', 'Agent version should be updated');
    console.log(`✔ Passed: Heartbeat recorded, status=online, last_heartbeat=${devAfterHb.last_heartbeat.toISOString()}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 8: Get commands for device (empty initially)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 8: Fetch Commands (Initially Empty) ---');
    const emptyCmdsRes = await fetch(
      `${baseUrl}/agents/${enrolledBody.device_id}/commands?credential_id=${enrolledBody.credential_id}&credential_secret=${enrolledBody.credential_secret}`
    );
    assert.strictEqual(emptyCmdsRes.status, 200, 'Must return 200 for valid command fetch');
    const emptyCmdsBody = await emptyCmdsRes.json();
    assert.deepStrictEqual(emptyCmdsBody.commands, [], 'Commands list should be empty initially');
    console.log('✔ Passed: Empty command list verified');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 9: Create command via DB insert (admin action), GET /commands confirms agent sees it
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 9: Command Dispatched to Agent ---');
    const insertCmdRes = await db.query(
      `INSERT INTO public.agent_commands (
        device_id, organization_id, command_type, target_data, status
      ) VALUES ($1, $2, 'collect_snapshot', '{"depth": "deep"}'::jsonb, 'pending')
      RETURNING *;`,
      [enrolledBody.device_id, org1.id]
    );
    const command = insertCmdRes.rows[0];
    createdCommandIds.push(command.id);

    const fetchCmdsRes = await fetch(
      `${baseUrl}/agents/${enrolledBody.device_id}/commands?credential_id=${enrolledBody.credential_id}&credential_secret=${enrolledBody.credential_secret}`
    );
    assert.strictEqual(fetchCmdsRes.status, 200);
    const fetchCmdsBody = await fetchCmdsRes.json();
    assert.strictEqual(fetchCmdsBody.commands.length, 1);
    assert.strictEqual(fetchCmdsBody.commands[0].id, command.id);
    assert.strictEqual(fetchCmdsBody.commands[0].command_type, 'collect_snapshot');
    assert.strictEqual(fetchCmdsBody.commands[0].status, 'pending');
    console.log(`✔ Passed: Agent picked up pending command ${command.id} (${command.command_type})`);

    // Also verify heartbeat now reports commands_pending: 1
    const hbWithPending = await agentService.recordHeartbeat(
      enrolledBody.device_id,
      enrolledBody.credential_id,
      enrolledBody.credential_secret
    );
    assert.strictEqual(hbWithPending.commands_pending, 1, 'Heartbeat must indicate 1 command pending');
    console.log('✔ Passed: Heartbeat reflects pending command count (1)');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 10: Report command result via POST -> command.status='completed'
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 10: Report Command Result -> Completed ---');
    const reportRes = await fetch(`${baseUrl}/agents/${enrolledBody.device_id}/commands/${command.id}/result`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_id: enrolledBody.credential_id,
        credential_secret: enrolledBody.credential_secret,
        status: 'completed',
        result: {
          processes_count: 142,
          network_connections: 28,
          integrity_verified: true
        }
      })
    });
    assert.strictEqual(reportRes.status, 200);
    const reportBody = await reportRes.json();
    assert.strictEqual(reportBody.success, true);

    const cmdInDb = await db.query(`SELECT * FROM public.agent_commands WHERE id = $1;`, [command.id]);
    assert.strictEqual(cmdInDb.rows[0].status, 'completed');
    assert.ok(cmdInDb.rows[0].executed_at, 'executed_at must be populated');
    const parsedRes = typeof cmdInDb.rows[0].result === 'string' ? JSON.parse(cmdInDb.rows[0].result) : cmdInDb.rows[0].result;
    assert.strictEqual(parsedRes.processes_count, 142);
    console.log(`✔ Passed: Command marked completed with output stored in DB`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 11: Cross-tenant device status check: Org 1 sees device, Org 2 gets 404
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 11: Multi-Tenant Scoping (Org 1 Admin vs Org 2 Admin) ---');
    // Admin 1 (same org)
    const statusAdmin1Res = await fetch(`${baseUrl}/agents/${enrolledBody.device_id}/status`, {
      headers: { Authorization: `Bearer ${admin1Token}` }
    });
    assert.strictEqual(statusAdmin1Res.status, 200, 'Org 1 admin must see device');
    const statusAdmin1Body = await statusAdmin1Res.json();
    assert.strictEqual(statusAdmin1Body.id, enrolledBody.device_id);
    assert.strictEqual(statusAdmin1Body.organization_id, org1.id);
    assert.strictEqual(statusAdmin1Body.status, 'online');
    assert.ok(statusAdmin1Body.last_heartbeat_age_seconds !== undefined);
    console.log(`✔ Passed: Admin 1 retrieved device status (age: ${statusAdmin1Body.last_heartbeat_age_seconds}s)`);

    // Admin 2 (different org) -> Must return 404 Not Found (never 403 to prevent enumeration)
    const statusAdmin2Res = await fetch(`${baseUrl}/agents/${enrolledBody.device_id}/status`, {
      headers: { Authorization: `Bearer ${admin2Token}` }
    });
    assert.strictEqual(statusAdmin2Res.status, 404, 'Cross-tenant access must return 404 Not Found');
    console.log('✔ Passed: Admin 2 received 404 Not Found on Org 1 device');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 12: Model Wrapper Delegation Verification
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 12: Agent Model Delegation ---');
    const modelStatus = await Agent.getStatus(enrolledBody.device_id, org1.id);
    assert.strictEqual(modelStatus.id, enrolledBody.device_id);

    const modelCmds = await Agent.getCommands(
      enrolledBody.device_id,
      enrolledBody.credential_id,
      enrolledBody.credential_secret
    );
    assert.ok(Array.isArray(modelCmds));

    const modelHb = await Agent.recordHeartbeat(
      enrolledBody.device_id,
      enrolledBody.credential_id,
      enrolledBody.credential_secret,
      { agent_version: '1.0.2' }
    );
    assert.strictEqual(modelHb.status, 'online');
    console.log('✔ Passed: Agent model delegates cleanly to agentService');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL PHASE A ENTERPRISE AGENT BACKEND TESTS PASSED! (12/12)');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    if (server) {
      server.close();
    }

    console.log('--- Teardown: Cleaning Test Records ---');
    if (createdCommandIds.length > 0) {
      await db.query(`DELETE FROM public.agent_commands WHERE id = ANY($1::uuid[]);`, [createdCommandIds]);
    }
    if (createdDeviceIds.length > 0) {
      await db.query(`DELETE FROM public.devices WHERE id = ANY($1::uuid[]);`, [createdDeviceIds]);
    }
    if (createdUserIds.length > 0) {
      await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
    }
    if (createdOrgIds.length > 0) {
      await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
    }
    console.log('✔ Cleanup complete.');
  }
}

if (require.main === module) {
  runEnterpriseAgentBackendTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ TEST FAILURE:', err);
      process.exit(1);
    });
}

module.exports = { runEnterpriseAgentBackendTests };
