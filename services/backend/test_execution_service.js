process.env.NODE_ENV = 'test';

const assert = require('assert');
const bcrypt = require('bcrypt');
const db = require('./src/config/db');
const redis = require('./src/config/redis');
const RefreshToken = require('./src/models/RefreshToken');
const Device = require('./src/models/Device');
const executionService = require('./src/services/executionService');

async function runExecutionServiceTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 2A EXECUTION SERVICE TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  // Enable Redis mock if real server is unavailable
  if (!redis.isConnected()) {
    console.log('[REDIS] Live Redis not connected, activating in-memory mock engine');
    redis.enableMockRedis();
  }

  const timestamp = Date.now();
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdIncidentIds = [];
  const createdActionIds = [];
  const createdDeviceIds = [];

  try {
    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Seed Organization, Admin User, and Base Incident
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Setup: Seeding Database Entities ---');
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org Exec Test ${timestamp}`]
    );
    const org = orgRes.rows[0];
    createdOrgIds.push(org.id);

    const passwordHash = await bcrypt.hash('P@ssword123!', 10);
    const userRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING *;`,
      [`user_exec_${timestamp}@cyberguard.internal`, passwordHash, org.id]
    );
    const user = userRes.rows[0];
    createdUserIds.push(user.id);

    const incRes = await db.query(
      `INSERT INTO public.incidents (user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation)
       VALUES ($1, $2, 'account_takeover', 'login', 90, 'critical', 'open', 'Automated Test Incident') RETURNING *;`,
      [user.id, org.id]
    );
    const incident = incRes.rows[0];
    createdIncidentIds.push(incident.id);

    console.log(`✔ Seeded: Org=${org.id}, User=${user.id}, Incident=${incident.id}`);

    // Helper to insert an action row
    async function createTestRow(attrs = {}) {
      const defaultAttrs = {
        organization_id: org.id,
        incident_id: incident.id,
        action_type: 'revoke_session',
        action_mode: 'live',
        status: 'approved',
        target: { user_id: user.id },
        execution_attempts: 0
      };
      const merged = { ...defaultAttrs, ...attrs };
      const res = await db.query(
        `INSERT INTO public.response_actions (
          organization_id, incident_id, action_type, action_mode, status, target, execution_attempts
        ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;`,
        [
          merged.organization_id,
          merged.incident_id,
          merged.action_type,
          merged.action_mode,
          merged.status,
          JSON.stringify(merged.target),
          merged.execution_attempts
        ]
      );
      const row = res.rows[0];
      createdActionIds.push(row.id);
      return row;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: revoke session
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: Revoke Session Execution ---');
    // Generate an active refresh token for user
    const rawToken = await RefreshToken.create(user.id);
    const tokenHash = RefreshToken.hash(rawToken);
    const validBefore = await RefreshToken.findValid(tokenHash, user.id);
    assert.strictEqual(validBefore, user.id, 'Token should be valid prior to revocation');

    const revokeAction = await createTestRow({
      action_type: 'revoke_session',
      target: { user_id: user.id }
    });

    const revokeResult = await executionService.execute(revokeAction);
    assert.strictEqual(revokeResult.success, true, 'revokeSession execution must succeed');
    assert(revokeResult.result.revoked_tokens >= 1, 'Expected at least 1 token revoked');
    assert.strictEqual(revokeResult.result.user_id, user.id);

    // Verify DB update
    const dbRevokeRes = await db.query(`SELECT status, executed_at, result FROM public.response_actions WHERE id = $1;`, [revokeAction.id]);
    assert.strictEqual(dbRevokeRes.rows[0].status, 'executed', 'DB status must be executed');
    assert(dbRevokeRes.rows[0].executed_at, 'executed_at must be set');

    // Verify token invalidated
    const validAfter = await RefreshToken.findValid(tokenHash, user.id);
    assert.strictEqual(validAfter, null, 'Token must be invalidated after revocation');
    console.log('PASS: revoke_session executed, RefreshToken.revokeByUserId revoked tokens and status=executed');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: block IP
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Block IP Execution ---');
    const externalIp = '198.51.100.42';
    const blockIpAction = await createTestRow({
      action_type: 'block_ip',
      target: { ip_address: externalIp }
    });

    const blockIpResult = await executionService.execute(blockIpAction);
    assert.strictEqual(blockIpResult.success, true, 'blockIp execution must succeed');
    assert.strictEqual(blockIpResult.result.blocked_ip, externalIp);

    const redisIpVal = await redis.get(`blocked_ips:${blockIpAction.id}`);
    assert.strictEqual(redisIpVal, externalIp, 'Redis key blocked_ips:<id> must contain the IP');

    const dbBlockRes = await db.query(`SELECT status FROM public.response_actions WHERE id = $1;`, [blockIpAction.id]);
    assert.strictEqual(dbBlockRes.rows[0].status, 'executed');
    console.log('PASS: block_ip executed, Redis key verified and GET retrieved value');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: block IP protected
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Protected IP Guardrail (127.0.0.1) ---');
    const protectedIpAction = await createTestRow({
      action_type: 'block_ip',
      target: { ip_address: '127.0.0.1' }
    });

    const protectedIpResult = await executionService.execute(protectedIpAction);
    assert.strictEqual(protectedIpResult.success, false, 'Protected IP must fail');
    assert(protectedIpResult.error.toLowerCase().includes('protected'), 'Error must indicate protected target');

    const dbProtectedRes = await db.query(`SELECT status, last_execution_error FROM public.response_actions WHERE id = $1;`, [protectedIpAction.id]);
    assert.strictEqual(dbProtectedRes.rows[0].status, 'failed');
    console.log('PASS: block_ip on 127.0.0.1 refused with error: "target is protected"');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: suspend device
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Suspend Device Execution ---');
    const deviceId = `device_test_${timestamp}`;
    await db.query(
      `INSERT INTO public.devices (user_id, device_id, device_name, status, is_trusted)
       VALUES ($1, $2, 'Test Workstation', 'active', true);`,
      [user.id, deviceId]
    );
    createdDeviceIds.push(deviceId);

    const suspendDeviceAction = await createTestRow({
      action_type: 'suspend_device',
      target: { device_id: deviceId }
    });

    const suspendResult = await executionService.execute(suspendDeviceAction);
    assert.strictEqual(suspendResult.success, true, 'suspendDevice execution must succeed');
    assert.strictEqual(suspendResult.result.suspended_device_id, deviceId);

    const dbDeviceRes = await db.query(`SELECT status FROM public.devices WHERE device_id = $1;`, [deviceId]);
    assert.strictEqual(dbDeviceRes.rows[0].status, 'suspended', 'Device status must be updated to suspended');
    console.log('PASS: suspend_device executed and devices.status updated to "suspended"');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: force password reset
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Force Password Reset Execution ---');
    const resetAction = await createTestRow({
      action_type: 'force_password_reset',
      target: { user_id: user.id }
    });

    const resetResult = await executionService.execute(resetAction);
    assert.strictEqual(resetResult.success, true, 'forcePasswordReset execution must succeed');
    assert.strictEqual(resetResult.result.user_id, user.id);
    assert.strictEqual(resetResult.result.expires_in_days, 7);

    const redisResetVal = await redis.get(`password_reset_required:${user.id}`);
    assert.strictEqual(redisResetVal, 'true', 'Redis password_reset_required key must be true');
    console.log('PASS: force_password_reset executed, Redis key set with 7-day TTL');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Guardrail — Shadow Mode
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Guardrail — Shadow Mode Rejection ---');
    const shadowAction = await createTestRow({
      action_mode: 'shadow',
      status: 'approved'
    });

    let shadowFailedWith400 = false;
    try {
      await executionService.execute(shadowAction);
    } catch (err) {
      if (err.statusCode === 400 || err.status === 400 || err.message.includes('400')) {
        shadowFailedWith400 = true;
      }
    }
    assert.strictEqual(shadowFailedWith400, true, 'execute() with action_mode=shadow must throw 400');
    console.log('PASS: execute() with action_mode="shadow" rejected with 400');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 7: Guardrail — Proposed Status
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 7: Guardrail — Proposed Status Rejection ---');
    const proposedAction = await createTestRow({
      action_mode: 'live',
      status: 'proposed'
    });

    let proposedFailedWith400 = false;
    try {
      await executionService.execute(proposedAction);
    } catch (err) {
      if (err.statusCode === 400 || err.status === 400 || err.message.includes('400')) {
        proposedFailedWith400 = true;
      }
    }
    assert.strictEqual(proposedFailedWith400, true, 'execute() with status=proposed must throw 400');
    console.log('PASS: execute() with status="proposed" rejected with 400');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 8: Guardrail — Retry Limit Cap (Max 3)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 8: Guardrail — Retry Limit Cap (Max 3) ---');
    const retryAction = await createTestRow({
      action_type: 'revoke_session',
      target: { user_id: '00000000-0000-0000-0000-000000000000' }, // Non-existent user
      execution_attempts: 2
    });

    // 1st attempt: fails, increments to 3
    retryAction.target = {}; // trigger validation failure
    const attempt1 = await executionService.execute(retryAction);
    assert.strictEqual(attempt1.success, false);

    // Refresh action from DB to verify attempts = 3
    const refreshedRes = await db.query(`SELECT * FROM public.response_actions WHERE id = $1;`, [retryAction.id]);
    const refreshedAction = refreshedRes.rows[0];
    assert.strictEqual(refreshedAction.execution_attempts, 3, 'Attempts should now be 3');

    // 2nd call: execution_attempts is already 3 -> must immediately stop trying
    const attempt2 = await executionService.execute(refreshedAction);
    assert.strictEqual(attempt2.success, false, 'Must fail once cap reached');
    assert(
      attempt2.error.toLowerCase().includes('3') || attempt2.error.toLowerCase().includes('exceeded'),
      'Must indicate retry cap exceeded'
    );
    console.log('PASS: Retry limit capped at 3, stopped attempting further execution');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL PHASE 2A EXECUTION SERVICE TESTS PASSED! (8/8)');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    console.log('--- Teardown: Cleaning Test Records ---');
    try {
      for (const id of createdActionIds) {
        await db.query(`DELETE FROM public.response_actions WHERE id = $1;`, [id]);
      }
      for (const id of createdDeviceIds) {
        await db.query(`DELETE FROM public.devices WHERE device_id = $1;`, [id]);
      }
      for (const id of createdIncidentIds) {
        await db.query(`DELETE FROM public.incidents WHERE id = $1;`, [id]);
      }
      for (const id of createdUserIds) {
        await db.query(`DELETE FROM public.refresh_tokens WHERE user_id = $1;`, [id]);
        await db.query(`DELETE FROM public.users WHERE id = $1;`, [id]);
      }
      for (const id of createdOrgIds) {
        await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [id]);
      }
      console.log('✔ Cleanup complete.');
    } catch (cleanupErr) {
      console.error('[CLEANUP WARNING]', cleanupErr.message);
    }
  }
}

runExecutionServiceTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\n✖ TEST SUITE FAILED:', err);
    process.exit(1);
  });
