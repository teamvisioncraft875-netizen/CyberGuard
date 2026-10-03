process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { app } = require('./src');
const db = require('./src/config/db');
const redis = require('./src/config/redis');
const RefreshToken = require('./src/models/RefreshToken');
const AuditLog = require('./src/models/AuditLog');

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

async function runActionExecutionEndpointTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 2B LIVE ACTION EXECUTION ENDPOINT TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    console.log('[REDIS] Live Redis not connected, activating in-memory mock engine');
    redis.enableMockRedis();
  }

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdIncidentIds = [];
  const createdPolicyIds = [];
  const createdActionIds = [];
  const createdAuditLogIds = [];

  const timestamp = Date.now();

  try {
    // 0. Start ephemeral HTTP test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}`);
        resolve();
      });
    });

    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Seed Organizations and Users
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Setup: Seeding Test Organizations & Users ---');
    const passwordHash = await bcrypt.hash('P@ssword123!', 10);

    // Org 1 + Admin 1 + Employee 1
    const org1Res = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org 1 Exec Endpoint ${timestamp}`]
    );
    const org1 = org1Res.rows[0];
    createdOrgIds.push(org1.id);

    const admin1Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin1_exec_${timestamp}@cyberguard.internal`, passwordHash, org1.id]
    );
    const admin1 = admin1Res.rows[0];
    createdUserIds.push(admin1.id);
    const admin1Token = createToken(admin1);

    const employee1Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING *;`,
      [`emp1_exec_${timestamp}@cyberguard.internal`, passwordHash, org1.id]
    );
    const employee1 = employee1Res.rows[0];
    createdUserIds.push(employee1.id);
    const employee1Token = createToken(employee1);

    // Org 2 + Admin 2
    const org2Res = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org 2 Exec Endpoint ${timestamp}`]
    );
    const org2 = org2Res.rows[0];
    createdOrgIds.push(org2.id);

    const admin2Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin2_exec_${timestamp}@cyberguard.internal`, passwordHash, org2.id]
    );
    const admin2 = admin2Res.rows[0];
    createdUserIds.push(admin2.id);
    const admin2Token = createToken(admin2);

    // Incident in Org 1
    const incRes = await db.query(
      `INSERT INTO public.incidents (user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation)
       VALUES ($1, $2, 'account_takeover', 'login', 95, 'critical', 'open', 'Credential takeover test incident')
       RETURNING *;`,
      [employee1.id, org1.id]
    );
    const incident1 = incRes.rows[0];
    createdIncidentIds.push(incident1.id);

    // Policy in Org 1
    const polRes = await db.query(
      `INSERT INTO public.response_policies (organization_id, name, enabled, created_by_id, rules)
       VALUES ($1, 'Live Exec Test Policy', true, $2, $3)
       RETURNING *;`,
      [
        org1.id,
        admin1.id,
        JSON.stringify([
          { threat_type: 'account_takeover', min_score: 80, action_type: 'revoke_session', action_mode: 'live' }
        ])
      ]
    );
    const policy1 = polRes.rows[0];
    createdPolicyIds.push(policy1.id);

    console.log(`✔ Org1: ${org1.id}, Admin1: ${admin1.email}`);
    console.log(`✔ Org2: ${org2.id}, Admin2: ${admin2.email}`);

    // Helper to insert a response action
    async function createActionRow(overrides = {}) {
      const defaults = {
        organization_id: org1.id,
        incident_id: incident1.id,
        policy_id: policy1.id,
        action_type: 'revoke_session',
        action_mode: 'live',
        status: 'approved',
        requested_by_id: null,
        approved_by_id: admin1.id,
        approved_at: new Date(),
        target: { user_id: employee1.id },
        execution_attempts: 0
      };
      const merged = { ...defaults, ...overrides };
      const res = await db.query(
        `INSERT INTO public.response_actions (
          organization_id, incident_id, policy_id, action_type, action_mode, status,
          requested_by_id, approved_by_id, approved_at, target, execution_attempts
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *;`,
        [
          merged.organization_id,
          merged.incident_id,
          merged.policy_id,
          merged.action_type,
          merged.action_mode,
          merged.status,
          merged.requested_by_id,
          merged.approved_by_id,
          merged.approved_at,
          JSON.stringify(merged.target),
          merged.execution_attempts
        ]
      );
      const row = res.rows[0];
      createdActionIds.push(row.id);
      return row;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: POST /admin/actions/:id/execute as admin -> 200, status='executed'
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: POST /admin/actions/:id/execute as admin ---');
    // Create an active token for employee
    const rawToken = await RefreshToken.create(employee1.id);
    const tokenHash = RefreshToken.hash(rawToken);
    const validBefore = await RefreshToken.findValid(tokenHash, employee1.id);
    assert.strictEqual(validBefore, employee1.id);

    const action1 = await createActionRow({
      action_type: 'revoke_session',
      target: { user_id: employee1.id }
    });

    const execRes1 = await fetch(`${baseUrl}/admin/actions/${action1.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      }
    });

    assert.strictEqual(execRes1.status, 200, `Expected 200 OK, got ${execRes1.status}`);
    const body1 = await execRes1.json();

    assert.strictEqual(body1.success, true);
    assert.strictEqual(body1.action.status, 'executed');
    assert(body1.result.revoked_tokens >= 1);
    assert.strictEqual(body1.result.user_id, employee1.id);

    // Verify database row
    const dbAction1 = await db.query(`SELECT status, executed_at, result FROM public.response_actions WHERE id = $1;`, [action1.id]);
    assert.strictEqual(dbAction1.rows[0].status, 'executed');
    assert(dbAction1.rows[0].executed_at, 'executed_at must be populated');

    // Assert audit_log entry created with action='action_executed'
    const auditRes = await db.query(
      `SELECT * FROM public.audit_logs WHERE resource_id = $1 AND action = 'action_executed';`,
      [action1.id]
    );
    assert(auditRes.rows.length >= 1, 'Expected audit_log row for action_executed');
    createdAuditLogIds.push(auditRes.rows[0].id);
    console.log('PASS: 200 OK, status="executed", executor result verified, audit_log created');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Call same endpoint again (status now 'executed') -> 400 EXECUTION_GUARD_REJECTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Re-executing already executed action -> 400 EXECUTION_GUARD_REJECTED ---');
    const execRes2 = await fetch(`${baseUrl}/admin/actions/${action1.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      }
    });

    assert.strictEqual(execRes2.status, 400, `Expected 400 Bad Request, got ${execRes2.status}`);
    const body2 = await execRes2.json();
    assert.strictEqual(body2.error, 'EXECUTION_GUARD_REJECTED');
    assert(body2.message.includes('executed'));
    console.log('PASS: Re-execution rejected with 400 EXECUTION_GUARD_REJECTED');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Execute as non-admin -> 403 Forbidden
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Execute as non-admin -> 403 Forbidden ---');
    const action3 = await createActionRow({
      action_type: 'revoke_session',
      target: { user_id: employee1.id }
    });

    const execRes3 = await fetch(`${baseUrl}/admin/actions/${action3.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${employee1Token}`
      }
    });

    assert.strictEqual(execRes3.status, 403, `Expected 403 Forbidden, got ${execRes3.status}`);
    console.log('PASS: Non-admin rejected with 403 Forbidden');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Execute action from different org -> 404 Not Found
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Cross-tenant execution -> 404 Not Found ---');
    const execRes4 = await fetch(`${baseUrl}/admin/actions/${action3.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin2Token}` // Org 2 admin trying to execute Org 1 action
      }
    });

    assert.strictEqual(execRes4.status, 404, `Expected 404 Not Found, got ${execRes4.status}`);
    const body4 = await execRes4.json();
    assert.strictEqual(body4.error, 'NOT_FOUND');
    console.log('PASS: Cross-tenant execution returned 404 Not Found');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: Execute action with action_mode='shadow' -> 400 EXECUTION_GUARD_REJECTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Execute action with action_mode="shadow" -> 400 ---');
    const shadowAction = await createActionRow({
      action_mode: 'shadow',
      status: 'approved'
    });

    const execRes5 = await fetch(`${baseUrl}/admin/actions/${shadowAction.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      }
    });

    assert.strictEqual(execRes5.status, 400, `Expected 400 Bad Request, got ${execRes5.status}`);
    const body5 = await execRes5.json();
    assert.strictEqual(body5.error, 'EXECUTION_GUARD_REJECTED');
    assert(body5.message.toLowerCase().includes('shadow'));
    console.log('PASS: Shadow action execution rejected with 400 with message about shadow mode');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Block IP on protected IP 127.0.0.1 -> 400 EXECUTION_GUARD_REJECTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Block IP on 127.0.0.1 -> 400 with "protected" ---');
    const protectedIpAction = await createActionRow({
      action_type: 'block_ip',
      target: { ip_address: '127.0.0.1' },
      status: 'approved',
      action_mode: 'live'
    });

    const execRes6 = await fetch(`${baseUrl}/admin/actions/${protectedIpAction.id}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      }
    });

    assert.strictEqual(execRes6.status, 400, `Expected 400 Bad Request, got ${execRes6.status}`);
    const body6 = await execRes6.json();
    assert.strictEqual(body6.error, 'EXECUTION_GUARD_REJECTED');
    assert(body6.message.toLowerCase().includes('protected'));
    console.log('PASS: Protected IP block rejected with 400 "target is protected"');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL ACTION EXECUTION ENDPOINT TESTS PASSED! (6/6)');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    if (server) {
      server.close();
    }

    console.log('--- Teardown: Cleaning Test Records ---');
    try {
      for (const id of createdAuditLogIds) {
        await db.query(`DELETE FROM public.audit_logs WHERE id = $1;`, [id]);
      }
      for (const id of createdActionIds) {
        await db.query(`DELETE FROM public.response_actions WHERE id = $1;`, [id]);
      }
      for (const id of createdPolicyIds) {
        await db.query(`DELETE FROM public.response_policies WHERE id = $1;`, [id]);
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

runActionExecutionEndpointTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\n✖ TEST SUITE FAILED:', err);
    process.exit(1);
  });
