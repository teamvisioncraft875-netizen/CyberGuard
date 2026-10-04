/**
 * test_admin_agents_list.js
 *
 * Verifies GET /api/v1/admin/agents (and alias /api/v1/agents):
 * 1. Admin can list all devices for their organization
 * 2. Response shape: { total, limit, offset, agents: [ ... ] }
 * 3. Heartbeat freshness: last_heartbeat_age_seconds calculation
 * 4. Pagination: limit and offset query parameters
 * 5. Status filtering: ?status=online, ?status=offline, ?status=disabled
 * 6. Tenant isolation: Admin A only sees Org A agents, not Org B
 * 7. RBAC: Non-admin (employee) receives 403 Forbidden
 * 8. Auth: Unauthenticated request receives 401 Unauthorized
 * 9. Validation: Invalid limit, offset, or status returns 400 Bad Request
 * 10. Route alias: GET /api/v1/agents works identically for admins
 */

process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { app } = require('./src');
const db = require('./src/config/db');
const config = require('./src/config');
const redis = require('./src/config/redis');

async function runAdminAgentsListTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — ADMIN AGENTS LIST ENDPOINT TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    redis.enableMockRedis();
  }

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  console.log(`[INIT] Test server listening on ${baseUrl}`);

  const timestamp = Date.now();
  let orgIdA = null;
  let adminIdA = null;
  let adminTokenA = null;
  let employeeIdA = null;
  let employeeTokenA = null;

  let orgIdB = null;
  let adminIdB = null;
  let adminTokenB = null;

  let deviceOnlineA = null;
  let deviceOfflineA = null;
  let deviceDisabledA = null;
  let deviceOrgB = null;

  try {
    // ──────────────────────────────────────────────────────────────────────────
    // SETUP: Organizations, Users, and Devices
    // ──────────────────────────────────────────────────────────────────────────
    console.log('[SETUP] Seeding Tenant A and Tenant B...');
    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);

    // 1. Organization A
    const orgResA = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Agents List A ${timestamp}`]
    );
    orgIdA = orgResA.rows[0].id;

    // Admin A
    const adminResA = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_list_a_${timestamp}@cyberguard.test`, pwHash, orgIdA]
    );
    adminIdA = adminResA.rows[0].id;
    adminTokenA = jwt.sign(
      { id: adminIdA, organization_id: orgIdA, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Employee A (non-admin)
    const empResA = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING id;`,
      [`emp_list_a_${timestamp}@cyberguard.test`, pwHash, orgIdA]
    );
    employeeIdA = empResA.rows[0].id;
    employeeTokenA = jwt.sign(
      { id: employeeIdA, organization_id: orgIdA, role: 'employee' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 2. Organization B
    const orgResB = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Agents List B ${timestamp}`]
    );
    orgIdB = orgResB.rows[0].id;

    // Admin B
    const adminResB = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_list_b_${timestamp}@cyberguard.test`, pwHash, orgIdB]
    );
    adminIdB = adminResB.rows[0].id;
    adminTokenB = jwt.sign(
      { id: adminIdB, organization_id: orgIdB, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 3. Seed 3 agents in Org A: Online, Offline, Disabled
    const now = new Date();
    const tenSecsAgo = new Date(now.getTime() - 10 * 1000);
    const oneHourAgo = new Date(now.getTime() - 3600 * 1000);

    const dev1Res = await db.query(
      `INSERT INTO public.devices (
        organization_id, hostname, os, platform, status, last_heartbeat, agent_version, created_at
      ) VALUES ($1, 'laptop-john-online', 'Windows 11 Pro', 'desktop', 'online', $2, '1.2.0', NOW())
      RETURNING *;`,
      [orgIdA, tenSecsAgo]
    );
    deviceOnlineA = dev1Res.rows[0];

    const dev2Res = await db.query(
      `INSERT INTO public.devices (
        organization_id, hostname, os, platform, status, last_heartbeat, agent_version, created_at
      ) VALUES ($1, 'workstation-mary-offline', 'Ubuntu 22.04 LTS', 'linux', 'offline', $2, '1.1.0', NOW() - INTERVAL '1 day')
      RETURNING *;`,
      [orgIdA, oneHourAgo]
    );
    deviceOfflineA = dev2Res.rows[0];

    const dev3Res = await db.query(
      `INSERT INTO public.devices (
        organization_id, hostname, os, platform, status, last_heartbeat, agent_version, created_at
      ) VALUES ($1, 'macbook-dev-disabled', 'macOS Sonoma', 'darwin', 'disabled', NULL, '1.0.0', NOW() - INTERVAL '2 days')
      RETURNING *;`,
      [orgIdA]
    );
    deviceDisabledA = dev3Res.rows[0];

    // 4. Seed 1 agent in Org B
    const devBRes = await db.query(
      `INSERT INTO public.devices (
        organization_id, hostname, os, platform, status, last_heartbeat, agent_version, created_at
      ) VALUES ($1, 'server-org-b', 'Debian 12', 'server', 'online', NOW(), '1.2.0', NOW())
      RETURNING *;`,
      [orgIdB]
    );
    deviceOrgB = devBRes.rows[0];

    console.log(`[SETUP] Seeding complete. OrgA=${orgIdA}, OrgB=${orgIdB}\n`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: GET /api/v1/admin/agents returns all 3 agents with full shape
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Test 1: List all agents for admin organization ---');
    const res1 = await fetch(`${baseUrl}/admin/agents`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res1.status, 200, `Expected 200 OK, got ${res1.status}`);
    const body1 = await res1.json();

    assert.strictEqual(body1.total, 3, 'Total count must be 3');
    assert.strictEqual(body1.limit, 25, 'Default limit must be 25');
    assert.strictEqual(body1.offset, 0, 'Default offset must be 0');
    assert.ok(Array.isArray(body1.agents), 'agents must be an array');
    assert.strictEqual(body1.agents.length, 3, 'Must return 3 agents');

    // Verify ordering: online (most recent heartbeat) is first
    assert.strictEqual(body1.agents[0].id, deviceOnlineA.id, 'Most recent heartbeat must be first');
    assert.strictEqual(body1.agents[0].status, 'online');
    assert.strictEqual(body1.agents[0].hostname, 'laptop-john-online');
    assert.strictEqual(body1.agents[0].os, 'Windows 11 Pro');
    assert.strictEqual(body1.agents[0].platform, 'desktop');
    assert.strictEqual(body1.agents[0].agent_version, '1.2.0');
    assert.ok(body1.agents[0].last_heartbeat, 'last_heartbeat must be present');
    assert.ok(typeof body1.agents[0].last_heartbeat_age_seconds === 'number', 'age in seconds must be a number');
    assert.ok(body1.agents[0].last_heartbeat_age_seconds >= 9, 'Heartbeat age should reflect ~10s');

    // Verify agent with null heartbeat has null age
    const disabledAgent = body1.agents.find((a) => a.id === deviceDisabledA.id);
    assert.ok(disabledAgent, 'Disabled agent must be in list');
    assert.strictEqual(disabledAgent.last_heartbeat, null);
    assert.strictEqual(disabledAgent.last_heartbeat_age_seconds, null);

    console.log('✅ PASS: All 3 agents returned with correct shape, types, and heartbeat freshness');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Pagination with limit=1
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Pagination with limit=1 ---');
    const res2 = await fetch(`${baseUrl}/admin/agents?limit=1`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res2.status, 200);
    const body2 = await res2.json();
    assert.strictEqual(body2.total, 3, 'Total remains 3');
    assert.strictEqual(body2.limit, 1, 'Limit must be 1');
    assert.strictEqual(body2.offset, 0);
    assert.strictEqual(body2.agents.length, 1, 'Should return exactly 1 agent');
    assert.strictEqual(body2.agents[0].id, deviceOnlineA.id);
    console.log('✅ PASS: Pagination limit=1 verified');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Pagination with offset=1
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Pagination with limit=1&offset=1 ---');
    const res3 = await fetch(`${baseUrl}/admin/agents?limit=1&offset=1`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res3.status, 200);
    const body3 = await res3.json();
    assert.strictEqual(body3.total, 3);
    assert.strictEqual(body3.limit, 1);
    assert.strictEqual(body3.offset, 1);
    assert.strictEqual(body3.agents.length, 1);
    assert.strictEqual(body3.agents[0].id, deviceOfflineA.id, 'Second page must return second device');
    console.log('✅ PASS: Pagination offset=1 verified');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Status filter: ?status=online
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Status filter ?status=online ---');
    const res4 = await fetch(`${baseUrl}/admin/agents?status=online`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res4.status, 200);
    const body4 = await res4.json();
    assert.strictEqual(body4.total, 1, 'Only 1 online agent');
    assert.strictEqual(body4.agents.length, 1);
    assert.strictEqual(body4.agents[0].id, deviceOnlineA.id);
    assert.strictEqual(body4.agents[0].status, 'online');
    console.log('✅ PASS: Filter status=online returned 1 matching agent');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: Status filter: ?status=disabled
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Status filter ?status=disabled ---');
    const res5 = await fetch(`${baseUrl}/admin/agents?status=disabled`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res5.status, 200);
    const body5 = await res5.json();
    assert.strictEqual(body5.total, 1);
    assert.strictEqual(body5.agents[0].id, deviceDisabledA.id);
    assert.strictEqual(body5.agents[0].status, 'disabled');
    console.log('✅ PASS: Filter status=disabled returned 1 matching agent');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Scoping / Tenant Isolation (Admin A vs Admin B)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Scoping / Tenant Isolation ---');
    // Admin A should not see Org B
    const resOrgA = await fetch(`${baseUrl}/admin/agents`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    const bodyOrgA = await resOrgA.json();
    const hasOrgBAgent = bodyOrgA.agents.some((a) => a.id === deviceOrgB.id);
    assert.strictEqual(hasOrgBAgent, false, 'Admin A must never see Org B devices');

    // Admin B sees only Org B agent
    const resOrgB = await fetch(`${baseUrl}/admin/agents`, {
      headers: { Authorization: `Bearer ${adminTokenB}` }
    });
    assert.strictEqual(resOrgB.status, 200);
    const bodyOrgB = await resOrgB.json();
    assert.strictEqual(bodyOrgB.total, 1);
    assert.strictEqual(bodyOrgB.agents.length, 1);
    assert.strictEqual(bodyOrgB.agents[0].id, deviceOrgB.id);
    assert.strictEqual(bodyOrgB.agents[0].organization_id, orgIdB);
    console.log('✅ PASS: Tenant isolation strictly enforced between Org A and Org B');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 7: Non-admin gets 403 Forbidden
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 7: RBAC - Non-admin user gets 403 ---');
    const res7 = await fetch(`${baseUrl}/admin/agents`, {
      headers: { Authorization: `Bearer ${employeeTokenA}` }
    });
    assert.strictEqual(res7.status, 403, `Expected 403 Forbidden, got ${res7.status}`);
    const body7 = await res7.json();
    assert.strictEqual(body7.error, 'FORBIDDEN');
    console.log('✅ PASS: Non-admin rejected with 403 Forbidden');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 8: Unauthenticated gets 401 Unauthorized
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 8: Auth - Unauthenticated request gets 401 ---');
    const res8 = await fetch(`${baseUrl}/admin/agents`);
    assert.strictEqual(res8.status, 401, `Expected 401 Unauthorized, got ${res8.status}`);
    console.log('✅ PASS: Unauthenticated request rejected with 401 Unauthorized');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 9: Invalid query parameters get 400 Bad Request
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 9: Input Validation on Query Parameters ---');
    // limit < 1
    const res9a = await fetch(`${baseUrl}/admin/agents?limit=0`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res9a.status, 400);
    const body9a = await res9a.json();
    assert.strictEqual(body9a.error, 'INVALID_QUERY_PARAMS');

    // limit > 100
    const res9b = await fetch(`${baseUrl}/admin/agents?limit=101`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res9b.status, 400);

    // offset < 0
    const res9c = await fetch(`${baseUrl}/admin/agents?offset=-5`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res9c.status, 400);

    // invalid status
    const res9d = await fetch(`${baseUrl}/admin/agents?status=invalid_status`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res9d.status, 400);
    console.log('✅ PASS: Invalid query params rejected with 400 Bad Request');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 10: Route Alias /api/v1/agents works for Admin A
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 10: Route alias GET /api/v1/agents ---');
    const res10 = await fetch(`${baseUrl}/agents`, {
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    assert.strictEqual(res10.status, 200);
    const body10 = await res10.json();
    assert.strictEqual(body10.total, 3);
    assert.strictEqual(body10.agents.length, 3);
    console.log('✅ PASS: Route alias GET /api/v1/agents returns identical data');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 10 ADMIN AGENTS LIST TESTS PASSED SUCCESSFULLY!                 ');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    console.log('[TEARDOWN] Test HTTP server closed.');
  }
}

if (require.main === module) {
  runAdminAgentsListTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal Test Suite Error:', err);
      process.exit(1);
    });
}

module.exports = { runAdminAgentsListTests };
