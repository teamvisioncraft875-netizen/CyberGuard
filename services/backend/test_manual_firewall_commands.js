/**
 * CYBERGUARD Phase C: Manual Firewall Commands Integration Test Suite
 * Validates POST /api/v1/admin/agents/:agent_id/firewall-commands
 *
 * Verifies:
 * 1. Admin can manually dispatch block_ip/block_domain directly to online agents
 * 2. Input validation enforces IP/domain syntax and protected target lists
 * 3. Enforces RBAC (admin only) and tenant isolation (cross-org rejected)
 * 4. Guards against sending commands to offline (404) or disabled (409) agents
 * 5. Rules are only created in agent_firewall_rules AFTER agent reports execution
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
const agentService = require('./src/services/agentService');

async function runManualFirewallCommandsTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C MANUAL FIREWALL COMMANDS INTEGRATION TESTS');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  console.log(`[INIT] Test server running on ${baseUrl}`);

  const timestamp = Date.now();
  let orgIdA = null;
  let orgIdB = null;
  let adminIdA = null;
  let adminTokenA = null;
  let analystTokenA = null;
  let deviceIdA = null;
  let credIdA = null;
  let credSecretA = null;
  let deviceIdB = null;

  try {
    // 1. Setup Tenant A and Admin User
    const orgResA = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Manual Cmd A ${timestamp}`]
    );
    orgIdA = orgResA.rows[0].id;

    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);
    const userResA = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_manual_${timestamp}@cyberguard.test`, pwHash, orgIdA]
    );
    adminIdA = userResA.rows[0].id;

    adminTokenA = jwt.sign(
      { id: adminIdA, organization_id: orgIdA, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Non-admin user (employee)
    const employeeResA = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING id;`,
      [`employee_manual_${timestamp}@cyberguard.test`, pwHash, orgIdA]
    );
    analystTokenA = jwt.sign(
      { id: employeeResA.rows[0].id, organization_id: orgIdA, role: 'employee' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 2. Setup Tenant B (for cross-org tests)
    const orgResB = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Manual Cmd B ${timestamp}`]
    );
    orgIdB = orgResB.rows[0].id;

    const enrollTokenB = await agentService.generateEnrollmentToken(orgIdB, 24);
    const enrolledB = await agentService.enrollDevice({
      token: enrollTokenB,
      hostname: `workstation-b-${timestamp}`,
      os: 'Linux Ubuntu 22.04',
      platform: 'linux',
      agent_version: '1.0.0'
    });
    deviceIdB = enrolledB.device_id;

    // 3. Enroll Agent A and Heartbeat to Online status
    const enrollTokenA = await agentService.generateEnrollmentToken(orgIdA, 24);
    const enrolledA = await agentService.enrollDevice({
      token: enrollTokenA,
      hostname: `workstation-a-${timestamp}`,
      os: 'Windows 11 Enterprise',
      platform: 'win32',
      agent_version: '1.0.0'
    });
    deviceIdA = enrolledA.device_id;
    credIdA = enrolledA.credential_id;
    credSecretA = enrolledA.credential_secret;

    // Send heartbeat to transition status to 'online'
    const heartbeatRes = await agentService.recordHeartbeat(
      deviceIdA,
      credIdA,
      credSecretA,
      { agent_version: '1.0.0' }
    );
    assert.strictEqual(heartbeatRes?.status, 'online', 'Agent must transition to online on heartbeat');

    console.log(`[SETUP] Initialized OrgA=${orgIdA}, AdminA=${adminIdA}, DeviceA=${deviceIdA} (Online), DeviceB=${deviceIdB}`);

    // --- TEST 1: Admin manually sends block_ip command to online agent ---
    console.log('\n--- Test 1: Admin manually sends block_ip command to online agent ---');
    const manualCmdRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '203.0.113.142' },
        reason: 'Manual ad-hoc testing'
      })
    });

    const manualCmdBody = await manualCmdRes.json();
    assert.strictEqual(manualCmdRes.status, 201, `Expected 201, got ${manualCmdRes.status}: ${JSON.stringify(manualCmdBody)}`);
    assert.strictEqual(manualCmdBody.success, true);
    assert.ok(manualCmdBody.command_id, 'Must return command_id');
    assert.strictEqual(manualCmdBody.status, 'pending');
    assert.strictEqual(manualCmdBody.agent_id, deviceIdA);
    const manualCommandId = manualCmdBody.command_id;

    // Verify row in agent_commands
    const dbCmdRes = await db.query(
      `SELECT * FROM public.agent_commands WHERE id = $1;`,
      [manualCommandId]
    );
    assert.strictEqual(dbCmdRes.rows.length, 1, 'agent_commands row must exist');
    assert.strictEqual(dbCmdRes.rows[0].command_type, 'block_ip');
    assert.strictEqual(dbCmdRes.rows[0].status, 'pending');
    assert.strictEqual(dbCmdRes.rows[0].can_execute, true);
    assert.strictEqual(dbCmdRes.rows[0].requested_by_id, adminIdA);

    // Verify agent_firewall_rules does NOT have rule yet
    const fwRuleCheck = await db.query(
      `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
      [manualCommandId]
    );
    assert.strictEqual(fwRuleCheck.rows.length, 0, 'agent_firewall_rules must NOT be created before execution');
    console.log(`✔ Passed: agent_commands row created (id=${manualCommandId}, can_execute=true, status='pending') without premature firewall rule`);

    // --- TEST 2: Agent polls and receives the manual command ---
    console.log('\n--- Test 2: Agent polls and receives the manual command ---');
    const pollRes = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
      method: 'GET',
      headers: {
        'x-agent-credential-id': credIdA,
        'x-agent-credential-secret': credSecretA
      }
    });

    const pollBody = await pollRes.json();
    assert.strictEqual(pollRes.status, 200, `Expected 200, got ${pollRes.status}`);
    const foundCmd = pollBody.commands.find((c) => c.id === manualCommandId);
    assert.ok(foundCmd, 'Agent must receive the manual command during polling');
    assert.strictEqual(foundCmd.command_type, 'block_ip');
    console.log(`✔ Passed: Agent successfully retrieved manual command ${manualCommandId} via GET /agents/:device_id/commands`);

    // --- TEST 3: Validation: Invalid IP rejected with 400 ---
    console.log('\n--- Test 3: Validation: Invalid IP rejected with 400 ---');
    const invalidIpRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: 'invalid-not-an-ip' }
      })
    });
    const invalidIpBody = await invalidIpRes.json();
    assert.strictEqual(invalidIpRes.status, 400, `Expected 400, got ${invalidIpRes.status}`);
    assert.ok(invalidIpBody.message.includes('Invalid IP address format'));
    console.log(`✔ Passed: Rejected invalid IP with error: "${invalidIpBody.message}"`);

    // --- TEST 4: Validation: Protected IP (127.0.0.1) rejected with 400 ---
    console.log('\n--- Test 4: Validation: Protected IP (127.0.0.1) rejected with 400 ---');
    const protectedIpRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '127.0.0.1' }
      })
    });
    const protectedIpBody = await protectedIpRes.json();
    assert.strictEqual(protectedIpRes.status, 400, `Expected 400, got ${protectedIpRes.status}`);
    assert.ok(protectedIpBody.message.includes('protected list'));
    console.log(`✔ Passed: Rejected protected IP: "${protectedIpBody.message}"`);

    // --- TEST 5: Authorization: Non-admin rejected with 403 ---
    console.log('\n--- Test 5: Authorization: Non-admin rejected with 403 ---');
    const nonAdminRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '203.0.113.50' }
      })
    });
    assert.strictEqual(nonAdminRes.status, 403, `Expected 403 for analyst, got ${nonAdminRes.status}`);
    console.log('✔ Passed: Non-admin user rejected with HTTP 403 Forbidden');

    // --- TEST 6: Tenant Boundary: Agent in different org rejected with 404 ---
    console.log('\n--- Test 6: Tenant Boundary: Agent in different org rejected with 404 ---');
    const crossOrgRes = await fetch(`${baseUrl}/admin/agents/${deviceIdB}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '203.0.113.50' }
      })
    });
    assert.strictEqual(crossOrgRes.status, 404, `Expected 404 for cross-tenant agent, got ${crossOrgRes.status}`);
    console.log('✔ Passed: Cross-tenant command rejected with HTTP 404 Not Found');

    // --- TEST 7: Agent Status: Offline agent rejected with 404 ---
    console.log('\n--- Test 7: Agent Status: Offline agent rejected with 404 ---');
    await db.query(`UPDATE public.devices SET status = 'offline' WHERE id = $1;`, [deviceIdA]);

    const offlineRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '203.0.113.50' }
      })
    });
    const offlineBody = await offlineRes.json();
    assert.strictEqual(offlineRes.status, 404, `Expected 404 for offline agent, got ${offlineRes.status}`);
    assert.strictEqual(offlineBody.error, 'AGENT_OFFLINE');
    console.log(`✔ Passed: Offline agent rejected with HTTP 404: "${offlineBody.message}"`);

    // --- TEST 8: Agent Status: Disabled agent rejected with 409 ---
    console.log('\n--- Test 8: Agent Status: Disabled agent rejected with 409 ---');
    await db.query(`UPDATE public.devices SET status = 'disabled' WHERE id = $1;`, [deviceIdA]);

    const disabledRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminTokenA}`
      },
      body: JSON.stringify({
        command_type: 'block_ip',
        target_data: { ip_address: '203.0.113.50' }
      })
    });
    const disabledBody = await disabledRes.json();
    assert.strictEqual(disabledRes.status, 409, `Expected 409 for disabled agent, got ${disabledRes.status}`);
    assert.strictEqual(disabledBody.error, 'AGENT_DISABLED');
    console.log(`✔ Passed: Disabled agent rejected with HTTP 409: "${disabledBody.message}"`);

    // Restore device to online status
    await db.query(`UPDATE public.devices SET status = 'online' WHERE id = $1;`, [deviceIdA]);

    // --- TEST 9: Agent executes command & reports result -> rule created in agent_firewall_rules ---
    console.log('\n--- Test 9: Agent executes command & reports result -> rule created in agent_firewall_rules ---');
    const localRuleName = 'CyberGuard-block_ip-manual142';
    const reportRes = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${manualCommandId}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-agent-credential-id': credIdA,
        'x-agent-credential-secret': credSecretA
      },
      body: JSON.stringify({
        credential_id: credIdA,
        credential_secret: credSecretA,
        status: 'completed',
        result: {
          success: true,
          rule_name: localRuleName,
          target: '203.0.113.142'
        }
      })
    });

    const reportBody = await reportRes.json();
    assert.strictEqual(reportRes.status, 200, `Expected 200, got ${reportRes.status}: ${JSON.stringify(reportBody)}`);

    // Verify rule row in agent_firewall_rules
    const ruleRowRes = await db.query(
      `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
      [manualCommandId]
    );
    assert.strictEqual(ruleRowRes.rows.length, 1, 'agent_firewall_rules row must now exist');
    const rule = ruleRowRes.rows[0];
    assert.strictEqual(rule.status, 'active');
    assert.strictEqual(rule.target_ip, '203.0.113.142');
    assert.strictEqual(rule.rule_id_local, localRuleName);
    console.log(`✔ Passed: agent_firewall_rules row created with status='active', target_ip='${rule.target_ip}', rule_id_local='${rule.rule_id_local}'`);

    // --- TEST 10: Admin dashboard can retrieve the newly created rule ---
    console.log('\n--- Test 10: Admin dashboard can retrieve the newly created rule ---');
    const listRulesRes = await fetch(`${baseUrl}/admin/firewall-rules`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${adminTokenA}` }
    });
    const listRulesBody = await listRulesRes.json();
    assert.strictEqual(listRulesRes.status, 200);
    const listedRule = listRulesBody.rules.find((r) => r.source_command_id === manualCommandId);
    assert.ok(listedRule, 'Admin must see the activated manual firewall rule');
    assert.strictEqual(listedRule.status, 'active');
    console.log(`✔ Passed: Admin dashboard verified active manual rule: ${listedRule.id}`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 10 MANUAL FIREWALL COMMANDS TESTS PASSED SUCCESSFULLY!  ');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    console.log('[CLEANUP] Cleaning up test fixtures...');
    if (orgIdA) {
      await db.query(`DELETE FROM public.agent_firewall_rules WHERE organization_id = $1;`, [orgIdA]);
      await db.query(`DELETE FROM public.agent_commands WHERE organization_id = $1;`, [orgIdA]);
      await db.query(`DELETE FROM public.audit_logs WHERE organization_id = $1;`, [orgIdA]);
      await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [orgIdA]);
      await db.query(`DELETE FROM public.users WHERE organization_id = $1;`, [orgIdA]);
      await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgIdA]);
    }
    if (orgIdB) {
      await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [orgIdB]);
      await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgIdB]);
    }
    await new Promise((resolve) => server.close(resolve));
    console.log('[CLEANUP] Test server closed.');
  }
}

runManualFirewallCommandsTests()
  .then(() => {
    console.log('Test run finished.');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Test run failed with error:', err);
    process.exit(1);
  });
