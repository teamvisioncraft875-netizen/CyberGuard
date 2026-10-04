/**
 * CYBERGUARD Phase C: Agent Execution Result to Firewall Rules Test Suite
 * Validates that when an agent reports command execution results (success or failure),
 * backend records it in public.agent_firewall_rules with source_command_id linkage
 * and proper status ('active' or 'failed'), visible in GET /admin/firewall-rules.
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
const firewallService = require('./src/services/firewallService');

async function runAgentResultToRulesTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C AGENT RESULT TO FIREWALL RULES INTEGRATION TESTS');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  console.log(`[INIT] Test server running on ${baseUrl}`);

  const timestamp = Date.now();
  let orgId = null;
  let adminId = null;
  let adminToken = null;
  let deviceId = null;
  let credId = null;
  let credSecret = null;
  let createdCommandIds = [];

  try {
    // 1. Setup Tenant and Admin User
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Result Sync ${timestamp}`]
    );
    orgId = orgRes.rows[0].id;

    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);
    const userRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_res_sync_${timestamp}@cyberguard.test`, pwHash, orgId]
    );
    adminId = userRes.rows[0].id;

    adminToken = jwt.sign(
      { id: adminId, organization_id: orgId, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 2. Enroll Agent Device
    const enrollmentToken = await agentService.generateEnrollmentToken(orgId, 24);
    const enrolled = await agentService.enrollDevice({
      token: enrollmentToken,
      hostname: `workstation-res-${timestamp}`,
      os: 'Windows 11 Enterprise',
      platform: 'win32',
      agent_version: '1.0.0'
    });
    deviceId = enrolled.device_id;
    credId = enrolled.credential_id;
    credSecret = enrolled.credential_secret;

    console.log(`[SETUP] Initialized Org=${orgId}, Admin=${adminId}, Device=${deviceId}`);

    // --- TEST 1: Agent reports SUCCESS for block_ip command ---
    console.log('\n--- Test 1: Agent reports SUCCESS for block_ip command ---');
    const cmd1Res = await db.query(
      `INSERT INTO public.agent_commands (
        device_id, organization_id, command_type, target_data, status, can_execute, requires_approval, created_at
      ) VALUES ($1, $2, 'block_ip', $3, 'pending', true, false, NOW())
      RETURNING id;`,
      [deviceId, orgId, JSON.stringify({ ip_address: '203.0.113.111' })]
    );
    const command1Id = cmd1Res.rows[0].id;
    createdCommandIds.push(command1Id);

    const ruleName1 = 'CyberGuard-block_ip-success1234';
    const report1Res = await fetch(`${baseUrl}/agents/${deviceId}/commands/${command1Id}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-agent-credential-id': credId,
        'x-agent-credential-secret': credSecret
      },
      body: JSON.stringify({
        credential_id: credId,
        credential_secret: credSecret,
        status: 'completed',
        result: {
          success: true,
          rule_name: ruleName1,
          target: '203.0.113.111',
          firewall: 'windows_defender'
        }
      })
    });
    assert.strictEqual(report1Res.status, 200, 'Result reporting must return HTTP 200');

    // Assert: agent_firewall_rules row created with status='active'
    const fw1Res = await db.query(
      `SELECT id, agent_id, organization_id, rule_type, target_ip, rule_id_local, status, source_command_id, result
       FROM public.agent_firewall_rules
       WHERE agent_id = $1 AND target_ip = $2;`,
      [deviceId, '203.0.113.111']
    );
    assert.strictEqual(fw1Res.rows.length, 1, 'Rule row must exist in agent_firewall_rules');
    const rule1 = fw1Res.rows[0];
    assert.strictEqual(rule1.status, 'active');
    assert.strictEqual(rule1.target_ip, '203.0.113.111');
    assert.strictEqual(rule1.rule_id_local, ruleName1);
    assert.strictEqual(rule1.source_command_id, command1Id, 'source_command_id must point to originating command');
    console.log(`✔ Passed: agent_firewall_rules created status='active', rule_id_local='${ruleName1}', source_command_id=${command1Id}`);

    // --- TEST 2: Verify GET /admin/firewall-rules returns active rule ---
    console.log('\n--- Test 2: Admin can see active rule in GET /admin/firewall-rules ---');
    const adminListRes = await fetch(`${baseUrl}/admin/firewall-rules?status=active`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(adminListRes.status, 200);
    const adminListBody = await adminListRes.json();
    assert.ok(adminListBody.total >= 1);
    const foundRule1 = adminListBody.rules.find((r) => r.id === rule1.id);
    assert.ok(foundRule1, 'Rule must appear in admin rules list');
    assert.strictEqual(foundRule1.target_ip, '203.0.113.111');
    assert.strictEqual(foundRule1.source_command_id, command1Id);
    console.log(`✔ Passed: Admin successfully retrieved active rule in dashboard with source_command_id`);

    // --- TEST 3: Agent reports FAILURE for block_ip command (insufficient_privileges) ---
    console.log('\n--- Test 3: Agent reports FAILURE for block_ip command ---');
    const cmd2Res = await db.query(
      `INSERT INTO public.agent_commands (
        device_id, organization_id, command_type, target_data, status, can_execute, requires_approval, created_at
      ) VALUES ($1, $2, 'block_ip', $3, 'pending', true, false, NOW())
      RETURNING id;`,
      [deviceId, orgId, JSON.stringify({ ip_address: '203.0.113.222' })]
    );
    const command2Id = cmd2Res.rows[0].id;
    createdCommandIds.push(command2Id);

    const report2Res = await fetch(`${baseUrl}/agents/${deviceId}/commands/${command2Id}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-agent-credential-id': credId,
        'x-agent-credential-secret': credSecret
      },
      body: JSON.stringify({
        credential_id: credId,
        credential_secret: credSecret,
        status: 'failed',
        result: {
          success: false,
          error: 'insufficient_privileges',
          message: 'Firewall execution requires administrator rights on Windows or root on Linux',
          target: '203.0.113.222'
        }
      })
    });
    assert.strictEqual(report2Res.status, 200);

    // Assert: agent_firewall_rules created with status='failed'
    const fw2Res = await db.query(
      `SELECT id, agent_id, organization_id, rule_type, target_ip, status, source_command_id, result
       FROM public.agent_firewall_rules
       WHERE agent_id = $1 AND target_ip = $2;`,
      [deviceId, '203.0.113.222']
    );
    assert.strictEqual(fw2Res.rows.length, 1, 'Failed rule row must exist in agent_firewall_rules');
    const rule2 = fw2Res.rows[0];
    assert.strictEqual(rule2.status, 'failed');
    assert.strictEqual(rule2.target_ip, '203.0.113.222');
    assert.strictEqual(rule2.source_command_id, command2Id);
    assert.strictEqual(rule2.result.error, 'insufficient_privileges');
    console.log(`✔ Passed: agent_firewall_rules created status='failed', error='${rule2.result.error}', source_command_id=${command2Id}`);

    // --- TEST 4: Admin views failed rules in dashboard via GET /admin/firewall-rules?status=failed ---
    console.log('\n--- Test 4: Admin views failed rules in dashboard ---');
    const adminFailedListRes = await fetch(`${baseUrl}/admin/firewall-rules?status=failed`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(adminFailedListRes.status, 200);
    const adminFailedListBody = await adminFailedListRes.json();
    assert.ok(adminFailedListBody.total >= 1);
    const foundRule2 = adminFailedListBody.rules.find((r) => r.id === rule2.id);
    assert.ok(foundRule2, 'Failed rule must be visible in failed rules list');
    assert.strictEqual(foundRule2.result.error, 'insufficient_privileges');
    console.log(`✔ Passed: Admin dashboard can inspect failed rule and audit error: "${foundRule2.result.message}"`);

    // --- TEST 5: Verify source_command_id linkage back to original command ---
    console.log('\n--- Test 5: Verify bidirectional command and rule linkage ---');
    const auditRes = await db.query(
      `SELECT action, resource_type, resource_id, details
       FROM public.audit_logs
       WHERE organization_id = $1 AND resource_id = $2;`,
      [orgId, rule1.id]
    );
    assert.ok(auditRes.rows.length >= 1, 'Audit log entry must exist for firewall_rule_created');
    assert.strictEqual(auditRes.rows[0].details.source_command_id, command1Id);
    console.log(`✔ Passed: Audit log verifies rule ${rule1.id} originated from command ${command1Id}`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 5 AGENT RESULT TO RULES TESTS PASSED SUCCESSFULLY!  ');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    console.log('[CLEANUP] Cleaning up test fixtures...');
    if (deviceId) {
      await db.query(`DELETE FROM public.agent_firewall_rules WHERE agent_id = $1;`, [deviceId]);
      await db.query(`DELETE FROM public.agent_commands WHERE device_id = $1;`, [deviceId]);
      await db.query(`DELETE FROM public.devices WHERE id = $1;`, [deviceId]);
    }
    if (orgId) {
      await db.query(`DELETE FROM public.audit_logs WHERE organization_id = $1;`, [orgId]);
      await db.query(`DELETE FROM public.users WHERE organization_id = $1;`, [orgId]);
      await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgId]);
    }

    server.close();
    console.log('[CLEANUP] Test server closed.\n');
  }
}

if (require.main === module) {
  runAgentResultToRulesTests()
    .then(() => {
      console.log('Test run finished.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('\n❌ Test suite encountered an error:\n', err);
      process.exit(1);
    });
}

module.exports = { runAgentResultToRulesTests };
