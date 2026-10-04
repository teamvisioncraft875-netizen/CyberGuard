/**
 * CYBERGUARD Phase C: End-to-End Command Conversion Test Suite
 * Validates the bridge from PolicyEngine -> response_actions -> executionService ->
 * agentCommandService -> agent_commands -> Agent Command Polling -> Result Reporting ->
 * agent_firewall_rules sync.
 */

process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { app } = require('./src');
const db = require('./src/config/db');
const config = require('./src/config');
const agentCommandService = require('./src/services/agentCommandService');
const executionService = require('./src/services/executionService');
const ResponseAction = require('./src/models/ResponseAction');
const agentService = require('./src/services/agentService');

async function runCommandConversionTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C POLICY TO AGENT COMMAND CONVERSION TESTS');
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
  let incidentId = null;
  let createdActionIds = [];
  let createdCommandIds = [];

  try {
    // 1. Setup Tenant, Admin User, and Incident
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Conversion ${timestamp}`]
    );
    orgId = orgRes.rows[0].id;

    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);
    const userRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_conv_${timestamp}@cyberguard.test`, pwHash, orgId]
    );
    adminId = userRes.rows[0].id;

    adminToken = jwt.sign(
      { id: adminId, organization_id: orgId, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Create test incident
    const incRes = await db.query(
      `INSERT INTO public.incidents (
        user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation
      ) VALUES ($1, $2, 'phishing', 'email', 85, 'high', 'open', 'Phishing C2 communication')
      RETURNING id;`,
      [adminId, orgId]
    );
    incidentId = incRes.rows[0].id;

    // 2. Enroll a test Agent Device
    const enrollmentToken = await agentService.generateEnrollmentToken(orgId, 24);
    const enrolled = await agentService.enrollDevice({
      token: enrollmentToken,
      hostname: `workstation-conv-${timestamp}`,
      os: 'Windows 11 Enterprise',
      platform: 'win32',
      agent_version: '1.0.0'
    });
    deviceId = enrolled.device_id;
    credId = enrolled.credential_id;
    credSecret = enrolled.credential_secret;

    console.log(`[SETUP] Initialized Org=${orgId}, Device=${deviceId}, Incident=${incidentId}`);

    // --- TEST 1: Policy Engine creates response_action with action_type='block_ip' ---
    console.log('\n--- Test 1: Policy creates response_action for incident ---');
    const action = await ResponseAction.create({
      organization_id: orgId,
      incident_id: incidentId,
      action_type: 'block_ip',
      action_mode: 'live',
      status: 'proposed',
      target: {
        ip_address: '203.0.113.88',
        target_device_id: deviceId
      },
      target_device_id: deviceId,
      requested_by_id: null
    });
    createdActionIds.push(action.id);
    assert.strictEqual(action.action_type, 'block_ip');
    assert.strictEqual(action.target_device_id, deviceId);
    console.log(`✔ Passed: Response action created with id=${action.id}, target_device_id=${deviceId}`);

    // --- TEST 2: Admin Approves Response Action ---
    console.log('\n--- Test 2: Admin approves response_action ---');
    const approveRes = await fetch(`${baseUrl}/admin/actions/${action.id}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ approved: true })
    });
    assert.strictEqual(approveRes.status, 200, 'Approval must succeed');
    const approveBody = await approveRes.json();
    assert.strictEqual(approveBody.action.status, 'approved');
    console.log(`✔ Passed: Action ${action.id} marked status='approved' by admin`);

    // --- TEST 3: Execution Trigger Converts Action to Agent Command ---
    console.log('\n--- Test 3: Live execution triggers agentCommandService conversion ---');
    // Fetch latest action record to get approved status
    const actionToExec = await ResponseAction.findById(action.id);
    const execResult = await executionService.execute(actionToExec, 'admin');

    assert.strictEqual(execResult.success, true);
    assert.ok(execResult.result.agent_command_id, 'Execution result must contain agent_command_id');
    const commandId = execResult.result.agent_command_id;
    createdCommandIds.push(commandId);
    console.log(`✔ Passed: Execution succeeded and created agent_command ${commandId}`);

    // --- TEST 4: Verify agent_commands table structure and target_data ---
    console.log('\n--- Test 4: Verify agent_commands row matches response_action ---');
    const cmdDbRes = await db.query(
      `SELECT id, device_id, organization_id, command_type, target_data, status, can_execute
       FROM public.agent_commands WHERE id = $1;`,
      [commandId]
    );
    assert.strictEqual(cmdDbRes.rows.length, 1);
    const cmdRow = cmdDbRes.rows[0];
    assert.strictEqual(cmdRow.device_id, deviceId);
    assert.strictEqual(cmdRow.organization_id, orgId);
    assert.strictEqual(cmdRow.command_type, 'block_ip');
    assert.strictEqual(cmdRow.target_data.ip_address, '203.0.113.88');
    assert.strictEqual(cmdRow.status, 'pending');
    assert.strictEqual(cmdRow.can_execute, true);
    console.log(`✔ Passed: agent_command fields verified (command_type='block_ip', target='203.0.113.88')`);

    // --- TEST 5: Verify agent_firewall_rules entry created in 'pending' status ---
    console.log('\n--- Test 5: Verify mirrored entry in agent_firewall_rules ---');
    const fwRuleRes = await db.query(
      `SELECT id, agent_id, rule_type, target_ip, status
       FROM public.agent_firewall_rules WHERE agent_id = $1 AND target_ip = $2;`,
      [deviceId, '203.0.113.88']
    );
    assert.strictEqual(fwRuleRes.rows.length, 1);
    assert.strictEqual(fwRuleRes.rows[0].status, 'pending');
    console.log(`✔ Passed: agent_firewall_rules entry created in pending status`);

    // --- TEST 6: Agent polls commands via GET /agents/:device_id/commands ---
    console.log('\n--- Test 6: Agent polls and receives the queued command ---');
    const pollRes = await fetch(`${baseUrl}/agents/${deviceId}/commands`, {
      headers: {
        'x-agent-credential-id': credId,
        'x-agent-credential-secret': credSecret
      }
    });
    assert.strictEqual(pollRes.status, 200);
    const pollBody = await pollRes.json();
    assert.ok(Array.isArray(pollBody.commands), 'commands must be an array');
    const matchingCmd = pollBody.commands.find((c) => c.id === commandId);
    assert.ok(matchingCmd, 'Polled commands must include queued command');
    assert.strictEqual(matchingCmd.command_type, 'block_ip');
    assert.strictEqual(matchingCmd.target_data.ip_address, '203.0.113.88');
    console.log(`✔ Passed: Agent successfully polled command ${commandId}`);

    // --- TEST 7: Agent reports completion via POST /commands/:id/result ---
    console.log('\n--- Test 7: Agent reports completion and syncs agent_firewall_rules ---');
    const simulatedRuleName = 'CyberGuard-block_ip-test9988';
    const reportRes = await fetch(`${baseUrl}/agents/${deviceId}/commands/${commandId}/result`, {
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
          rule_name: simulatedRuleName,
          target: '203.0.113.88',
          firewall: 'windows_defender'
        }
      })
    });
    assert.strictEqual(reportRes.status, 200, 'Reporting result must succeed');

    // Verify command status in DB is 'completed'
    const cmdAfterRes = await db.query(
      `SELECT status, executed_at, result FROM public.agent_commands WHERE id = $1;`,
      [commandId]
    );
    assert.strictEqual(cmdAfterRes.rows[0].status, 'completed');
    assert.ok(cmdAfterRes.rows[0].executed_at, 'executed_at must be set');

    // Verify agent_firewall_rules status is now 'active' with rule_id_local populated
    const fwAfterRes = await db.query(
      `SELECT status, rule_id_local FROM public.agent_firewall_rules WHERE agent_id = $1 AND target_ip = $2;`,
      [deviceId, '203.0.113.88']
    );
    assert.strictEqual(fwAfterRes.rows[0].status, 'active');
    assert.strictEqual(fwAfterRes.rows[0].rule_id_local, simulatedRuleName);
    console.log(`✔ Passed: agent_commands is completed and agent_firewall_rules is ACTIVE with rule_id_local='${simulatedRuleName}'`);

    // --- TEST 8: Admin Rule Revocation generates unblock_ip command ---
    console.log('\n--- Test 8: Admin deletes rule -> unblock_ip command queued for agent ---');
    const ruleId = fwRuleRes.rows[0].id;
    const deleteRes = await fetch(`${baseUrl}/admin/firewall-rules/${ruleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(deleteRes.status, 200);

    // Verify unblock command was queued in agent_commands
    const unblockCmdRes = await db.query(
      `SELECT id, command_type, target_data, status
       FROM public.agent_commands 
       WHERE device_id = $1 AND command_type = 'unblock_ip'
       ORDER BY created_at DESC LIMIT 1;`,
      [deviceId]
    );
    assert.strictEqual(unblockCmdRes.rows.length, 1);
    assert.strictEqual(unblockCmdRes.rows[0].command_type, 'unblock_ip');
    assert.strictEqual(unblockCmdRes.rows[0].target_data.ip_address, '203.0.113.88');
    assert.strictEqual(unblockCmdRes.rows[0].status, 'pending');
    createdCommandIds.push(unblockCmdRes.rows[0].id);
    console.log(`✔ Passed: Revocation generated 'unblock_ip' command ${unblockCmdRes.rows[0].id} for device`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 8 PHASE C CONVERSION & INTEGRATION TESTS PASSED SUCCESSFULLY!  ');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    // Cleanup fixtures
    console.log('[CLEANUP] Removing test fixtures...');
    if (createdCommandIds.length > 0) {
      await db.query(`DELETE FROM public.agent_commands WHERE id = ANY($1::uuid[]);`, [createdCommandIds]);
    }
    if (deviceId) {
      await db.query(`DELETE FROM public.agent_firewall_rules WHERE agent_id = $1;`, [deviceId]);
      await db.query(`DELETE FROM public.devices WHERE id = $1;`, [deviceId]);
    }
    if (createdActionIds.length > 0) {
      await db.query(`DELETE FROM public.response_actions WHERE id = ANY($1::uuid[]);`, [createdActionIds]);
    }
    if (incidentId) {
      await db.query(`DELETE FROM public.incidents WHERE id = $1;`, [incidentId]);
    }
    if (orgId) {
      await db.query(`DELETE FROM public.users WHERE organization_id = $1;`, [orgId]);
      await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgId]);
    }

    server.close();
    console.log('[CLEANUP] Test server closed.\n');
  }
}

if (require.main === module) {
  runCommandConversionTests()
    .then(() => {
      console.log('Test run finished.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('\n❌ Test suite encountered an error:\n', err);
      process.exit(1);
    });
}

module.exports = { runCommandConversionTests };
