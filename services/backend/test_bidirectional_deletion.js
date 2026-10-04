/**
 * CYBERGUARD Phase C: Bidirectional Firewall Rule Deletion Test Suite
 * Validates that when an admin deletes a firewall rule:
 * 1. Backend queues an asynchronous delete_firewall_rule command with rule_id_local
 * 2. Marks agent_firewall_rules.status = 'pending_delete'
 * 3. Returns { deleted: true, status: 'deletion_pending', agent_notified: true, command_id }
 * 4. Agent polls and executes deletion command
 * 5. On completion report, backend updates status to 'deleted' and populates deleted_at
 * 6. On failure report, backend updates status to 'failed' and stores error details
 * 7. Admin sees updated statuses in GET /admin/firewall-rules
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

async function runBidirectionalDeletionTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — BIDIRECTIONAL FIREWALL RULE DELETION INTEGRATION TESTS');
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
  let rule1Id = null;
  let rule2Id = null;
  let deleteCmd1Id = null;
  let deleteCmd2Id = null;

  try {
    // 0. Setup Organization and Admin User
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Bidir Deletion ${timestamp}`]
    );
    orgId = orgRes.rows[0].id;

    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);
    const userRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_bidir_${timestamp}@cyberguard.test`, pwHash, orgId]
    );
    adminId = userRes.rows[0].id;

    adminToken = jwt.sign(
      { id: adminId, organization_id: orgId, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Enroll Agent Device
    const enrollmentToken = await agentService.generateEnrollmentToken(orgId, 24);
    const enrolled = await agentService.enrollDevice({
      token: enrollmentToken,
      hostname: `workstation-del-${timestamp}`,
      os: 'Windows 11 Pro',
      platform: 'win32',
      agent_version: '1.0.0'
    });
    deviceId = enrolled.device_id;
    credId = enrolled.credential_id;
    credSecret = enrolled.credential_secret;

    console.log(`[SETUP] Initialized Org=${orgId}, Admin=${adminId}, Device=${deviceId}`);

    // --- STEP 1: Create rule and record agent execution with rule_id_local ---
    console.log('\n--- Step 1: Create Firewall Rule with rule_id_local ---');
    const localRuleName1 = `CyberGuard-block_ip-${timestamp.toString().slice(-6)}`;
    const targetIp1 = '198.51.100.42';

    // Simulate agent executing block_ip command and reporting result
    const cmd1Res = await db.query(
      `INSERT INTO public.agent_commands (
        device_id, organization_id, command_type, target_data, status, can_execute, requires_approval, created_at
      ) VALUES ($1, $2, 'block_ip', $3, 'pending', true, false, NOW())
      RETURNING id;`,
      [deviceId, orgId, JSON.stringify({ ip_address: targetIp1 })]
    );
    const blockCmd1Id = cmd1Res.rows[0].id;

    const report1Res = await fetch(`${baseUrl}/agents/${deviceId}/commands/${blockCmd1Id}/result`, {
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
          rule_name: localRuleName1,
          target: targetIp1,
          firewall: 'windows_defender'
        }
      })
    });
    assert.strictEqual(report1Res.status, 200);

    const rule1DbRes = await db.query(
      `SELECT id, status, rule_id_local, target_ip FROM public.agent_firewall_rules
       WHERE agent_id = $1 AND target_ip = $2;`,
      [deviceId, targetIp1]
    );
    assert.strictEqual(rule1DbRes.rows.length, 1);
    rule1Id = rule1DbRes.rows[0].id;
    assert.strictEqual(rule1DbRes.rows[0].status, 'active');
    assert.strictEqual(rule1DbRes.rows[0].rule_id_local, localRuleName1);
    console.log(`✔ Passed: Rule created with id=${rule1Id}, status='active', rule_id_local='${localRuleName1}'`);

    // --- STEP 2: Admin calls DELETE /admin/firewall-rules/:rule_id ---
    console.log('\n--- Step 2: Admin calls DELETE /admin/firewall-rules/:rule_id ---');
    const deleteRes = await fetch(`${baseUrl}/admin/firewall-rules/${rule1Id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    assert.strictEqual(deleteRes.status, 200, 'DELETE endpoint must return HTTP 200');
    const deleteBody = await deleteRes.json();

    assert.strictEqual(deleteBody.deleted, true);
    assert.strictEqual(deleteBody.rule_id, rule1Id);
    assert.strictEqual(deleteBody.status, 'deletion_pending');
    assert.strictEqual(deleteBody.agent_notified, true);
    assert.ok(deleteBody.command_id, 'Must return queued delete command_id');
    deleteCmd1Id = deleteBody.command_id;
    console.log(`✔ Passed: DELETE responded with deletion_pending and command_id=${deleteCmd1Id}`);

    // Assert: agent_firewall_rules is in pending_delete
    const rule1PendingRes = await db.query(
      `SELECT status, deleted_at FROM public.agent_firewall_rules WHERE id = $1;`,
      [rule1Id]
    );
    assert.strictEqual(rule1PendingRes.rows[0].status, 'pending_delete');
    assert.ok(rule1PendingRes.rows[0].deleted_at, 'deleted_at must be populated on pending_delete');
    console.log("✔ Passed: agent_firewall_rules.status is 'pending_delete'");

    // Assert: agent_commands contains delete_firewall_rule command
    const cmdDeleteRes = await db.query(
      `SELECT id, command_type, target_data, status, can_execute FROM public.agent_commands WHERE id = $1;`,
      [deleteCmd1Id]
    );
    assert.strictEqual(cmdDeleteRes.rows.length, 1);
    const deleteCmdRow = cmdDeleteRes.rows[0];
    assert.strictEqual(deleteCmdRow.command_type, 'delete_firewall_rule');
    assert.strictEqual(deleteCmdRow.status, 'pending');
    assert.strictEqual(deleteCmdRow.can_execute, true);

    const targetData = typeof deleteCmdRow.target_data === 'string'
      ? JSON.parse(deleteCmdRow.target_data)
      : deleteCmdRow.target_data;

    assert.strictEqual(targetData.rule_id_local, localRuleName1, 'target_data must include rule_id_local');
    assert.strictEqual(targetData.rule_id, rule1Id, 'target_data must include rule_id');
    assert.strictEqual(targetData.target_ip_or_domain, targetIp1, 'target_data must include target_ip_or_domain');
    console.log(`✔ Passed: Queued agent_command type='delete_firewall_rule' contains rule_id_local='${localRuleName1}'`);

    // --- STEP 3: Agent fetches pending commands and receives delete_firewall_rule ---
    console.log('\n--- Step 3: Agent fetches pending commands from gateway ---');
    const getCmdsRes = await fetch(`${baseUrl}/agents/${deviceId}/commands`, {
      headers: {
        'x-agent-credential-id': credId,
        'x-agent-credential-secret': credSecret
      }
    });
    assert.strictEqual(getCmdsRes.status, 200);
    const getCmdsBody = await getCmdsRes.json();
    const queuedDeleteCmd = getCmdsBody.commands.find((c) => c.id === deleteCmd1Id);
    assert.ok(queuedDeleteCmd, 'Agent must receive queued delete command');
    assert.strictEqual(queuedDeleteCmd.command_type, 'delete_firewall_rule');
    console.log('✔ Passed: Agent fetched delete_firewall_rule command');

    // --- STEP 4: Agent reports SUCCESSFUL deletion ---
    console.log('\n--- Step 4: Agent reports successful deletion ---');
    const reportDeleteRes = await fetch(`${baseUrl}/agents/${deviceId}/commands/${deleteCmd1Id}/result`, {
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
          deleted: true,
          rule_id_local: localRuleName1,
          target: targetIp1,
          firewall: 'windows_defender'
        }
      })
    });
    assert.strictEqual(reportDeleteRes.status, 200);

    // Assert: agent_firewall_rules.status is updated to 'deleted'
    const rule1DeletedRes = await db.query(
      `SELECT status, deleted_at, result FROM public.agent_firewall_rules WHERE id = $1;`,
      [rule1Id]
    );
    assert.strictEqual(rule1DeletedRes.rows[0].status, 'deleted', "Rule status must transition to 'deleted'");
    assert.ok(rule1DeletedRes.rows[0].deleted_at, 'deleted_at must be populated');
    const resData = rule1DeletedRes.rows[0].result;
    assert.ok(
      resData?.agent_deletion_report?.deleted === true || resData?.agent_deletion_status === 'completed',
      'Result must contain agent deletion confirmation'
    );
    console.log("✔ Passed: agent_firewall_rules status updated to 'deleted'");

    // --- STEP 5: Test Failure Case: Agent cannot find/delete rule ---
    console.log('\n--- Step 5: Test Failure Case (rule not found on host) ---');
    const localRuleName2 = `CyberGuard-block_ip-missing-${timestamp.toString().slice(-4)}`;
    const targetIp2 = '198.51.100.99';

    // Create second active rule
    const rule2Create = await db.query(
      `INSERT INTO public.agent_firewall_rules (
        agent_id, organization_id, rule_type, target_ip, rule_id_local, status, created_at
      ) VALUES ($1, $2, 'block_ip', $3, $4, 'active', NOW())
      RETURNING id;`,
      [deviceId, orgId, targetIp2, localRuleName2]
    );
    rule2Id = rule2Create.rows[0].id;

    // Admin revokes second rule
    const delete2Res = await fetch(`${baseUrl}/admin/firewall-rules/${rule2Id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(delete2Res.status, 200);
    const delete2Body = await delete2Res.json();
    deleteCmd2Id = delete2Body.command_id;

    // Agent executes delete command, fails because rule is not found
    const reportFailRes = await fetch(`${baseUrl}/agents/${deviceId}/commands/${deleteCmd2Id}/result`, {
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
          error: 'rule_not_found',
          message: `Firewall rule '${localRuleName2}' not found on host`,
          details: 'No MSFT_NetFirewallRule objects found'
        }
      })
    });
    assert.strictEqual(reportFailRes.status, 200);

    // Assert: agent_firewall_rules status is marked 'failed'
    const rule2FailedRes = await db.query(
      `SELECT status, result FROM public.agent_firewall_rules WHERE id = $1;`,
      [rule2Id]
    );
    assert.strictEqual(rule2FailedRes.rows[0].status, 'failed', "Rule status must be 'failed' upon agent deletion failure");
    assert.strictEqual(rule2FailedRes.rows[0].result?.agent_deletion_report?.error, 'rule_not_found');
    console.log("✔ Passed: Failure case records status='failed' and preserves error details");

    // --- STEP 6: Verify Admin View (GET /admin/firewall-rules) ---
    console.log('\n--- Step 6: Verify Admin View shows updated statuses ---');
    const listRes = await fetch(`${baseUrl}/admin/firewall-rules?limit=20`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(listRes.status, 200);
    const listBody = await listRes.json();
    assert.ok(Array.isArray(listBody.rules));

    const foundRule1 = listBody.rules.find((r) => r.id === rule1Id);
    assert.ok(foundRule1, 'Rule 1 must be present in admin listing');
    assert.strictEqual(foundRule1.status, 'deleted', "Admin must see Rule 1 as 'deleted'");

    const foundRule2 = listBody.rules.find((r) => r.id === rule2Id);
    assert.ok(foundRule2, 'Rule 2 must be present in admin listing');
    assert.strictEqual(foundRule2.status, 'failed', "Admin must see Rule 2 as 'failed'");
    console.log("✔ Passed: Admin list displays both 'deleted' and 'failed' states correctly");

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL BIDIRECTIONAL DELETION TESTS PASSED SUCCESSFULLY! (6/6)');
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } finally {
    // Cleanup created records
    try {
      if (deleteCmd1Id) await db.query('DELETE FROM public.agent_commands WHERE id = $1;', [deleteCmd1Id]);
      if (deleteCmd2Id) await db.query('DELETE FROM public.agent_commands WHERE id = $1;', [deleteCmd2Id]);
      if (rule1Id) await db.query('DELETE FROM public.agent_firewall_rules WHERE id = $1;', [rule1Id]);
      if (rule2Id) await db.query('DELETE FROM public.agent_firewall_rules WHERE id = $1;', [rule2Id]);
      if (deviceId) {
        await db.query('DELETE FROM public.agent_commands WHERE device_id = $1;', [deviceId]);
        await db.query('DELETE FROM public.agent_firewall_rules WHERE agent_id = $1;', [deviceId]);
        await db.query('DELETE FROM public.devices WHERE id = $1;', [deviceId]);
      }
      if (adminId) await db.query('DELETE FROM public.users WHERE id = $1;', [adminId]);
      if (orgId) {
        await db.query('DELETE FROM public.audit_logs WHERE organization_id = $1;', [orgId]);
        await db.query('DELETE FROM public.organizations WHERE id = $1;', [orgId]);
      }
    } catch (cleanupErr) {
      console.warn('[CLEANUP WARNING]', cleanupErr.message);
    }

    await new Promise((resolve) => server.close(resolve));
    await db.pool.end();
  }
}

runBidirectionalDeletionTests().catch((err) => {
  console.error('\n❌ TEST RUN FAILED:', err);
  process.exit(1);
});
