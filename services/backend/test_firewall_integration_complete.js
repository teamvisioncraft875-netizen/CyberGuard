/**
 * test_firewall_integration_complete.js
 *
 * CYBERGUARD Phase C: Final Comprehensive Firewall Integration Test Suite
 * Executes all 10 End-to-End Scenarios against live Postgres DB and Express HTTP server:
 *
 *  Scenario 1: Policy Engine → Agent → Execution → Dashboard
 *  Scenario 2: Manual Admin Testing (Direct ad-hoc dispatch)
 *  Scenario 3: Protected Target Rejection (Multi-layer guard)
 *  Scenario 4: Agent Insufficient Privilege Handling
 *  Scenario 5: Firewall Tool Unavailable Handling
 *  Scenario 6: Bidirectional Deletion (Admin DELETE → Agent OS rule cleanup)
 *  Scenario 7: Protected Targets Live Distribution Endpoint
 *  Scenario 8: Agent Rate Limiting Enforcement & Error Tracking
 *  Scenario 9: Cross-Tenant Multi-Org Isolation
 *  Scenario 10: Agent Status Transitions (Offline command queueing & reconnect sync)
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
const agentService = require('./src/services/agentService');
const agentCommandService = require('./src/services/agentCommandService');
const firewallService = require('./src/services/firewallService');

async function runCompleteIntegrationSuite() {
  console.log('════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C COMPLETE FIREWALL INTEGRATION TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    redis.enableMockRedis();
  }

  // 1. Start test server
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  console.log(`[INIT] Integration test server listening on ${baseUrl}`);

  const timestamp = Date.now();
  let orgIdA = null;
  let adminIdA = null;
  let adminTokenA = null;
  let deviceIdA = null;
  let credIdA = null;
  let credSecretA = null;

  let orgIdB = null;
  let adminIdB = null;
  let adminTokenB = null;
  let deviceIdB = null;
  let credIdB = null;
  let credSecretB = null;

  const testResults = [];

  try {
    // ──────────────────────────────────────────────────────────────────────────
    // SETUP: Organizations, Admins, Agents
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n[SETUP] Seeding Tenant A and Tenant B...');
    const pwHash = await bcrypt.hash('AdminP@ss123!', 10);

    // Tenant A
    const orgResA = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`PhaseC Org A ${timestamp}`]
    );
    orgIdA = orgResA.rows[0].id;

    const userResA = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_e2e_a_${timestamp}@cyberguard.test`, pwHash, orgIdA]
    );
    adminIdA = userResA.rows[0].id;
    adminTokenA = jwt.sign(
      { id: adminIdA, organization_id: orgIdA, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '2h' }
    );

    const enrollTokenA = await agentService.generateEnrollmentToken(orgIdA, 24);
    const enrolledA = await agentService.enrollDevice({
      token: enrollTokenA,
      hostname: `agent-station-a-${timestamp}`,
      os: 'Windows 11 Enterprise',
      platform: 'win32',
      agent_version: '1.2.0'
    });
    deviceIdA = enrolledA.device_id;
    credIdA = enrolledA.credential_id;
    credSecretA = enrolledA.credential_secret;

    // Bring Agent A online
    await agentService.recordHeartbeat(deviceIdA, credIdA, credSecretA, { agent_version: '1.2.0' });

    // Tenant B
    const orgResB = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`PhaseC Org B ${timestamp}`]
    );
    orgIdB = orgResB.rows[0].id;

    const userResB = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id;`,
      [`admin_e2e_b_${timestamp}@cyberguard.test`, pwHash, orgIdB]
    );
    adminIdB = userResB.rows[0].id;
    adminTokenB = jwt.sign(
      { id: adminIdB, organization_id: orgIdB, role: 'admin' },
      config.JWT_SECRET,
      { expiresIn: '2h' }
    );

    const enrollTokenB = await agentService.generateEnrollmentToken(orgIdB, 24);
    const enrolledB = await agentService.enrollDevice({
      token: enrollTokenB,
      hostname: `agent-station-b-${timestamp}`,
      os: 'Linux Ubuntu 22.04 LTS',
      platform: 'linux',
      agent_version: '1.2.0'
    });
    deviceIdB = enrolledB.device_id;
    credIdB = enrolledB.credential_id;
    credSecretB = enrolledB.credential_secret;
    await agentService.recordHeartbeat(deviceIdB, credIdB, credSecretB, { agent_version: '1.2.0' });

    console.log(`[SETUP] Done. OrgA=${orgIdA}, DeviceA=${deviceIdA} | OrgB=${orgIdB}, DeviceB=${deviceIdB}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 1: Policy Engine → Agent → Execution → Dashboard
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 1: Policy Engine → Agent → Execution → Dashboard');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1. Create incident
      const incRes = await db.query(
        `INSERT INTO public.incidents (
          user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation
        ) VALUES ($1, $2, 'phishing', 'email', 85, 'high', 'open', 'Phishing Credential Harvester detected')
        RETURNING id;`,
        [adminIdA, orgIdA]
      );
      const incidentId1 = incRes.rows[0].id;

      // 2. Policy engine calculates response action (block_ip 203.0.113.42)
      const actionRes = await db.query(
        `INSERT INTO public.response_actions (
          organization_id, incident_id, action_type, action_mode, status,
          target, execution_attempts
        ) VALUES ($1, $2, 'block_ip', 'live', 'proposed', $3, 0)
        RETURNING id;`,
        [orgIdA, incidentId1, JSON.stringify({ ip_address: '203.0.113.42', target_device_id: deviceIdA })]
      );
      const actionId1 = actionRes.rows[0].id;

      // 3. Admin approves action
      const approveRes = await fetch(`${baseUrl}/admin/actions/${actionId1}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenA}` },
        body: JSON.stringify({ approved: true })
      });
      assert.strictEqual(approveRes.status, 200, 'Admin approval must succeed with 200');
      const approveBody = await approveRes.json();
      assert.strictEqual(approveBody.action.status, 'approved', 'Action status must be approved');

      // 4. Admin triggers execution (or automatic execution pipeline)
      const execActionRes = await fetch(`${baseUrl}/admin/actions/${actionId1}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenA}` }
      });
      assert.strictEqual(execActionRes.status, 200, 'Action execution endpoint must succeed with 200');
      const execActionBody = await execActionRes.json();
      assert.strictEqual(execActionBody.success, true);
      assert.ok(execActionBody.result.agent_command_id, 'Must contain agent_command_id');
      const queuedCommandId1 = execActionBody.result.agent_command_id;

      // 5. Agent polls and receives command
      const pollRes1 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
        method: 'GET',
        headers: {
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        }
      });
      assert.strictEqual(pollRes1.status, 200);
      const pollBody1 = await pollRes1.json();
      const cmd1 = (pollBody1.commands || []).find((c) => c.id === queuedCommandId1);
      assert.ok(cmd1, 'Agent must receive queued command');
      assert.strictEqual(cmd1.command_type, 'block_ip');

      // 6 & 7 & 8. Agent executes and reports success
      const osRuleName1 = `CyberGuard-block_ip-${timestamp.toString().slice(-6)}-1`;
      const reportRes1 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${queuedCommandId1}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        },
        body: JSON.stringify({
          status: 'completed',
          result: {
            success: true,
            rule_name: osRuleName1,
            firewall_tool: 'netsh',
            target: '203.0.113.42',
            created_at: new Date().toISOString()
          }
        })
      });
      assert.strictEqual(reportRes1.status, 200);

      // 9. Backend creates agent_firewall_rules row (status='active')
      const fwRuleCheck1 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
        [queuedCommandId1]
      );
      assert.strictEqual(fwRuleCheck1.rows.length, 1, 'agent_firewall_rules row must exist');
      assert.strictEqual(fwRuleCheck1.rows[0].status, 'active');
      assert.strictEqual(fwRuleCheck1.rows[0].target_ip, '203.0.113.42');
      assert.strictEqual(fwRuleCheck1.rows[0].rule_id_local, osRuleName1);
      assert.strictEqual(fwRuleCheck1.rows[0].result.rule_name, osRuleName1);

      // 10. Admin views GET /admin/firewall-rules -> sees "Blocked 203.0.113.42"
      const listRes1 = await fetch(`${baseUrl}/admin/firewall-rules`, {
        headers: { Authorization: `Bearer ${adminTokenA}` }
      });
      assert.strictEqual(listRes1.status, 200);
      const listBody1 = await listRes1.json();
      const foundRule1 = (listBody1.rules || []).find((r) => r.target_ip === '203.0.113.42');
      assert.ok(foundRule1, 'Admin must see rule in dashboard');
      assert.strictEqual(foundRule1.status, 'active');

      // 11. Audit log shows: 'firewall_rule_created' with all details
      const auditRes1 = await db.query(
        `SELECT * FROM public.audit_logs WHERE action = 'firewall_rule_created' AND organization_id = $1 ORDER BY created_at DESC LIMIT 1;`,
        [orgIdA]
      );
      assert.ok(['admin', 'device', 'system_policy'].includes(auditRes1.rows[0].actor_type));
      assert.strictEqual(auditRes1.rows[0].details.target || auditRes1.rows[0].details.target_ip, '203.0.113.42');

      testResults.push({ scenario: 1, name: 'Policy Engine → Agent → Execution → Dashboard', passed: true });
      console.log('✅ Scenario 1 Passed: Full policy to dashboard chain verified.');
    } catch (err) {
      console.error('❌ Scenario 1 Failed:', err);
      testResults.push({ scenario: 1, name: 'Policy Engine → Agent → Execution → Dashboard', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 2: Manual Admin Testing
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 2: Manual Admin Testing');
    console.log('──────────────────────────────────────────────────────────────────────────');
    let manualRuleId2 = null;
    let manualLocalRuleName2 = `CyberGuard-manual-192-0-2-1`;
    try {
      // 1. Admin calls POST /admin/agents/:agent_id/firewall-commands
      const manualCmdRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenA}` },
        body: JSON.stringify({
          command_type: 'block_ip',
          target_data: { ip_address: '192.0.2.1' },
          reason: 'Manual ad-hoc testing'
        })
      });
      assert.strictEqual(manualCmdRes.status, 201);
      const manualCmdBody = await manualCmdRes.json();
      assert.strictEqual(manualCmdBody.success, true);
      const manualCmdId = manualCmdBody.command_id;

      // 2. agent_commands row created
      const dbCmd2 = await db.query(`SELECT * FROM public.agent_commands WHERE id = $1;`, [manualCmdId]);
      assert.strictEqual(dbCmd2.rows.length, 1);
      assert.strictEqual(dbCmd2.rows[0].status, 'pending');

      // 3. Agent polls and receives command
      const pollRes2 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
        headers: { 'x-agent-credential-id': credIdA, 'x-agent-credential-secret': credSecretA }
      });
      const pollBody2 = await pollRes2.json();
      const cmd2 = (pollBody2.commands || []).find((c) => c.id === manualCmdId);
      assert.ok(cmd2, 'Agent must receive manual command');

      // 4. Agent executes and reports success
      const reportRes2 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${manualCmdId}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        },
        body: JSON.stringify({
          status: 'completed',
          result: {
            success: true,
            rule_name: manualLocalRuleName2,
            firewall_tool: 'netsh',
            target: '192.0.2.1',
            created_at: new Date().toISOString()
          }
        })
      });
      assert.strictEqual(reportRes2.status, 200);

      // 5. agent_firewall_rules row created
      const fwRuleCheck2 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
        [manualCmdId]
      );
      assert.strictEqual(fwRuleCheck2.rows.length, 1);
      assert.strictEqual(fwRuleCheck2.rows[0].status, 'active');
      manualRuleId2 = fwRuleCheck2.rows[0].id;

      // 6. Admin sees rule in dashboard
      const listRes2 = await fetch(`${baseUrl}/admin/firewall-rules`, {
        headers: { Authorization: `Bearer ${adminTokenA}` }
      });
      const listBody2 = await listRes2.json();
      const found2 = (listBody2.rules || []).find((r) => r.target_ip === '192.0.2.1');
      assert.ok(found2, 'Manual rule must appear in dashboard');

      testResults.push({ scenario: 2, name: 'Manual Admin Testing', passed: true });
      console.log('✅ Scenario 2 Passed: Manual creation works without incident pipeline.');
    } catch (err) {
      console.error('❌ Scenario 2 Failed:', err);
      testResults.push({ scenario: 2, name: 'Manual Admin Testing', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 3: Protected Target Rejection
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 3: Protected Target Rejection');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1 & 2 & 3. Admin tries to block 127.0.0.1 (localhost)
      const protRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenA}` },
        body: JSON.stringify({
          command_type: 'block_ip',
          target_data: { ip_address: '127.0.0.1' },
          reason: 'Test block localhost'
        })
      });
      assert.strictEqual(protRes.status, 400);
      const protBody = await protRes.json();
      assert.strictEqual(protBody.error_type, 'validation_failed');
      assert.ok(protBody.message.includes('protected'), 'Error message must note target is protected');

      // 4. No agent_command created for 127.0.0.1
      const cmdCheck3 = await db.query(
        `SELECT * FROM public.agent_commands WHERE target_data->>'ip_address' = '127.0.0.1';`
      );
      assert.strictEqual(cmdCheck3.rows.length, 0, 'No command should be created for protected IP');

      // 5. No agent_firewall_rules created
      const ruleCheck3 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE target_ip = '127.0.0.1';`
      );
      assert.strictEqual(ruleCheck3.rows.length, 0, 'No firewall rule should be created for protected IP');

      // 6. Audit log shows 'firewall_rule_creation_failed'
      const auditRes3 = await db.query(
        `SELECT * FROM public.audit_logs 
         WHERE action = 'firewall_rule_creation_failed' AND details->>'target' = '127.0.0.1'
         ORDER BY created_at DESC LIMIT 1;`
      );
      assert.strictEqual(auditRes3.rows.length, 1, 'Audit log entry must record creation failure');

      testResults.push({ scenario: 3, name: 'Protected Target Rejection', passed: true });
      console.log('✅ Scenario 3 Passed: Multi-layer protection correctly rejected block on 127.0.0.1.');
    } catch (err) {
      console.error('❌ Scenario 3 Failed:', err);
      testResults.push({ scenario: 3, name: 'Protected Target Rejection', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 4: Agent Insufficient Privilege
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 4: Agent Insufficient Privilege');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1 & 2. Admin sends block_ip command
      const cmdRes4 = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenA}` },
        body: JSON.stringify({
          command_type: 'block_ip',
          target_data: { ip_address: '203.0.113.44' },
          reason: 'Test non-admin privilege'
        })
      });
      assert.strictEqual(cmdRes4.status, 201);
      const cmdBody4 = await cmdRes4.json();
      const commandId4 = cmdBody4.command_id;

      // 3 & 4. Agent executes: firewall_executor reports insufficient_privileges
      const privFailResult = {
        success: false,
        error_type: 'insufficient_privileges',
        error_message: 'Firewall execution requires elevated administrator privileges',
        platform: 'windows',
        attempted_action: 'block_ip',
        target: '203.0.113.44'
      };

      const reportRes4 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${commandId4}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        },
        body: JSON.stringify({
          status: 'failed',
          result: privFailResult
        })
      });
      assert.strictEqual(reportRes4.status, 200);

      // 5 & 6. agent_firewall_rules created with status='failed' and error details in result
      const ruleCheck4 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
        [commandId4]
      );
      assert.strictEqual(ruleCheck4.rows.length, 1);
      assert.strictEqual(ruleCheck4.rows[0].status, 'failed');
      assert.strictEqual(ruleCheck4.rows[0].result.error_type, 'insufficient_privileges');

      // 7. Admin sees error in dashboard
      const listRes4 = await fetch(`${baseUrl}/admin/firewall-rules?status=failed`, {
        headers: { Authorization: `Bearer ${adminTokenA}` }
      });
      const listBody4 = await listRes4.json();
      const found4 = (listBody4.rules || []).find((r) => r.target_ip === '203.0.113.44');
      assert.ok(found4, 'Failed rule must be visible in dashboard');
      assert.strictEqual(found4.result.error_type, 'insufficient_privileges');

      testResults.push({ scenario: 4, name: 'Agent Insufficient Privilege', passed: true });
      console.log('✅ Scenario 4 Passed: Privilege failures captured, stored in JSONB, and surfaced to admin.');
    } catch (err) {
      console.error('❌ Scenario 4 Failed:', err);
      testResults.push({ scenario: 4, name: 'Agent Insufficient Privilege', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 5: Firewall Tool Unavailable
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 5: Firewall Tool Unavailable');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1 & 2. Admin sends block_ip command to Linux agent (Device B)
      const cmdRes5 = await fetch(`${baseUrl}/admin/agents/${deviceIdB}/firewall-commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenB}` },
        body: JSON.stringify({
          command_type: 'block_ip',
          target_data: { ip_address: '203.0.113.45' },
          reason: 'Test no firewall tool'
        })
      });
      assert.strictEqual(cmdRes5.status, 201);
      const cmdBody5 = await cmdRes5.json();
      const commandId5 = cmdBody5.command_id;

      // 3 & 4. Agent detects no firewall available
      const noFwResult = {
        success: false,
        error_type: 'no_firewall_detected',
        error_message: 'No supported firewall found on Linux (checked ufw, firewalld, iptables)',
        platform: 'linux',
        attempted_action: 'block_ip',
        target: '203.0.113.45'
      };

      const reportRes5 = await fetch(`${baseUrl}/agents/${deviceIdB}/commands/${commandId5}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdB,
          'x-agent-credential-secret': credSecretB
        },
        body: JSON.stringify({
          status: 'failed',
          result: noFwResult
        })
      });
      assert.strictEqual(reportRes5.status, 200);

      // 5. agent_firewall_rules shows error
      const ruleCheck5 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
        [commandId5]
      );
      assert.strictEqual(ruleCheck5.rows.length, 1);
      assert.strictEqual(ruleCheck5.rows[0].status, 'failed');
      assert.strictEqual(ruleCheck5.rows[0].result.error_type, 'no_firewall_detected');

      testResults.push({ scenario: 5, name: 'Firewall Tool Unavailable', passed: true });
      console.log('✅ Scenario 5 Passed: Missing OS firewall detected and recorded gracefully.');
    } catch (err) {
      console.error('❌ Scenario 5 Failed:', err);
      testResults.push({ scenario: 5, name: 'Firewall Tool Unavailable', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 6: Bidirectional Deletion
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 6: Bidirectional Deletion');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1. Rule exists: using manualRuleId2 from Scenario 2
      assert.ok(manualRuleId2, 'Rule from Scenario 2 must exist');
      const ruleCheck6 = await db.query(`SELECT status FROM public.agent_firewall_rules WHERE id = $1;`, [manualRuleId2]);
      assert.strictEqual(ruleCheck6.rows[0].status, 'active');

      // 2 & 3. Admin calls DELETE /admin/firewall-rules/:rule_id
      const delRes6 = await fetch(`${baseUrl}/admin/firewall-rules/${manualRuleId2}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminTokenA}` }
      });
      assert.strictEqual(delRes6.status, 200);
      const delBody6 = await delRes6.json();
      assert.strictEqual(delBody6.deleted, true);
      assert.strictEqual(delBody6.status, 'deletion_pending');
      assert.strictEqual(delBody6.agent_notified, true);
      assert.ok(delBody6.command_id);
      const deleteCmdId6 = delBody6.command_id;

      // Backend marked status='pending_delete'
      const statusPendingCheck = await db.query(`SELECT status FROM public.agent_firewall_rules WHERE id = $1;`, [manualRuleId2]);
      assert.strictEqual(statusPendingCheck.rows[0].status, 'pending_delete');

      // 4. Agent receives delete command
      const pollRes6 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
        headers: { 'x-agent-credential-id': credIdA, 'x-agent-credential-secret': credSecretA }
      });
      const pollBody6 = await pollRes6.json();
      const delCmd6 = (pollBody6.commands || []).find((c) => c.id === deleteCmdId6);
      assert.ok(delCmd6, 'Agent must receive delete command');
      assert.strictEqual(delCmd6.command_type, 'delete_firewall_rule');

      // 5 & 6. Agent executes deletion and reports status='completed'
      const reportRes6 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${deleteCmdId6}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        },
        body: JSON.stringify({
          status: 'completed',
          result: {
            success: true,
            deleted: true,
            rule_id_local: manualLocalRuleName2,
            message: 'Firewall rule removed successfully from OS'
          }
        })
      });
      assert.strictEqual(reportRes6.status, 200);

      // 7. Backend marks: agent_firewall_rules.status='deleted'
      const finalRuleCheck6 = await db.query(
        `SELECT status, deleted_at FROM public.agent_firewall_rules WHERE id = $1;`,
        [manualRuleId2]
      );
      assert.strictEqual(finalRuleCheck6.rows[0].status, 'deleted');
      assert.ok(finalRuleCheck6.rows[0].deleted_at, 'deleted_at must be populated');

      // 8. Audit log: 'firewall_rule_deleted'
      const auditRes6 = await db.query(
        `SELECT * FROM public.audit_logs WHERE action = 'firewall_rule_deleted' AND resource_id = $1 LIMIT 1;`,
        [manualRuleId2]
      );
      assert.strictEqual(auditRes6.rows.length, 1);

      testResults.push({ scenario: 6, name: 'Bidirectional Deletion', passed: true });
      console.log('✅ Scenario 6 Passed: Bidirectional deletion synced across DB, Agent OS rule, and Audit trail.');
    } catch (err) {
      console.error('❌ Scenario 6 Failed:', err);
      testResults.push({ scenario: 6, name: 'Bidirectional Deletion', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 7: Protected Targets Sync
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 7: Protected Targets Sync');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1. Agent calls GET /api/v1/agents/:device_id/protected-targets
      const protSyncRes = await fetch(`${baseUrl}/agents/${deviceIdA}/protected-targets`);
      assert.strictEqual(protSyncRes.status, 200);
      const protSyncBody = await protSyncRes.json();

      // 2. Receives: protected_ips, protected_domains, protected_ip_ranges
      assert.ok(Array.isArray(protSyncBody.protected_ips), 'protected_ips must be an array');
      assert.ok(Array.isArray(protSyncBody.protected_domains), 'protected_domains must be an array');
      assert.ok(Array.isArray(protSyncBody.protected_ip_ranges), 'protected_ip_ranges must be an array');

      // 3. Verify standard protected targets
      assert.ok(protSyncBody.protected_ips.includes('127.0.0.1'));
      assert.ok(protSyncBody.protected_domains.includes('localhost'));
      assert.ok(protSyncBody.protected_domains.includes('cyberguard.local'));

      // 4. Verify agent command polling also provides updated protected targets
      const pollTargetsRes = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
        headers: { 'x-agent-credential-id': credIdA, 'x-agent-credential-secret': credSecretA }
      });
      const pollTargetsBody = await pollTargetsRes.json();
      assert.ok(pollTargetsBody.protected_targets, 'Command polling must bundle live protected targets');

      testResults.push({ scenario: 7, name: 'Protected Targets Sync', passed: true });
      console.log('✅ Scenario 7 Passed: Agent fetches and syncs live protected target lists.');
    } catch (err) {
      console.error('❌ Scenario 7 Failed:', err);
      testResults.push({ scenario: 7, name: 'Protected Targets Sync', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 8: Rate Limiting
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 8: Rate Limiting');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1 & 2. First 10 execute successfully (recorded in agent_firewall_rules)
      for (let i = 1; i <= 10; i++) {
        const dummyIp = `198.51.100.${i}`;
        const cmdRes = await db.query(
          `INSERT INTO public.agent_commands (
            device_id, organization_id, command_type, target_data, status, can_execute, requires_approval, created_at
          ) VALUES ($1, $2, 'block_ip', $3, 'completed', true, false, NOW()) RETURNING id;`,
          [deviceIdA, orgIdA, JSON.stringify({ ip_address: dummyIp })]
        );
        await firewallService.createFirewallRuleFromCommandResult(
          deviceIdA,
          'block_ip',
          { ip_address: dummyIp },
          { success: true, rule_name: `CyberGuard-rate-${i}`, target: dummyIp },
          cmdRes.rows[0].id
        );
      }

      // 3. 11th command: agent returns error='rate_limit_exceeded'
      const cmd11Res = await db.query(
        `INSERT INTO public.agent_commands (
          device_id, organization_id, command_type, target_data, status, can_execute, requires_approval, created_at
        ) VALUES ($1, $2, 'block_ip', $3, 'failed', true, false, NOW()) RETURNING id;`,
        [deviceIdA, orgIdA, JSON.stringify({ ip_address: '198.51.100.11' })]
      );
      const cmd11Id = cmd11Res.rows[0].id;

      const rateLimitExecResult = {
        success: false,
        error_type: 'rate_limit_exceeded',
        error_message: 'Rate limit exceeded: maximum 10 firewall operations allowed per hour',
        platform: 'windows',
        attempted_action: 'block_ip',
        target: '198.51.100.11'
      };

      const res8 = await firewallService.createFirewallRuleFromCommandResult(
        deviceIdA,
        'block_ip',
        { ip_address: '198.51.100.11' },
        rateLimitExecResult,
        cmd11Id
      );

      // 4. agent_firewall_rules shows failed with rate_limit_exceeded
      assert.strictEqual(res8.status, 'failed');
      assert.strictEqual(res8.rule.result.error_type, 'rate_limit_exceeded');

      // 5. Audit log tracks failure
      const auditRes8 = await db.query(
        `SELECT * FROM public.audit_logs 
         WHERE action = 'firewall_rule_creation_failed' AND details->>'error_type' = 'rate_limit_exceeded'
         ORDER BY created_at DESC LIMIT 1;`
      );
      assert.strictEqual(auditRes8.rows.length, 1);

      testResults.push({ scenario: 8, name: 'Rate Limiting', passed: true });
      console.log('✅ Scenario 8 Passed: Rate limit error captured in rule result and audit log.');
    } catch (err) {
      console.error('❌ Scenario 8 Failed:', err);
      testResults.push({ scenario: 8, name: 'Rate Limiting', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 9: Cross-Org Isolation
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 9: Cross-Org Isolation');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1. Admin A in Org 1 has rules (e.g. 203.0.113.42)
      // 2. Admin B in Org 2 calls GET /admin/firewall-rules
      const listResB = await fetch(`${baseUrl}/admin/firewall-rules`, {
        headers: { Authorization: `Bearer ${adminTokenB}` }
      });
      assert.strictEqual(listResB.status, 200);
      const listBodyB = await listResB.json();
      const orgARuleInB = (listBodyB.rules || []).find((r) => r.target_ip === '203.0.113.42');
      assert.strictEqual(orgARuleInB, undefined, 'Org B must NEVER see Org A firewall rules');

      // 3. Admin B tries to delete Org A's rule
      const delAttemptRes = await fetch(`${baseUrl}/admin/firewall-rules/${manualRuleId2}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminTokenB}` }
      });
      assert.strictEqual(delAttemptRes.status, 404, 'Admin B must receive 404 when trying to delete Org A rule');

      // 4. Admin B tries to dispatch command to Org A's device
      const crossDispatchRes = await fetch(`${baseUrl}/admin/agents/${deviceIdA}/firewall-commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminTokenB}` },
        body: JSON.stringify({
          command_type: 'block_ip',
          target_data: { ip_address: '198.51.100.99' },
          reason: 'Cross-tenant attack attempt'
        })
      });
      assert.strictEqual(crossDispatchRes.status, 404, 'Cross-tenant agent command dispatch must return 404');

      testResults.push({ scenario: 9, name: 'Cross-Org Isolation', passed: true });
      console.log('✅ Scenario 9 Passed: Complete tenant isolation enforced for listing, deletion, and dispatching.');
    } catch (err) {
      console.error('❌ Scenario 9 Failed:', err);
      testResults.push({ scenario: 9, name: 'Cross-Org Isolation', passed: false, error: err.message });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Scenario 10: Agent Status Transitions
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n──────────────────────────────────────────────────────────────────────────');
    console.log('Test Scenario 10: Agent Status Transitions');
    console.log('──────────────────────────────────────────────────────────────────────────');
    try {
      // 1. Transition Agent A to 'offline'
      await db.query(`UPDATE public.devices SET status = 'offline' WHERE id = $1;`, [deviceIdA]);

      // 2. Queue command via agentCommandService while agent is offline
      const mockAction = {
        id: require('uuid').v4(),
        organization_id: orgIdA,
        action_type: 'block_ip',
        target: { ip_address: '203.0.113.99', target_device_id: deviceIdA },
        approved_by_id: adminIdA
      };

      const queueResult = await agentCommandService.createAgentCommandFromResponseAction(mockAction, deviceIdA);
      assert.strictEqual(queueResult.success, true);
      assert.ok(queueResult.command_id);
      const queuedOfflineCmdId = queueResult.command_id;

      // Verify command is in 'pending' status in DB waiting for agent
      const cmdPendingCheck = await db.query(`SELECT status FROM public.agent_commands WHERE id = $1;`, [queuedOfflineCmdId]);
      assert.strictEqual(cmdPendingCheck.rows[0].status, 'pending');

      // 3. Agent comes online via heartbeat
      const hbRes = await agentService.recordHeartbeat(deviceIdA, credIdA, credSecretA, { agent_version: '1.2.0' });
      assert.strictEqual(hbRes.status, 'online');

      // 4. Agent polls and receives queued command
      const pollRes10 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands`, {
        headers: { 'x-agent-credential-id': credIdA, 'x-agent-credential-secret': credSecretA }
      });
      const pollBody10 = await pollRes10.json();
      const foundQueuedCmd = (pollBody10.commands || []).find((c) => c.id === queuedOfflineCmdId);
      assert.ok(foundQueuedCmd, 'Agent must receive command queued while offline');

      // 5. Agent executes and reports success
      const reportRes10 = await fetch(`${baseUrl}/agents/${deviceIdA}/commands/${queuedOfflineCmdId}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-agent-credential-id': credIdA,
          'x-agent-credential-secret': credSecretA
        },
        body: JSON.stringify({
          status: 'completed',
          result: {
            success: true,
            rule_name: 'CyberGuard-reconnect-sync-99',
            firewall_tool: 'netsh',
            target: '203.0.113.99'
          }
        })
      });
      assert.strictEqual(reportRes10.status, 200);

      // Verify backend recorded rule
      const ruleCheck10 = await db.query(
        `SELECT * FROM public.agent_firewall_rules WHERE source_command_id = $1;`,
        [queuedOfflineCmdId]
      );
      assert.strictEqual(ruleCheck10.rows.length, 1);
      assert.strictEqual(ruleCheck10.rows[0].status, 'active');

      testResults.push({ scenario: 10, name: 'Agent Status Transitions', passed: true });
      console.log('✅ Scenario 10 Passed: Commands queue safely for offline agents and execute on reconnect.');
    } catch (err) {
      console.error('❌ Scenario 10 Failed:', err);
      testResults.push({ scenario: 10, name: 'Agent Status Transitions', passed: false, error: err.message });
    }

  } finally {
    // Teardown
    await new Promise((resolve) => server.close(resolve));
    console.log('\n[TEARDOWN] Test HTTP server closed.');
  }

  // Summary Report
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('                    FINAL TEST RESULTS SUMMARY                         ');
  console.log('════════════════════════════════════════════════════════════════════════');
  let allPassed = true;
  for (const r of testResults) {
    const symbol = r.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[Scenario ${r.scenario}] ${symbol} : ${r.name}`);
    if (!r.passed) {
      allPassed = false;
      console.log(`    Reason: ${r.error}`);
    }
  }

  console.log('════════════════════════════════════════════════════════════════════════');
  if (allPassed) {
    console.log('🏆 ALL 10 INTEGRATION SCENARIOS PASSED WITH ZERO ERRORS.');
    console.log('PHASE C FIREWALL SUBSYSTEM IS VERIFIED END-TO-END.');
  } else {
    console.log('⚠️ SOME SCENARIOS FAILED. PLEASE REVIEW LOGS.');
    process.exitCode = 1;
  }
}

if (require.main === module) {
  runCompleteIntegrationSuite()
    .then(() => {
      process.exit(process.exitCode || 0);
    })
    .catch((err) => {
      console.error('Fatal Test Suite Error:', err);
      process.exit(1);
    });
}

module.exports = { runCompleteIntegrationSuite };
