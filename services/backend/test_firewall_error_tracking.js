/**
 * test_firewall_error_tracking.js
 *
 * Verifies Phase C Comprehensive Error Tracking and Audit Logging for Firewall Actions:
 * - Test 1: Successful rule creation -> agent_firewall_rules.result has success=true
 * - Test 2: Agent lacks privilege -> result has error_type='insufficient_privileges'
 * - Test 3: Protected target -> result has error_type='target_protected'
 * - Test 4: Rate limit exceeded -> result has error_type='rate_limit_exceeded'
 * - Test 5: Firewall command failed -> result includes command_output (stderr)
 * - Test 6: Each error creates audit_log entry with action='firewall_rule_creation_failed'
 * - Test 7: Deletion failure -> audit_log has action='firewall_rule_deletion_failed'
 * - Test 8: Admin sees error details in GET /admin/firewall-rules response (via listFirewallRules)
 * - Test 9: Dashboard can filter by status='failed' to see only errors
 * - Test 10: Audit log tells complete story: who triggered, what happened, why it failed
 */

const assert = require('assert');
const { v4: uuidv4 } = require('uuid');
const db = require('./src/config/db');
const firewallService = require('./src/services/firewallService');
const { AUDIT_ACTIONS } = require('./src/services/auditService');

async function runTests() {
  console.log('--- STARTING FIREWALL ERROR TRACKING & AUDIT LOG TESTS ---');

  let testOrgId = null;
  let testUserId = null;
  let testDeviceId = null;
  const testAdminEmail = `admin-${Date.now()}@example.com`;

  try {
    // 0. Setup Fixtures
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Audit Test Org ${Date.now()}`]
    );
    testOrgId = orgRes.rows[0].id;

    const userRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, 'hash123', 'admin', $2) RETURNING id;`,
      [testAdminEmail, testOrgId]
    );
    testUserId = userRes.rows[0].id;

    const devRes = await db.query(
      `INSERT INTO public.devices (organization_id, hostname, os, platform, status)
       VALUES ($1, 'laptop-john', 'Linux Ubuntu 22.04', 'linux', 'online') RETURNING id;`,
      [testOrgId]
    );
    testDeviceId = devRes.rows[0].id;

    // Test 1: Successful rule creation -> result has success=true
    console.log('\n[Test 1] Successful rule creation');
    const cmd1Res = await db.query(
      `INSERT INTO public.agent_commands (device_id, organization_id, command_type, target_data, status, requested_by_id, created_at)
       VALUES ($1, $2, 'block_ip', '{"ip_address":"203.0.113.42"}', 'completed', $3, NOW())
       RETURNING id;`,
      [testDeviceId, testOrgId, testUserId]
    );
    const cmd1Id = cmd1Res.rows[0].id;

    const successExecResult = {
      success: true,
      rule_name: 'CyberGuard-block_ip-a1b2c3d4',
      firewall_tool: 'ufw',
      target: '203.0.113.42',
      created_at: new Date().toISOString()
    };

    const res1 = await firewallService.createFirewallRuleFromCommandResult(
      testDeviceId,
      'block_ip',
      { ip_address: '203.0.113.42' },
      successExecResult,
      cmd1Id
    );

    assert.strictEqual(res1.status, 'active');
    assert.strictEqual(res1.rule.result.success, true);
    assert.strictEqual(res1.rule.result.rule_name, 'CyberGuard-block_ip-a1b2c3d4');
    assert.strictEqual(res1.rule.result.firewall_tool, 'ufw');
    console.log('✅ Test 1 Passed: Successful rule stored with success=true and firewall_tool=ufw');

    // Test 2: Agent lacks privilege -> result has error_type='insufficient_privileges'
    console.log('\n[Test 2] Agent lacks privilege');
    const cmd2Res = await db.query(
      `INSERT INTO public.agent_commands (device_id, organization_id, command_type, target_data, status, requested_by_id, created_at)
       VALUES ($1, $2, 'block_ip', '{"ip_address":"203.0.113.43"}', 'failed', $3, NOW())
       RETURNING id;`,
      [testDeviceId, testOrgId, testUserId]
    );
    const cmd2Id = cmd2Res.rows[0].id;

    const privFailResult = {
      success: false,
      error_type: 'insufficient_privileges',
      error_message: 'Firewall execution requires admin rights',
      platform: 'windows',
      attempted_action: 'block_ip',
      target: '203.0.113.43'
    };

    const res2 = await firewallService.createFirewallRuleFromCommandResult(
      testDeviceId,
      'block_ip',
      { ip_address: '203.0.113.43' },
      privFailResult,
      cmd2Id
    );

    assert.strictEqual(res2.status, 'failed');
    assert.strictEqual(res2.rule.result.success, false);
    assert.strictEqual(res2.rule.result.error_type, 'insufficient_privileges');
    assert.strictEqual(res2.rule.result.error_message, 'Firewall execution requires admin rights');
    assert.strictEqual(res2.rule.result.platform, 'windows');
    console.log('✅ Test 2 Passed: Privilege error stored with error_type="insufficient_privileges"');

    // Test 3: Protected target -> result has error_type='target_protected'
    console.log('\n[Test 3] Protected target');
    const cmd3Res = await db.query(
      `INSERT INTO public.agent_commands (device_id, organization_id, command_type, target_data, status, requested_by_id, created_at)
       VALUES ($1, $2, 'block_ip', '{"ip_address":"192.168.1.1"}', 'failed', $3, NOW())
       RETURNING id;`,
      [testDeviceId, testOrgId, testUserId]
    );
    const cmd3Id = cmd3Res.rows[0].id;

    const protFailResult = {
      success: false,
      error_type: 'target_protected',
      error_message: 'Cannot block protected target: 192.168.1.1',
      platform: 'linux',
      reason: 'target_in_protected_list',
      attempted_action: 'block_ip',
      target: '192.168.1.1'
    };

    const res3 = await firewallService.createFirewallRuleFromCommandResult(
      testDeviceId,
      'block_ip',
      { ip_address: '192.168.1.1' },
      protFailResult,
      cmd3Id
    );

    assert.strictEqual(res3.status, 'failed');
    assert.strictEqual(res3.rule.result.success, false);
    assert.strictEqual(res3.rule.result.error_type, 'target_protected');
    assert.strictEqual(res3.rule.result.reason, 'target_in_protected_list');
    console.log('✅ Test 3 Passed: Protected target failure stored with error_type="target_protected"');

    // Test 4: Rate limit exceeded -> result has error_type='rate_limit_exceeded'
    console.log('\n[Test 4] Rate limit exceeded');
    const cmd4Res = await db.query(
      `INSERT INTO public.agent_commands (device_id, organization_id, command_type, target_data, status, requested_by_id, created_at)
       VALUES ($1, $2, 'block_ip', '{"ip_address":"203.0.113.44"}', 'failed', $3, NOW())
       RETURNING id;`,
      [testDeviceId, testOrgId, testUserId]
    );
    const cmd4Id = cmd4Res.rows[0].id;

    const rateFailResult = {
      success: false,
      error_type: 'rate_limit_exceeded',
      error_message: 'Rate limit exceeded: maximum 10 rules per rolling hour',
      platform: 'linux',
      attempted_action: 'block_ip',
      target: '203.0.113.44'
    };

    const res4 = await firewallService.createFirewallRuleFromCommandResult(
      testDeviceId,
      'block_ip',
      { ip_address: '203.0.113.44' },
      rateFailResult,
      cmd4Id
    );

    assert.strictEqual(res4.status, 'failed');
    assert.strictEqual(res4.rule.result.success, false);
    assert.strictEqual(res4.rule.result.error_type, 'rate_limit_exceeded');
    console.log('✅ Test 4 Passed: Rate limit error stored with error_type="rate_limit_exceeded"');

    // Test 5: Firewall command failed -> result includes command_output (stderr)
    console.log('\n[Test 5] Firewall command failed with stderr output');
    const cmd5Res = await db.query(
      `INSERT INTO public.agent_commands (device_id, organization_id, command_type, target_data, status, requested_by_id, created_at)
       VALUES ($1, $2, 'block_ip', '{"ip_address":"203.0.113.45"}', 'failed', $3, NOW())
       RETURNING id;`,
      [testDeviceId, testOrgId, testUserId]
    );
    const cmd5Id = cmd5Res.rows[0].id;

    const cmdFailResult = {
      success: false,
      error_type: 'firewall_command_failed',
      error_message: 'ufw command returned non-zero exit code',
      firewall_tool: 'ufw',
      command_output: 'ERROR: Could not parse rule\n',
      platform: 'linux',
      attempted_action: 'block_ip',
      target: '203.0.113.45'
    };

    const res5 = await firewallService.createFirewallRuleFromCommandResult(
      testDeviceId,
      'block_ip',
      { ip_address: '203.0.113.45' },
      cmdFailResult,
      cmd5Id
    );

    assert.strictEqual(res5.status, 'failed');
    assert.strictEqual(res5.rule.result.success, false);
    assert.strictEqual(res5.rule.result.error_type, 'firewall_command_failed');
    assert.strictEqual(res5.rule.result.command_output, 'ERROR: Could not parse rule\n');
    console.log('✅ Test 5 Passed: Command failure includes command_output (stderr)');

    // Test 6: Each error creates audit_log entry with action='firewall_rule_creation_failed'
    console.log('\n[Test 6] Audit log contains firewall_rule_creation_failed entries');
    const creationFailAudits = await db.query(
      `SELECT * FROM public.audit_logs 
       WHERE organization_id = $1 AND action = 'firewall_rule_creation_failed'
       ORDER BY created_at ASC;`,
      [testOrgId]
    );

    assert(creationFailAudits.rows.length >= 4, `Expected at least 4 creation failure audit logs, got ${creationFailAudits.rows.length}`);
    const loggedErrorTypes = creationFailAudits.rows.map(r => r.details.error_type);
    assert(loggedErrorTypes.includes('insufficient_privileges'), 'Audit log missing insufficient_privileges');
    assert(loggedErrorTypes.includes('target_protected'), 'Audit log missing target_protected');
    assert(loggedErrorTypes.includes('rate_limit_exceeded'), 'Audit log missing rate_limit_exceeded');
    assert(loggedErrorTypes.includes('firewall_command_failed'), 'Audit log missing firewall_command_failed');
    console.log('✅ Test 6 Passed: Audit log accurately captured all creation failures with action="firewall_rule_creation_failed"');

    // Test 7: Deletion failure -> audit_log has action='firewall_rule_deletion_failed'
    console.log('\n[Test 7] Deletion failure generates firewall_rule_deletion_failed audit log');
    // Subcase 7A: Rule not found deletion attempt
    const nonExistentRuleId = uuidv4();
    await firewallService.deleteFirewallRule(nonExistentRuleId, testOrgId, testUserId);

    // Subcase 7B: Agent reports deletion failure
    await firewallService.recordFirewallRuleDeletionResult(
      testDeviceId,
      { rule_id: res1.rule.id, rule_id_local: 'CyberGuard-block_ip-a1b2c3d4', target: '203.0.113.42' },
      {
        success: false,
        error_type: 'rule_not_found',
        error_message: 'Rule CyberGuard-block_ip-a1b2c3d4 not found in ufw'
      },
      'failed'
    );

    const deletionFailAudits = await db.query(
      `SELECT * FROM public.audit_logs 
       WHERE organization_id = $1 AND action = 'firewall_rule_deletion_failed';`,
      [testOrgId]
    );

    assert(deletionFailAudits.rows.length >= 2, `Expected at least 2 deletion failure logs, got ${deletionFailAudits.rows.length}`);
    assert(deletionFailAudits.rows.some(r => r.details.error_type === 'rule_not_found'));
    console.log('✅ Test 7 Passed: Deletion failure logged with action="firewall_rule_deletion_failed"');

    // Test 8: Admin sees error details in GET /admin/firewall-rules response (FirewallRule.findByOrg)
    console.log('\n[Test 8] Admin listing includes agent_name, created_by, target, source, and result error details');
    const listResult = await firewallService.listFirewallRules(testOrgId);
    assert(listResult.rules.length >= 5, `Expected at least 5 rules in listing, got ${listResult.rules.length}`);

    const failedRule = listResult.rules.find(r => r.result?.error_type === 'firewall_command_failed');
    assert(failedRule, 'Failed rule with command_output not found in list response');
    assert.strictEqual(failedRule.agent_name, 'laptop-john');
    assert.strictEqual(failedRule.created_by, testAdminEmail);
    assert.strictEqual(failedRule.target, '203.0.113.45');
    assert.strictEqual(failedRule.source, 'manual');
    assert.strictEqual(failedRule.result.success, false);
    assert.strictEqual(failedRule.result.command_output, 'ERROR: Could not parse rule\n');
    console.log('✅ Test 8 Passed: Admin listing returns full rule metadata, source="manual", and detailed error result');

    // Test 9: Dashboard can filter by status='failed' to see only errors
    console.log('\n[Test 9] Dashboard status filter for status="failed"');
    const failedRulesList = await firewallService.listFirewallRules(testOrgId, { status: 'failed' });
    assert(failedRulesList.rules.length >= 4, `Expected at least 4 failed rules, got ${failedRulesList.rules.length}`);
    for (const rule of failedRulesList.rules) {
      assert.strictEqual(rule.status, 'failed', `Rule status expected 'failed', got '${rule.status}'`);
      assert(rule.result && rule.result.error_type, 'Failed rule missing result.error_type');
    }
    console.log('✅ Test 9 Passed: Dashboard correctly filters rules where status="failed"');

    // Test 10: Audit log tells complete story
    console.log('\n[Test 10] Complete audit trail verification');
    const fullAuditTrail = await db.query(
      `SELECT action, actor_type, user_id, resource_type, details
       FROM public.audit_logs
       WHERE organization_id = $1
       ORDER BY created_at ASC;`,
      [testOrgId]
    );

    const actions = fullAuditTrail.rows.map(r => r.action);
    assert(actions.includes('firewall_rule_created'), 'Audit trail missing firewall_rule_created');
    assert(actions.includes('firewall_rule_creation_failed'), 'Audit trail missing firewall_rule_creation_failed');
    assert(actions.includes('firewall_rule_deletion_failed'), 'Audit trail missing firewall_rule_deletion_failed');

    const sampleFail = fullAuditTrail.rows.find(r => r.action === 'firewall_rule_creation_failed' && r.details.error_type === 'target_protected');
    assert.strictEqual(sampleFail.user_id, testUserId, 'Audit user_id should match admin who requested the command');
    assert.strictEqual(sampleFail.actor_type, 'admin');
    assert.strictEqual(sampleFail.details.target, '192.168.1.1');
    assert.strictEqual(sampleFail.details.error_type, 'target_protected');
    assert.strictEqual(sampleFail.details.error_message, 'Cannot block protected target: 192.168.1.1');
    console.log('✅ Test 10 Passed: Audit log details tell complete story: who triggered, what happened, why it failed');

    console.log('\n======================================================');
    console.log('🎉 ALL 10 FIREWALL ERROR TRACKING TESTS PASSED SUCCESSFULLY!');
    console.log('======================================================');

  } finally {
    // Cleanup fixtures
    await db.query(`DELETE FROM public.audit_logs WHERE organization_id = $1;`, [testOrgId]).catch(() => {});
    await db.query(`DELETE FROM public.agent_firewall_rules WHERE organization_id = $1;`, [testOrgId]).catch(() => {});
    await db.query(`DELETE FROM public.agent_commands WHERE organization_id = $1;`, [testOrgId]).catch(() => {});
    await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [testOrgId]).catch(() => {});
    await db.query(`DELETE FROM public.users WHERE organization_id = $1;`, [testOrgId]).catch(() => {});
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [testOrgId]).catch(() => {});
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('❌ Test failed with error:', err);
    process.exit(1);
  });
