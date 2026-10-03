/**
 * CYBERGUARD Phase C.1: Firewall Integration Foundation Test Suite
 *
 * Verifies:
 * 1. Validate IP: "203.0.113.42" -> valid
 * 2. Validate IP: "not-an-ip" -> invalid
 * 3. Validate IP: "127.0.0.1" -> invalid (protected)
 * 4. Validate IP: backend's own IP / localhost -> invalid (protected)
 * 5. Validate domain: "evil.com" -> valid
 * 6. Validate domain: "*.evil.com" -> invalid (wildcard)
 * 7. Create rule: block_ip 203.0.113.42 -> status='pending', rule_id created
 * 8. Create rule: block_ip 127.0.0.1 -> rejected, validation_error
 * 9. List rules: org-scoped, confirm admin A can't see admin B's rules
 * 10. Delete rule: mark as 'pending_delete', audit logged
 * 11. Get protected targets: agent downloads list, includes localhost + internal ranges + backend IP
 * 12. Agent command polling: GET /agents/:device_id/commands includes protected_targets
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
const firewallService = require('./src/services/firewallService');
const agentService = require('./src/services/agentService');
const FirewallRule = require('./src/models/FirewallRule');

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

async function runFirewallFoundationTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C.1 FIREWALL INTEGRATION FOUNDATION TESTS');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    redis.enableMockRedis();
  }

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];
  const createdRuleIds = [];
  const timestamp = Date.now();

  try {
    // 0. Start test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}`);
        resolve();
      });
    });

    // Setup Test Orgs and Admin Users
    console.log('\n--- Setup Test Tenants ---');
    const orgARes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Test Org Firewall A ${timestamp}`]
    );
    const orgAId = orgARes.rows[0].id;
    createdOrgIds.push(orgAId);

    const orgBRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Test Org Firewall B ${timestamp}`]
    );
    const orgBId = orgBRes.rows[0].id;
    createdOrgIds.push(orgBId);

    const passwordHash = await bcrypt.hash('SecurePassword123!', 8);
    const adminARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id, email, role, organization_id;`,
      [`admin_a_${timestamp}@example.com`, passwordHash, orgAId]
    );
    const adminA = adminARes.rows[0];
    createdUserIds.push(adminA.id);
    const tokenA = createToken(adminA);

    const adminBRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING id, email, role, organization_id;`,
      [`admin_b_${timestamp}@example.com`, passwordHash, orgBId]
    );
    const adminB = adminBRes.rows[0];
    createdUserIds.push(adminB.id);
    const tokenB = createToken(adminB);

    // Create an enrolled device for Org A
    const enrollmentToken = await agentService.generateEnrollmentToken(orgAId);
    const enrolled = await agentService.enrollDevice({
      token: enrollmentToken,
      hostname: 'fw-agent-host',
      os: 'Linux Ubuntu 22.04',
      platform: 'linux'
    });
    const deviceAId = enrolled.device_id;
    createdDeviceIds.push(deviceAId);
    console.log(`[SETUP] Enrolled test agent ${deviceAId} for Org A`);

    // ──────────────────────────────────────────────────────────────────────────
    // Unit & Service Validations
    // ──────────────────────────────────────────────────────────────────────────

    // Test 1: Validate IP: "203.0.113.42" -> valid
    console.log('\n--- Test 1: Validate Public IP (203.0.113.42) ---');
    const v1 = firewallService.validateFirewallInput('block_ip', { ip_address: '203.0.113.42' });
    assert.strictEqual(v1.valid, true, 'Public IP must be valid');
    assert.strictEqual(v1.target_ip, '203.0.113.42');
    console.log('✔ Passed: 203.0.113.42 is valid');

    // Test 2: Validate IP: "not-an-ip" -> invalid
    console.log('\n--- Test 2: Validate Malformed IP ("not-an-ip") ---');
    const v2 = firewallService.validateFirewallInput('block_ip', { ip_address: 'not-an-ip' });
    assert.strictEqual(v2.valid, false, 'Malformed string must be rejected');
    assert.ok(v2.error.includes('Invalid IP address format'), 'Error must note invalid format');
    console.log(`✔ Passed: Rejected invalid IP with error: "${v2.error}"`);

    // Test 3: Validate IP: "127.0.0.1" -> invalid (protected)
    console.log('\n--- Test 3: Validate Protected Loopback IP ("127.0.0.1") ---');
    const v3 = firewallService.validateFirewallInput('block_ip', { ip_address: '127.0.0.1' });
    assert.strictEqual(v3.valid, false, '127.0.0.1 must be rejected');
    assert.ok(v3.error.includes('protected'), 'Must specify IP is protected');
    console.log(`✔ Passed: Rejected protected IP: "${v3.error}"`);

    // Test 4: Validate IP: backend's own IP / RFC 1918 range -> invalid (protected)
    console.log('\n--- Test 4: Validate Private / Internal Ranges ("10.0.0.1", "192.168.1.1") ---');
    const v4a = firewallService.validateFirewallInput('block_ip', { ip_address: '10.0.0.1' });
    assert.strictEqual(v4a.valid, false, '10.0.0.1 (RFC 1918) must be rejected');
    assert.ok(v4a.error.includes('protected'), 'Must specify IP is protected');

    const v4b = firewallService.validateFirewallInput('block_ip', { ip_address: '192.168.1.50' });
    assert.strictEqual(v4b.valid, false, '192.168.1.50 (RFC 1918) must be rejected');
    assert.ok(v4b.error.includes('protected'), 'Must specify IP is protected');
    console.log('✔ Passed: Rejected private / internal range targets');

    // Test 5: Validate domain: "evil.com" -> valid
    console.log('\n--- Test 5: Validate Domain ("evil.com") ---');
    const v5 = firewallService.validateFirewallInput('block_domain', { domain: 'evil.com' });
    assert.strictEqual(v5.valid, true, 'Valid domain must be accepted');
    assert.strictEqual(v5.target_domain, 'evil.com');
    console.log('✔ Passed: evil.com is valid');

    // Test 6: Validate domain: "*.evil.com" -> invalid (wildcard)
    console.log('\n--- Test 6: Validate Wildcard Domain ("*.evil.com") ---');
    const v6 = firewallService.validateFirewallInput('block_domain', { domain: '*.evil.com' });
    assert.strictEqual(v6.valid, false, 'Wildcard domain must be rejected');
    assert.ok(v6.error.toLowerCase().includes('wildcard'), 'Error must mention wildcards');
    console.log(`✔ Passed: Wildcard rejected with: "${v6.error}"`);

    // Test 6b: Protected domain: "localhost" -> invalid (protected)
    console.log('\n--- Test 6b: Validate Protected Domain ("localhost") ---');
    const v6b = firewallService.validateFirewallInput('block_domain', { domain: 'localhost' });
    assert.strictEqual(v6b.valid, false, 'localhost must be rejected');
    assert.ok(v6b.error.includes('protected'), 'Error must mention protected domain');
    console.log(`✔ Passed: Protected domain rejected: "${v6b.error}"`);

    // ──────────────────────────────────────────────────────────────────────────
    // API Endpoints Tests
    // ──────────────────────────────────────────────────────────────────────────

    // Test 7: API POST /api/v1/admin/firewall-rules/validate endpoint
    console.log('\n--- Test 7: API Pre-Validation Endpoint ---');
    const apiValRes = await fetch(`${baseUrl}/admin/firewall-rules/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        rule_type: 'block_ip',
        target_data: { ip_address: '203.0.113.42' }
      })
    });
    assert.strictEqual(apiValRes.status, 200);
    const apiValBody = await apiValRes.json();
    assert.strictEqual(apiValBody.valid, true);
    assert.strictEqual(apiValBody.target_ip, '203.0.113.42');
    console.log('✔ Passed: API pre-validation endpoint verified');

    // Test 8: Create rule: block_ip 203.0.113.42 -> status='pending', rule_id created
    console.log('\n--- Test 8: Create Rule via API (203.0.113.42) ---');
    const createRes = await fetch(`${baseUrl}/admin/firewall-rules`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        agent_id: deviceAId,
        rule_type: 'block_ip',
        target_data: { ip_address: '203.0.113.42' }
      })
    });
    assert.strictEqual(createRes.status, 201, 'Should return 201 Created');
    const createBody = await createRes.json();
    assert.strictEqual(createBody.success, true);
    assert.strictEqual(createBody.status, 'pending', "Rule must start with status 'pending'");
    assert.ok(createBody.rule_id, 'Must return rule_id');
    createdRuleIds.push(createBody.rule_id);
    console.log(`✔ Passed: Created rule ${createBody.rule_id} with status='${createBody.status}'`);

    // Test 9: Create rule: block_ip 127.0.0.1 -> rejected, validation_error
    console.log('\n--- Test 9: Create Rule with Protected IP (127.0.0.1) Rejected ---');
    const rejectRes = await fetch(`${baseUrl}/admin/firewall-rules`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        agent_id: deviceAId,
        rule_type: 'block_ip',
        target_data: { ip_address: '127.0.0.1' }
      })
    });
    assert.strictEqual(rejectRes.status, 400, 'Should return 400 Bad Request');
    const rejectBody = await rejectRes.json();
    assert.strictEqual(rejectBody.error, 'VALIDATION_FAILED');
    assert.ok(rejectBody.message.includes('protected'), 'Message must explain target is protected');
    console.log(`✔ Passed: Creation rejected for protected target: "${rejectBody.message}"`);

    // Test 10: List rules: org-scoped, confirm admin A can't see admin B's rules
    console.log("\n--- Test 10: Multi-Tenant Scoping for Listing Rules ---");
    // Admin A lists rules
    const listARes = await fetch(`${baseUrl}/admin/firewall-rules`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert.strictEqual(listARes.status, 200);
    const listABody = await listARes.json();
    assert.ok(listABody.total >= 1, 'Admin A should see their created rule');
    assert.ok(listABody.rules.some(r => r.id === createBody.rule_id));

    // Admin B lists rules
    const listBRes = await fetch(`${baseUrl}/admin/firewall-rules`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert.strictEqual(listBRes.status, 200);
    const listBBody = await listBRes.json();
    assert.strictEqual(listBBody.total, 0, 'Admin B should NOT see Admin A rules');
    assert.ok(!listBBody.rules.some(r => r.id === createBody.rule_id));
    console.log("✔ Passed: Multi-tenant isolation verified (Admin B cannot see Admin A's rules)");

    // Test 11: Delete rule: mark as 'pending_delete', audit logged
    console.log("\n--- Test 11: Delete Rule (Mark 'pending_delete' & Verify Audit Log) ---");
    const deleteRes = await fetch(`${baseUrl}/admin/firewall-rules/${createBody.rule_id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert.strictEqual(deleteRes.status, 200, 'Delete must succeed');
    const deleteBody = await deleteRes.json();
    assert.strictEqual(deleteBody.deleted, true);

    // Verify status in DB is 'pending_delete'
    const dbRuleRes = await db.query(
      'SELECT status, deleted_at FROM public.agent_firewall_rules WHERE id = $1;',
      [createBody.rule_id]
    );
    assert.strictEqual(dbRuleRes.rows[0].status, 'pending_delete');
    assert.ok(dbRuleRes.rows[0].deleted_at, 'deleted_at must be populated');

    // Verify audit log entry exists
    const auditRes = await db.query(
      `SELECT action, resource_type, resource_id FROM public.audit_logs 
       WHERE resource_id = $1 AND action = 'firewall_rule_deleted';`,
      [createBody.rule_id]
    );
    assert.ok(auditRes.rows.length >= 1, 'Audit log entry must be present for firewall_rule_deleted');
    console.log("✔ Passed: Rule marked as 'pending_delete' and audit log recorded");

    // Test 12: Get protected targets: agent downloads list, includes localhost + internal ranges + backend IP
    console.log("\n--- Test 12: Agent Protected Targets Download ---");
    const protRes = await fetch(`${baseUrl}/agents/${deviceAId}/protected-targets`);
    assert.strictEqual(protRes.status, 200);
    const protBody = await protRes.json();
    assert.ok(Array.isArray(protBody.protected_ips), 'protected_ips must be an array');
    assert.ok(protBody.protected_ips.includes('127.0.0.1'), 'Must include 127.0.0.1');
    assert.ok(Array.isArray(protBody.protected_ip_ranges), 'protected_ip_ranges must be an array');
    assert.ok(protBody.protected_ip_ranges.includes('10.0.0.0/8'), 'Must include 10.0.0.0/8');
    assert.ok(protBody.protected_ip_ranges.includes('192.168.0.0/16'), 'Must include 192.168.0.0/16');
    assert.ok(Array.isArray(protBody.protected_domains), 'protected_domains must be an array');
    assert.ok(protBody.protected_domains.includes('localhost'), 'Must include localhost');
    console.log("✔ Passed: Agent successfully retrieved protected targets catalog");

    // Test 13: Agent command polling includes protected_targets
    console.log("\n--- Test 13: Command Polling Includes protected_targets ---");
    const cmdPollRes = await fetch(
      `${baseUrl}/agents/${deviceAId}/commands?credential_id=${enrolled.credential_id}&credential_secret=${enrolled.credential_secret}`
    );
    assert.strictEqual(cmdPollRes.status, 200);
    const cmdPollBody = await cmdPollRes.json();
    assert.ok(Array.isArray(cmdPollBody.commands), 'commands must be an array');
    assert.ok(cmdPollBody.protected_targets, 'Response must include protected_targets');
    assert.ok(Array.isArray(cmdPollBody.protected_targets.protected_ips), 'protected_ips included');
    console.log("✔ Passed: Command polling returned commands and protected_targets");

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 13 PHASE C.1 FIREWALL FOUNDATION TESTS PASSED SUCCESSFULLY!  ');
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } catch (err) {
    console.error('\n❌ Test execution failed:', err);
    process.exitCode = 1;
    throw err;
  } finally {
    // Cleanup created test records
    console.log('[CLEANUP] Removing test fixtures...');
    try {
      if (createdRuleIds.length > 0) {
        await db.query(`DELETE FROM public.agent_firewall_rules WHERE id = ANY($1);`, [createdRuleIds]);
      }
      if (createdDeviceIds.length > 0) {
        await db.query(`DELETE FROM public.devices WHERE id = ANY($1);`, [createdDeviceIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [createdOrgIds]);
      }
    } catch (cleanErr) {
      console.error('[CLEANUP ERROR]', cleanErr.message);
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
      console.log('[CLEANUP] Test server closed.');
    }
  }
}

if (require.main === module) {
  runFirewallFoundationTests()
    .then(() => {
      console.log('Test run finished.');
      process.exit(0);
    })
    .catch(() => {
      process.exit(1);
    });
}

module.exports = { runFirewallFoundationTests };
