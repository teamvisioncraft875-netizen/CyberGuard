/**
 * CYBERGUARD Phase C: Live Protected Targets Endpoint Integration Tests
 * Validates:
 * 1. GET /api/v1/agents/:device_id/protected-targets is public (no auth required)
 * 2. Returns protected IPs, RFC 1918 CIDRs, protected domains, and updated_at timestamp
 * 3. Dynamically extracts and protects backend IP
 * 4. Enterprise Agent uses live list on startup & updates
 * 5. Python agent rejects protected targets using live list and reflects dynamic updates
 */

process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);
const { app } = require('./src');
const db = require('./src/config/db');
const agentService = require('./src/services/agentService');

async function runProtectedTargetsTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE C LIVE PROTECTED TARGETS INTEGRATION TESTS');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  console.log(`[INIT] Test server running on ${baseUrl}`);

  const timestamp = Date.now();
  let orgId = null;
  let deviceId = null;
  const pyRunnerPath = path.resolve(__dirname, '../enterprise-agent/test_live_targets_runner.py');

  try {
    // 1. Setup Tenant and Device
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING id;`,
      [`Test Org Protected Targets ${timestamp}`]
    );
    orgId = orgRes.rows[0].id;

    const enrollToken = await agentService.generateEnrollmentToken(orgId, 24);
    const enrolled = await agentService.enrollDevice({
      token: enrollToken,
      hostname: `workstation-prot-${timestamp}`,
      os: 'Windows 11 Enterprise',
      platform: 'win32',
      agent_version: '1.0.0'
    });
    deviceId = enrolled.device_id;
    console.log(`[SETUP] Initialized Org=${orgId}, Device=${deviceId}`);

    // --- TEST 1: Public endpoint accessible with NO auth ---
    console.log('\n--- Test 1: Public endpoint accessible with NO auth headers ---');
    const res1 = await fetch(`${baseUrl}/agents/${deviceId}/protected-targets`);
    assert.strictEqual(res1.status, 200, `Expected 200, got ${res1.status}`);

    const targets1 = await res1.json();
    assert.ok(Array.isArray(targets1.protected_ips), 'protected_ips must be an array');
    assert.ok(Array.isArray(targets1.protected_ip_ranges), 'protected_ip_ranges must be an array');
    assert.ok(Array.isArray(targets1.protected_domains), 'protected_domains must be an array');
    assert.ok(targets1.updated_at, 'updated_at timestamp must exist');

    assert.ok(targets1.protected_ips.includes('127.0.0.1'), 'Must protect 127.0.0.1');
    assert.ok(targets1.protected_domains.includes('localhost'), 'Must protect localhost');
    assert.ok(targets1.protected_ip_ranges.includes('10.0.0.0/8'), 'Must protect 10.0.0.0/8');
    assert.ok(targets1.protected_ip_ranges.includes('192.168.0.0/16'), 'Must protect 192.168.0.0/16');
    console.log(`✔ Passed: Returned ${targets1.protected_ips.length} IPs, ${targets1.protected_ip_ranges.length} CIDRs, ${targets1.protected_domains.length} domains with updated_at='${targets1.updated_at}'`);

    // --- TEST 2: Dynamic Backend IP extraction ---
    console.log('\n--- Test 2: Dynamic Backend IP extraction ---');
    process.env.CYBERGUARD_BACKEND_IP = '198.51.100.77';
    const res2 = await fetch(`${baseUrl}/agents/${deviceId}/protected-targets`);
    assert.strictEqual(res2.status, 200);
    const targets2 = await res2.json();
    assert.ok(
      targets2.protected_ips.includes('198.51.100.77'),
      'Backend IP (198.51.100.77) must be included in protected_ips'
    );
    console.log('✔ Passed: Dynamic backend IP 198.51.100.77 successfully included in live protected list');

    // --- TEST 3: Enterprise Agent Python integration (Live list on startup) ---
    console.log('\n--- Test 3: Enterprise Agent Python integration (Live list on startup) ---');
    const pyScript = `import sys
from config import AgentConfig
from command_handler import fetch_protected_targets
from firewall_executor import FirewallExecutor

backend_url = "${baseUrl}".replace("/api/v1", "")
device_id = "${deviceId}"

config = AgentConfig()
config.backend_url = backend_url
config.device_id = device_id

# 1. Fetch live targets on startup
targets = fetch_protected_targets(config)
print("Fetched protected IPs count:", len(targets.get("protected_ips", [])))
assert "198.51.100.77" in targets.get("protected_ips", []), "Backend IP 198.51.100.77 must be in fetched live targets"
assert "127.0.0.1" in targets.get("protected_ips", []), "127.0.0.1 must be in fetched live targets"

# 2. Instantiate executor with live targets
executor = FirewallExecutor(dry_run=True, protected_targets=targets)

# 3. Test rejection of backend IP
res_blocked_backend = executor.validate_and_execute({
    "command_type": "block_ip",
    "target_data": {"ip_address": "198.51.100.77"}
})
assert res_blocked_backend["success"] is False
assert res_blocked_backend["error"] == "target_protected"

# 4. Test acceptance of benign external IP
res_allowed = executor.validate_and_execute({
    "command_type": "block_ip",
    "target_data": {"ip_address": "203.0.113.88"}
})
assert res_allowed["success"] is True

print("PYTHON_AGENT_TEST_SUCCESS")
`;
    fs.writeFileSync(pyRunnerPath, pyScript, 'utf-8');

    let pyOutput = '';
    try {
      const res = await execPromise(`python test_live_targets_runner.py`, {
        cwd: path.resolve(__dirname, '../enterprise-agent')
      });
      pyOutput = res.stdout;
    } finally {
      if (fs.existsSync(pyRunnerPath)) fs.unlinkSync(pyRunnerPath);
    }

    assert.ok(pyOutput.includes('PYTHON_AGENT_TEST_SUCCESS'), 'Python agent execution must succeed');
    console.log('✔ Passed: Python agent loaded live list and rejected protected backend IP');

    // --- TEST 4: Live List Updates Dynamic Propagation ---
    console.log('\n--- Test 4: Live List Updates Dynamic Propagation ---');
    process.env.CYBERGUARD_BACKEND_IP = '198.51.100.99';

    const pyUpdateScript = `import sys
from config import AgentConfig
from command_handler import fetch_protected_targets
from firewall_executor import FirewallExecutor

backend_url = "${baseUrl}".replace("/api/v1", "")
device_id = "${deviceId}"

config = AgentConfig()
config.backend_url = backend_url
config.device_id = device_id

# Re-fetch live targets after backend update
new_targets = fetch_protected_targets(config)
print("Updated protected IPs count:", len(new_targets.get("protected_ips", [])))
assert "198.51.100.99" in new_targets.get("protected_ips", []), "Updated IP 198.51.100.99 must be in newly fetched targets"

executor = FirewallExecutor(dry_run=True, protected_targets=new_targets)
res = executor.validate_and_execute({
    "command_type": "block_ip",
    "target_data": {"ip_address": "198.51.100.99"}
})
assert res["success"] is False
assert res["error"] == "target_protected"

print("PYTHON_UPDATE_TEST_SUCCESS")
`;
    fs.writeFileSync(pyRunnerPath, pyUpdateScript, 'utf-8');

    let pyUpdateOutput = '';
    try {
      const res = await execPromise(`python test_live_targets_runner.py`, {
        cwd: path.resolve(__dirname, '../enterprise-agent')
      });
      pyUpdateOutput = res.stdout;
    } finally {
      if (fs.existsSync(pyRunnerPath)) fs.unlinkSync(pyRunnerPath);
    }

    assert.ok(pyUpdateOutput.includes('PYTHON_UPDATE_TEST_SUCCESS'), 'Python agent update test must succeed');
    console.log('✔ Passed: Python agent dynamically updated protected targets and protected new backend IP');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 4 LIVE PROTECTED TARGETS TESTS PASSED SUCCESSFULLY!  ');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    if (fs.existsSync(pyRunnerPath)) fs.unlinkSync(pyRunnerPath);
    delete process.env.CYBERGUARD_BACKEND_IP;
    console.log('[CLEANUP] Cleaning up test fixtures...');
    if (orgId) {
      await db.query(`DELETE FROM public.agent_commands WHERE organization_id = $1;`, [orgId]);
      await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [orgId]);
      await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgId]);
    }
    await new Promise((resolve) => server.close(resolve));
    console.log('[CLEANUP] Test server closed.');
  }
}

runProtectedTargetsTests()
  .then(() => {
    console.log('Test run finished.');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Test run failed with error:', err);
    process.exit(1);
  });
