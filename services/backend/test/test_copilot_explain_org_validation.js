process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src/index');
const db = require('../src/config/db');
const { createOrganizationFixture, createUserFixture } = require('./fixtures');

function createToken(user, orgOverride) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      organization_id: orgOverride !== undefined ? orgOverride : (user.organization_id || null)
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

let passed = 0;
let failed = 0;

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  [✅] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [❌] ${name}: ${err.message}`);
    failed++;
  }
}

async function runTargetedExplainOrgSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Targeted Test: Copilot Explain Organization Validation');
  console.log('========================================================================\n');

  let server;
  let baseUrl;

  try {
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    // Create user and org
    const org = await createOrganizationFixture({ name: 'Explain Validation Test Org' });
    const userWithOrg = await createUserFixture({ organization_id: org.id, role: 'analyst' });

    const validToken = createToken(userWithOrg, org.id);
    const missingOrgToken = createToken(userWithOrg, null); // Token with null organization_id

    // -------------------------------------------------------------------------
    // TEST A: Valid organization_id succeeds with 200
    // -------------------------------------------------------------------------
    await testAsync('A. Valid organization_id succeeds with HTTP 200 and explanation payload', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/explain`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${validToken}`
        },
        body: JSON.stringify({
          action: 'isolate_endpoint',
          reason: 'Active ransomware communication detected',
          evidence: 'C2 beaconing on port 4444'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.explanation);
      assert.strictEqual(data.explanation.action, 'isolate_endpoint');
      assert.strictEqual(data.explanation.risk_level, 'high');
      assert.strictEqual(data.explanation.requires_approval, true);
    });

    // -------------------------------------------------------------------------
    // TEST B: Missing organization_id returns HTTP 403 Forbidden
    // -------------------------------------------------------------------------
    await testAsync('B. Missing organization_id returns HTTP 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/explain`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${missingOrgToken}`
        },
        body: JSON.stringify({
          action: 'isolate_endpoint',
          reason: 'Active ransomware communication detected'
        })
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
      assert.strictEqual(data.message, 'Valid organization_id required');
    });

  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
    if (db.pool) {
      await db.pool.end();
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exitCode = 1;
  }
}

runTargetedExplainOrgSuite().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
