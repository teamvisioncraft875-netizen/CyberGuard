process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src/index');
const db = require('../src/config/db');
const { createOrganizationFixture, createUserFixture } = require('./fixtures');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotMessage = require('../src/models/CopilotMessage');
const naturalLanguageExecutionService = require('../src/services/copilot/naturalLanguageExecutionService');

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

async function runTargetedMessageIsolationSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Targeted Test: CopilotMessage Tenant Boundary Isolation');
  console.log('========================================================================\n');

  let server;
  let baseUrl;

  try {
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    // 1. Setup Tenant Alpha and Tenant Beta
    const orgA = await createOrganizationFixture({ name: 'Message Isolation Org Alpha' });
    const orgB = await createOrganizationFixture({ name: 'Message Isolation Org Beta' });

    const userA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    const userB = await createUserFixture({ organization_id: orgB.id, role: 'analyst' });

    const tokenA = createToken(userA);
    const tokenB = createToken(userB);

    // 2. Create session and secret messages belonging to Tenant A
    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: userA.id,
      title: 'Confidential Incident Investigation'
    });

    const msg1 = await CopilotMessage.create({
      session_id: sessionA.id,
      role: 'user',
      content: 'Classified incident inquiry: Breach in domain DC-01'
    });

    const msg2 = await CopilotMessage.create({
      session_id: sessionA.id,
      role: 'assistant',
      content: 'Isolating host DC-01 and resetting domain credentials.'
    });

    // -------------------------------------------------------------------------
    // TEST 1: Model layer findBySessionId enforces tenant boundary
    // -------------------------------------------------------------------------
    await testAsync('1. CopilotMessage.findBySessionId allows Org A but strictly blocks Org B', async () => {
      const allowedMessages = await CopilotMessage.findBySessionId(sessionA.id, 50, orgA.id);
      assert.strictEqual(allowedMessages.length, 2);
      assert.strictEqual(allowedMessages[0].id, msg1.id);

      const crossTenantMessages = await CopilotMessage.findBySessionId(sessionA.id, 50, orgB.id);
      assert.strictEqual(crossTenantMessages.length, 0, 'Tenant B must receive 0 messages for Tenant A session');
    });

    // -------------------------------------------------------------------------
    // TEST 2: Model layer findRecent enforces tenant boundary
    // -------------------------------------------------------------------------
    await testAsync('2. CopilotMessage.findRecent allows Org A but strictly blocks Org B', async () => {
      const allowedRecent = await CopilotMessage.findRecent(sessionA.id, 10, orgA.id);
      assert.strictEqual(allowedRecent.length, 2);

      const crossTenantRecent = await CopilotMessage.findRecent(sessionA.id, 10, orgB.id);
      assert.strictEqual(crossTenantRecent.length, 0, 'Tenant B must receive 0 recent messages for Tenant A session');
    });

    // -------------------------------------------------------------------------
    // TEST 3: Service layer naturalLanguageExecutionService.getSessionTimeline enforces tenant boundary
    // -------------------------------------------------------------------------
    await testAsync('3. Service timeline retrieval blocks Tenant B from accessing Tenant A timeline', async () => {
      let threw = false;
      try {
        await naturalLanguageExecutionService.getSessionTimeline({
          session_id: sessionA.id,
          organization_id: orgB.id
        });
      } catch (err) {
        threw = true;
        assert.ok(err.statusCode === 404 || err.message.includes('not found in organization'));
      }
      assert.strictEqual(threw, true, 'getSessionTimeline must reject cross-tenant access');
    });

    // -------------------------------------------------------------------------
    // TEST 4: API Endpoint GET /api/v1/copilot/sessions/:id blocks Tenant B
    // -------------------------------------------------------------------------
    await testAsync('4. API GET /sessions/:id returns 404 and does not leak Tenant A messages to Tenant B', async () => {
      const resB = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}`, {
        headers: { Authorization: `Bearer ${tokenB}` }
      });
      assert.strictEqual(resB.status, 404);
      const dataB = await resB.json();
      assert.strictEqual(dataB.error, 'NOT_FOUND');
      assert.strictEqual(dataB.data, undefined);

      // Verify Tenant A still has legitimate access
      const resA = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });
      assert.strictEqual(resA.status, 200);
      const dataA = await resA.json();
      assert.strictEqual(dataA.data.messages.length, 2);
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

runTargetedMessageIsolationSuite().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
