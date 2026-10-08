process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src/index');
const db = require('../src/config/db');
const { createOrganizationFixture, createUserFixture } = require('./fixtures');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarExecution = require('../src/models/SoarExecution');
const SoarApproval = require('../src/models/SoarApproval');
const CopilotSession = require('../src/models/CopilotSession');

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

async function runTargetedApprovalReplaySuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Targeted Test: Single-Use Copilot Approval Replay Defenses');
  console.log('========================================================================\n');

  let server;
  let baseUrl;

  try {
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    // 1. Fixtures Setup
    const orgA = await createOrganizationFixture({ name: 'Replay Test Tenant Alpha' });
    const orgB = await createOrganizationFixture({ name: 'Replay Test Tenant Beta' });

    const adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    const analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    const analystB = await createUserFixture({ organization_id: orgB.id, role: 'analyst' });

    const tokenAnalystA = createToken(analystA);
    const tokenAnalystB = createToken(analystB);

    const playbookA = await SoarPlaybook.create({
      organization_id: orgA.id,
      name: 'Host Isolation Procedure',
      severity: 'critical'
    });

    const executionA = await SoarExecution.create({
      organization_id: orgA.id,
      playbook_id: playbookA.id,
      status: 'waiting_approval'
    });

    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: analystA.id,
      title: 'Host Isolation Triage Session'
    });

    // Helper to create an approved approval for Tenant A
    async function createApprovedRecord() {
      const appRecord = await SoarApproval.create({
        execution_id: executionA.id,
        requested_by: analystA.id,
        reason: 'Authorized endpoint containment',
        level: 'L1'
      });
      await SoarApproval.decide(appRecord.id, {
        status: 'approved',
        decided_by: adminA.id,
        reason: 'Authorized by administrator'
      });
      return appRecord.id;
    }

    // -------------------------------------------------------------------------
    // TEST A: Approved high-risk action executes once
    // -------------------------------------------------------------------------
    const approvalId1 = await createApprovedRecord();

    await testAsync('A. Approved high-risk action executes once with valid approval_id', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'isolate_endpoint',
          payload: { host: 'WORKSTATION-REPLAY-1', approval_id: approvalId1 },
          reason: 'Authorized containment'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'executed');

      // Verify DB shows consumed = true
      const checkApproval = await SoarApproval.findById(approvalId1, orgA.id);
      assert.strictEqual(checkApproval.consumed, true);
      assert.ok(checkApproval.consumed_at !== null);
    });

    // -------------------------------------------------------------------------
    // TEST B & C: Same approval_id used a second time receives 403 & does not execute
    // -------------------------------------------------------------------------
    await testAsync('B. Same approval_id used a second time receives HTTP 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'isolate_endpoint',
          payload: { host: 'WORKSTATION-REPLAY-1', approval_id: approvalId1 },
          reason: 'Replay attempt with consumed approval'
        })
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
      assert.ok(data.message.includes('already been consumed'));
    });

    await testAsync('C. Second attempt does not execute underlying action or create execution', async () => {
      // Query session actions: only 1 executed action should exist for this approval
      const actionsRes = await db.query(
        `SELECT COUNT(*)::int AS count FROM public.copilot_session_actions
         WHERE session_id = $1 AND approval_id = $2 AND status = 'executed';`,
        [sessionA.id, approvalId1]
      );
      assert.strictEqual(actionsRes.rows[0].count, 1);
    });

    // -------------------------------------------------------------------------
    // TEST D: Tenant B cannot consume Tenant A approval
    // -------------------------------------------------------------------------
    const approvalIdTenantA = await createApprovedRecord();

    await testAsync('D. Tenant B cannot consume Tenant A approval (HTTP 403/404)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystB}`
        },
        body: JSON.stringify({
          action_type: 'isolate_endpoint',
          payload: { host: 'TARGET-HOST-B', approval_id: approvalIdTenantA },
          reason: 'Cross-tenant replay exploit attempt'
        })
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');

      // Ensure Tenant A's approval is still unconsumed!
      const checkA = await SoarApproval.findById(approvalIdTenantA, orgA.id);
      assert.strictEqual(checkA.consumed, false);
      assert.strictEqual(checkA.consumed_at, null);
    });

    // -------------------------------------------------------------------------
    // TEST E: Race Condition Safety: Two concurrent attempts with same approval
    // -------------------------------------------------------------------------
    const approvalIdRace = await createApprovedRecord();

    await testAsync('E. Concurrent requests race safety: exactly one consumes, exactly one rejected with 403', async () => {
      const [res1, res2] = await Promise.all([
        fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${tokenAnalystA}`
          },
          body: JSON.stringify({
            session_id: sessionA.id,
            action_type: 'isolate_endpoint',
            payload: { host: 'CONCURRENT-HOST-1', approval_id: approvalIdRace },
            reason: 'Concurrent request 1'
          })
        }),
        fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${tokenAnalystA}`
          },
          body: JSON.stringify({
            session_id: sessionA.id,
            action_type: 'isolate_endpoint',
            payload: { host: 'CONCURRENT-HOST-2', approval_id: approvalIdRace },
            reason: 'Concurrent request 2'
          })
        })
      ]);

      const statuses = [res1.status, res2.status].sort();
      // Exactly one must be 200, and exactly one must be 403
      assert.deepStrictEqual(statuses, [200, 403]);

      // Approval record in DB must be consumed
      const checkRace = await SoarApproval.findById(approvalIdRace, orgA.id);
      assert.strictEqual(checkRace.consumed, true);
      assert.ok(checkRace.consumed_at !== null);
    });

  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTargetedApprovalReplaySuite().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
