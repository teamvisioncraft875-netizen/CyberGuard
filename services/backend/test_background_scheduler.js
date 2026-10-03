/**
 * CYBERGUARD Phase 2C: Background Scheduler Test Suite
 *
 * Validates:
 * 1. Auto-execution of due response actions when scheduled_at <= NOW()
 * 2. Circuit breaker guardrail (max 10 auto-executions per hour per org)
 * 3. Per-organization isolation (different org executes when first org is capped)
 * 4. Graceful stop (stopScheduler stops execution of due actions)
 * 5. Resume on restart (startScheduler picks up due actions)
 * 6. getSchedulerStatus() reporting accuracy
 */

process.env.NODE_ENV = 'test';

const assert = require('assert');
const bcrypt = require('bcrypt');
const db = require('./src/config/db');
const redis = require('./src/config/redis');
const schedulerService = require('./src/services/schedulerService');

// Support either full 65-second waits or accelerated test interval
const IS_WAIT65 = process.argv.includes('--wait65');
const CRON_PATTERN = IS_WAIT65 ? '* * * * *' : '*/2 * * * * *';
const CYCLE_WAIT_MS = IS_WAIT65 ? 65000 : 3500;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runSchedulerTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 2C BACKGROUND SCHEDULER TEST SUITE');
  console.log(`  Mode: ${IS_WAIT65 ? 'Full 65s Real-Time Cron' : 'Accelerated Test Interval'} (wait: ${CYCLE_WAIT_MS}ms)`);
  console.log('════════════════════════════════════════════════════════════════════════\n');

  if (!redis.isConnected()) {
    console.log('[REDIS] Live Redis not connected, activating mock engine');
    redis.enableMockRedis();
  }

  const timestamp = Date.now();
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdIncidentIds = [];
  const createdPolicyIds = [];
  const createdActionIds = [];

  try {
    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Seed Organizations, Users, Incidents, Policies
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Setup: Seeding Database Entities ---');

    // Org A
    const orgARes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Scheduler Test Org A ${timestamp}`]
    );
    const orgA = orgARes.rows[0];
    createdOrgIds.push(orgA.id);

    // Org B
    const orgBRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Scheduler Test Org B ${timestamp}`]
    );
    const orgB = orgBRes.rows[0];
    createdOrgIds.push(orgB.id);

    const passwordHash = await bcrypt.hash('P@ssword123!', 10);

    const userARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin_a_${timestamp}@cyberguard.internal`, passwordHash, orgA.id]
    );
    const userA = userARes.rows[0];
    createdUserIds.push(userA.id);

    const userBRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin_b_${timestamp}@cyberguard.internal`, passwordHash, orgB.id]
    );
    const userB = userBRes.rows[0];
    createdUserIds.push(userB.id);

    const incARes = await db.query(
      `INSERT INTO public.incidents (user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation)
       VALUES ($1, $2, 'phishing', 'email', 85, 'high', 'open', 'Phishing incident A') RETURNING *;`,
      [userA.id, orgA.id]
    );
    const incidentA = incARes.rows[0];
    createdIncidentIds.push(incidentA.id);

    const incBRes = await db.query(
      `INSERT INTO public.incidents (user_id, organization_id, threat_type, source_type, risk_score, risk_level, status, explanation)
       VALUES ($1, $2, 'exposed_secret', 'check', 95, 'critical', 'open', 'Secret incident B') RETURNING *;`,
      [userB.id, orgB.id]
    );
    const incidentB = incBRes.rows[0];
    createdIncidentIds.push(incidentB.id);

    const polARes = await db.query(
      `INSERT INTO public.response_policies (organization_id, name, enabled, rules)
       VALUES ($1, 'Test Policy A', true, '[{"threat_type": "phishing", "min_risk_score": 80, "action_type": "block_ip", "action_mode": "live"}]'::jsonb) RETURNING *;`,
      [orgA.id]
    );
    const policyA = polARes.rows[0];
    createdPolicyIds.push(policyA.id);

    console.log(`✔ Seeded: OrgA=${orgA.id}, OrgB=${orgB.id}, UserA=${userA.id}, UserB=${userB.id}`);

    // Helper: insert response action
    async function createAction({
      org_id = orgA.id,
      incident_id = incidentA.id,
      policy_id = policyA.id,
      status = 'approved',
      action_mode = 'live',
      action_type = 'block_ip',
      target = { ip_address: '198.51.100.1' },
      scheduled_at = new Date(Date.now() - 10000) // 10s in the past (due)
    } = {}) {
      const res = await db.query(
        `INSERT INTO public.response_actions (
          organization_id, incident_id, policy_id, action_type, action_mode, status, target, scheduled_at, execution_attempts
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0) RETURNING *;`,
        [org_id, incident_id, policy_id, action_type, action_mode, status, JSON.stringify(target), scheduled_at]
      );
      const action = res.rows[0];
      createdActionIds.push(action.id);
      return action;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Step 1: Create due action, start scheduler, confirm status='executed'
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 1: Auto-Execute Due Action ---');
    const action1 = await createAction({
      org_id: orgA.id,
      status: 'approved',
      action_mode: 'live',
      target: { ip_address: '198.51.100.10' },
      scheduled_at: new Date(Date.now() - 10000)
    });
    console.log(`Created due action: id=${action1.id}, status=${action1.status}, scheduled_at=${action1.scheduled_at.toISOString()}`);

    // Helper to poll for status change
    async function waitForActionStatus(actionId, expectedStatus, timeoutSec = 25) {
      for (let i = 0; i < timeoutSec * 2; i++) {
        const qRes = await db.query(`SELECT * FROM public.response_actions WHERE id = $1;`, [actionId]);
        const row = qRes.rows[0];
        if (row && row.status === expectedStatus) {
          return row;
        }
        await sleep(500);
      }
      const finalRes = await db.query(`SELECT * FROM public.response_actions WHERE id = $1;`, [actionId]);
      return finalRes.rows[0] || null;
    }

    // Start scheduler
    schedulerService.startScheduler(CRON_PATTERN);
    console.log(`Scheduler started. Waiting for auto-execution...`);

    const updated1 = await waitForActionStatus(action1.id, 'executed', IS_WAIT65 ? 70 : 20);
    assert.ok(updated1, 'Action 1 record must exist');
    assert.strictEqual(updated1.status, 'executed', `Action 1 should be executed (got ${updated1.status})`);
    assert.ok(updated1.executed_at, 'Action 1 executed_at should be populated');
    console.log(`✔ Step 1 Passed: Action ${action1.id} executed successfully at ${updated1.executed_at.toISOString()}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 2: Create 15 more actions (same org), confirm circuit breaker caps at 10
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 2: Circuit Breaker Cap (15 due actions -> exactly 10 execute) ---');

    // Move action1 executed_at outside the 1-hour window so hourly count starts at 0
    await db.query(
      `UPDATE public.response_actions SET executed_at = NOW() - INTERVAL '2 hours' WHERE id = $1;`,
      [action1.id]
    );

    // Pause scheduler during seeding so all 15 actions are inserted before processing
    await schedulerService.stopScheduler();

    const batch15Ids = [];
    for (let i = 1; i <= 15; i++) {
      const act = await createAction({
        org_id: orgA.id,
        status: 'approved',
        action_mode: 'live',
        target: { ip_address: `198.51.100.${20 + i}` },
        scheduled_at: new Date(Date.now() - 10000 - i * 1000)
      });
      batch15Ids.push(act.id);
    }
    console.log(`Created 15 due actions for Org A.`);

    // Restart scheduler and poll until 10 are executed
    schedulerService.startScheduler(CRON_PATTERN);
    console.log(`Waiting for batch processing and circuit breaker check...`);

    let executedCount = 0;
    let unexecutedCount = 15;
    const maxPolls = IS_WAIT65 ? 80 : 30;

    for (let p = 0; p < maxPolls; p++) {
      const q15Res = await db.query(
        `SELECT id, status FROM public.response_actions WHERE id = ANY($1::uuid[]);`,
        [batch15Ids]
      );
      executedCount = q15Res.rows.filter((r) => r.status === 'executed').length;
      unexecutedCount = q15Res.rows.filter((r) => r.status !== 'executed').length;
      if (executedCount === 10) {
        break;
      }
      await sleep(1000);
    }

    // Allow 2 additional seconds to confirm no further actions execute (circuit breaker holds)
    await sleep(2000);
    const finalQ15 = await db.query(
      `SELECT id, status FROM public.response_actions WHERE id = ANY($1::uuid[]);`,
      [batch15Ids]
    );
    executedCount = finalQ15.rows.filter((r) => r.status === 'executed').length;
    unexecutedCount = finalQ15.rows.filter((r) => r.status !== 'executed').length;

    console.log(`Batch results: ${executedCount} executed, ${unexecutedCount} capped/unexecuted`);
    assert.strictEqual(executedCount, 10, `Circuit breaker must cap at exactly 10 executions (got ${executedCount})`);
    assert.strictEqual(unexecutedCount, 5, `Remaining 5 actions must remain unexecuted (got ${unexecutedCount})`);
    console.log('✔ Step 2 Passed: Circuit breaker capped executions at exactly 10 per hour for Org A');

    // ──────────────────────────────────────────────────────────────────────────
    // Step 3: Create due action in a different org (Org B), confirm it executes
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 3: Per-Org Cap Isolation (Org B executes while Org A is capped) ---');
    const actionOrgB = await createAction({
      org_id: orgB.id,
      incident_id: incidentB.id,
      status: 'approved',
      action_mode: 'live',
      target: { ip_address: '198.51.100.99' },
      scheduled_at: new Date(Date.now() - 10000)
    });

    console.log(`Created due action for Org B: id=${actionOrgB.id}`);
    const updatedB = await waitForActionStatus(actionOrgB.id, 'executed', IS_WAIT65 ? 70 : 20);
    assert.ok(updatedB, 'Org B action must exist');
    assert.strictEqual(updatedB.status, 'executed', `Org B action should execute independently (got ${updatedB.status})`);
    console.log('✔ Step 3 Passed: Org B action executed successfully (cap is per-org, not global)');

    // ──────────────────────────────────────────────────────────────────────────
    // Step 4: Kill scheduler (stopScheduler), create due action, confirm NOT executed
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 4: Graceful Shutdown (stopScheduler) ---');
    await schedulerService.stopScheduler();

    const actionWhileStopped = await createAction({
      org_id: orgB.id,
      incident_id: incidentB.id,
      status: 'approved',
      action_mode: 'live',
      target: { ip_address: '198.51.100.101' },
      scheduled_at: new Date(Date.now() - 10000)
    });
    console.log(`Created due action while scheduler stopped: id=${actionWhileStopped.id}`);

    console.log(`Waiting 4s (scheduler is stopped)...`);
    await sleep(4000);

    const qStoppedRes = await db.query(`SELECT * FROM public.response_actions WHERE id = $1;`, [actionWhileStopped.id]);
    const updatedStopped = qStoppedRes.rows[0];
    assert.strictEqual(
      updatedStopped.status,
      'approved',
      `Action must NOT execute while scheduler is stopped (got ${updatedStopped.status})`
    );
    console.log('✔ Step 4 Passed: Action remained unexecuted while scheduler was stopped');

    // ──────────────────────────────────────────────────────────────────────────
    // Step 5: Restart scheduler, wait a cycle, confirm action now executed
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 5: Scheduler Restart & Resume ---');
    schedulerService.startScheduler(CRON_PATTERN);

    console.log(`Scheduler restarted. Waiting for action to execute...`);
    const updatedResumed = await waitForActionStatus(actionWhileStopped.id, 'executed', IS_WAIT65 ? 70 : 20);
    assert.ok(updatedResumed, 'Resumed action must exist');
    assert.strictEqual(
      updatedResumed.status,
      'executed',
      `Action should execute after restart (got ${updatedResumed.status})`
    );
    console.log('✔ Step 5 Passed: Previously pending action executed immediately after restart');

    // ──────────────────────────────────────────────────────────────────────────
    // Step 6: getSchedulerStatus() validation
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 6: getSchedulerStatus() Verification ---');
    const status = schedulerService.getSchedulerStatus();
    console.log('Scheduler Status:', JSON.stringify(status, null, 2));

    assert.strictEqual(status.running, true, 'status.running must be true');
    assert.ok(status.last_run, 'status.last_run timestamp must be set');
    assert.ok(status.actions_executed_this_hour, 'actions_executed_this_hour must be defined');
    assert.strictEqual(
      status.actions_executed_this_hour[orgA.id],
      10,
      `Org A count this hour should be 10 (got ${status.actions_executed_this_hour[orgA.id]})`
    );
    assert.ok(
      status.actions_executed_this_hour[orgB.id] >= 1,
      `Org B count should be at least 1 (got ${status.actions_executed_this_hour[orgB.id]})`
    );
    console.log('✔ Step 6 Passed: getSchedulerStatus() accurately reflects running state and hourly counts');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL PHASE 2C BACKGROUND SCHEDULER TESTS PASSED');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    // Teardown
    await schedulerService.stopScheduler();

    console.log('--- Teardown: Cleaning Test Records ---');
    if (createdActionIds.length > 0) {
      await db.query(`DELETE FROM public.response_actions WHERE id = ANY($1::uuid[]);`, [createdActionIds]);
    }
    if (createdPolicyIds.length > 0) {
      await db.query(`DELETE FROM public.response_policies WHERE id = ANY($1::uuid[]);`, [createdPolicyIds]);
    }
    if (createdIncidentIds.length > 0) {
      await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
    }
    if (createdUserIds.length > 0) {
      await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
    }
    if (createdOrgIds.length > 0) {
      await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
    }
    console.log('✔ Teardown complete');
  }
}

if (require.main === module) {
  runSchedulerTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ TEST FAILURE:', err);
      process.exit(1);
    });
}

module.exports = { runSchedulerTests };
