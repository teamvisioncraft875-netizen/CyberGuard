process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { app } = require('./src');
const db = require('./src/config/db');
const PolicyEngine = require('./src/services/PolicyEngine');
const ResponsePolicy = require('./src/models/ResponsePolicy');
const ResponseAction = require('./src/models/ResponseAction');
const { persistDetectionIncident } = require('./src/services/incidentService');

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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForActions(orgId, incidentId, expectedCount = 1, timeoutMs = 4000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await ResponseAction.list({ organization_id: orgId, incident_id: incidentId });
    if (res.total >= expectedCount) return res;
    await sleep(150);
  }
  return await ResponseAction.list({ organization_id: orgId, incident_id: incidentId });
}

async function runPolicyEngineTestSuite() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 1B RESPONSE POLICY ENGINE (SHADOW MODE) SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdPolicyIds = [];
  const createdIncidentIds = [];
  const createdActionIds = [];

  const timestamp = Date.now();
  const rawAdminPassword = 'SuperSecretAdminP@ss123!';

  try {
    // 0. Start ephemeral HTTP test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}`);
        resolve();
      });
    });

    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Create Organizations & Admin Users
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Setup: Seed Organizations and Admin Users ---');
    const orgARes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org Alpha Phase1B ${timestamp}`]
    );
    const orgA = orgARes.rows[0];
    createdOrgIds.push(orgA.id);

    const orgBRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org Beta Phase1B ${timestamp}`]
    );
    const orgB = orgBRes.rows[0];
    createdOrgIds.push(orgB.id);

    const passwordHash = await bcrypt.hash(rawAdminPassword, 10);

    const adminARes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin_a_${timestamp}@alpha.test`, passwordHash, orgA.id]
    );
    const adminA = adminARes.rows[0];
    createdUserIds.push(adminA.id);

    const adminBRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin_b_${timestamp}@beta.test`, passwordHash, orgB.id]
    );
    const adminB = adminBRes.rows[0];
    createdUserIds.push(adminB.id);

    const tokenA = createToken(adminA);
    const tokenB = createToken(adminB);

    console.log(`[SETUP] Org A: ${orgA.id}, Admin A: ${adminA.id}`);
    console.log(`[SETUP] Org B: ${orgB.id}, Admin B: ${adminB.id}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: Create Response Policy via POST /api/v1/admin/response-policies
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: Create Policy via Admin Endpoint ---');
    const policyPayload = {
      name: 'High Severity Phishing Shadow Policy',
      enabled: true,
      rules: [
        {
          threat_type: 'phishing',
          min_score: 70,
          action_type: 'notify_admin',
          action_mode: 'shadow',
          requires_approval: false,
          auto_execute_after_mins: 0,
          target_filter: { user_roles: ['employee', 'admin'] }
        }
      ]
    };

    const createPolicyRes = await fetch(`${baseUrl}/admin/response-policies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify(policyPayload)
    });

    assert.strictEqual(createPolicyRes.status, 201, `Expected 201 Created, got ${createPolicyRes.status}`);
    const createPolicyJson = await createPolicyRes.json();
    assert.strictEqual(createPolicyJson.success, true);
    assert.strictEqual(createPolicyJson.policy.name, policyPayload.name);
    assert.strictEqual(createPolicyJson.policy.organization_id, orgA.id);
    createdPolicyIds.push(createPolicyJson.policy.id);
    console.log(`[PASS] Response Policy created with ID: ${createPolicyJson.policy.id}`);

    // Test validation error rejection on malformed rules
    const invalidPolicyRes = await fetch(`${baseUrl}/admin/response-policies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        name: 'Invalid Policy',
        rules: [{ threat_type: 'phishing', min_score: 150, action_type: 'invalid_action' }]
      })
    });
    assert.strictEqual(invalidPolicyRes.status, 400, 'Expected 400 for invalid action_type & min_score');
    console.log('[PASS] Policy validation correctly rejected invalid rules schema');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Trigger Phishing Incident (Score: 85 >= 70) -> Proposed Shadow Action Created
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Phishing Incident (Score 85) Triggers Proposed Shadow Action ---');
    const highRiskIncident = await persistDetectionIncident({
      user: adminA,
      threatType: 'phishing',
      sourceType: 'email',
      mlResult: {
        risk_score: 85,
        risk_level: 'High',
        explanation: 'Suspicious credential harvest attempt identified with high confidence',
        confidence: 95,
        signals: {
          confidence_score: 0.95,
          domain: 'login-secure-fake.net',
          ip_address: '198.51.100.23'
        }
      },
      recommendedActions: ['notify_admin', 'require_mfa']
    });
    createdIncidentIds.push(highRiskIncident.id);

    // Wait for async fire-and-forget policy engine evaluation to persist
    const actionsAfterHighRisk = await waitForActions(orgA.id, highRiskIncident.id, 1);

    assert.strictEqual(actionsAfterHighRisk.total, 1, `Expected 1 action, found ${actionsAfterHighRisk.total}`);
    const highRiskAction = actionsAfterHighRisk.actions[0];
    createdActionIds.push(highRiskAction.id);

    assert.strictEqual(highRiskAction.status, 'proposed', `Expected status proposed, got ${highRiskAction.status}`);
    assert.strictEqual(highRiskAction.action_mode, 'shadow', `Expected action_mode shadow, got ${highRiskAction.action_mode}`);
    assert.strictEqual(highRiskAction.action_type, 'notify_admin', `Expected action_type notify_admin, got ${highRiskAction.action_type}`);
    assert.strictEqual(highRiskAction.policy_id, createPolicyJson.policy.id);
    console.log(`[PASS] Response action created: ID=${highRiskAction.id}, status=${highRiskAction.status}, mode=${highRiskAction.action_mode}, type=${highRiskAction.action_type}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Trigger Incident with Score 45 (< 70 threshold) -> No Action Created
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Below-Threshold Incident (Score 45 < 70) -> No Action ---');
    const lowRiskIncident = await persistDetectionIncident({
      user: adminA,
      threatType: 'phishing',
      sourceType: 'email',
      mlResult: {
        risk_score: 45,
        risk_level: 'Medium',
        explanation: 'Low-confidence heuristic mismatch, below alert threshold',
        confidence: 50,
        signals: { confidence_score: 0.50 }
      },
      recommendedActions: []
    });
    createdIncidentIds.push(lowRiskIncident.id);

    await sleep(250);

    const actionsAfterLowRisk = await ResponseAction.list({
      organization_id: orgA.id,
      incident_id: lowRiskIncident.id
    });

    assert.strictEqual(actionsAfterLowRisk.total, 0, `Expected 0 actions for score 45, found ${actionsAfterLowRisk.total}`);
    console.log('[PASS] Threshold filtering verified: No response actions created for score below 70');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Guardrail Check — Network Anomaly / System Engine incident
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Guardrail Check — System/Network Engine Forces Shadow Mode ---');
    // Create a policy for network/system threat attempting 'live' mode
    const systemPolicyRes = await db.query(
      `INSERT INTO public.response_policies (organization_id, name, enabled, rules)
       VALUES ($1, $2, true, $3) RETURNING *;`,
      [
        orgA.id,
        'System Engine Live Override Attempt Policy',
        JSON.stringify([
          {
            threat_type: 'technical_threat',
            min_score: 50,
            action_type: 'block_ip',
            action_mode: 'live', // Attempting live mode
            requires_approval: false
          }
        ])
      ]
    );
    const systemPolicy = systemPolicyRes.rows[0];
    createdPolicyIds.push(systemPolicy.id);

    const systemIncident = await persistDetectionIncident({
      user: adminA,
      threatType: 'technical_threat',
      sourceType: 'system', // Guardrail A trigger: system engine
      mlResult: {
        risk_score: 90,
        risk_level: 'Critical',
        explanation: 'High packet anomaly detected by system network probe',
        confidence: 80,
        signals: {
          ip_address: '203.0.113.195'
        }
      },
      recommendedActions: ['block_ip']
    });
    createdIncidentIds.push(systemIncident.id);

    // Wait for async fire-and-forget policy engine evaluation to persist over remote network
    const systemActions = await waitForActions(orgA.id, systemIncident.id, 1);

    assert.strictEqual(systemActions.total, 1, `Expected 1 action, found ${systemActions.total}`);
    const systemAction = systemActions.actions[0];
    createdActionIds.push(systemAction.id);

    // Guardrail Assertion: action_mode MUST be 'shadow' regardless of policy's 'live' request
    assert.strictEqual(
      systemAction.action_mode,
      'shadow',
      `Guardrail violation: action_mode should be shadow, but was ${systemAction.action_mode}`
    );
    assert.strictEqual(systemAction.action_type, 'block_ip');
    console.log(`[PASS] Guardrail enforced: System engine action forced to action_mode='shadow'`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: List Actions via GET /api/v1/admin/response-actions & Tenant Scoping
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Admin Endpoint Scoping (Admin A vs Admin B) ---');
    // Admin A retrieves actions: should see Org A's actions (at least 2 created above)
    const listResA = await fetch(`${baseUrl}/admin/response-actions`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert.strictEqual(listResA.status, 200, `Admin A GET failed: ${listResA.status}`);
    const listJsonA = await listResA.json();
    assert.strictEqual(listJsonA.success, true);
    assert.ok(listJsonA.total >= 2, `Admin A should see >= 2 actions, found ${listJsonA.total}`);
    const allOrgA = listJsonA.actions.every((a) => a.organization_id === orgA.id);
    assert.strictEqual(allOrgA, true, "Admin A saw an action not belonging to Org A!");
    console.log(`[PASS] Admin A retrieved ${listJsonA.total} actions, all strictly scoped to Org A (${orgA.id})`);

    // Admin B retrieves actions: should see 0 actions (no actions created for Org B)
    const listResB = await fetch(`${baseUrl}/admin/response-actions`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert.strictEqual(listResB.status, 200, `Admin B GET failed: ${listResB.status}`);
    const listJsonB = await listResB.json();
    assert.strictEqual(listJsonB.success, true);
    assert.strictEqual(listJsonB.total, 0, `Tenant leakage: Admin B saw ${listJsonB.total} actions from Org A!`);
    console.log(`[PASS] Admin B retrieved 0 actions; strictly zero cross-tenant leakage`);

    // Non-admin rejection check
    const employeeRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'employee', $3) RETURNING *;`,
      [`emp_${timestamp}@alpha.test`, passwordHash, orgA.id]
    );
    const empUser = employeeRes.rows[0];
    createdUserIds.push(empUser.id);
    const empToken = createToken(empUser);

    const empForbiddenRes = await fetch(`${baseUrl}/admin/response-actions`, {
      headers: { Authorization: `Bearer ${empToken}` }
    });
    assert.strictEqual(empForbiddenRes.status, 403, 'Employee should receive 403 Forbidden');
    console.log('[PASS] Non-admin (employee) received 403 Forbidden on admin endpoint');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 5 PHASE 1B RESPONSE POLICY ENGINE TEST SUITES PASSED! ✓');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    // Teardown
    console.log('--- Teardown: Cleaning up test records ---');
    try {
      if (createdActionIds.length > 0) {
        await db.query(`DELETE FROM public.response_actions WHERE id = ANY($1::uuid[]);`, [createdActionIds]);
      }
      if (createdPolicyIds.length > 0) {
        await db.query(`DELETE FROM public.response_policies WHERE id = ANY($1::uuid[]);`, [createdPolicyIds]);
      }
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
      }
      console.log('[TEARDOWN] Cleanup completed.');
    } catch (cleanupErr) {
      console.error('[TEARDOWN ERROR]', cleanupErr);
    }

    if (server) {
      server.close();
    }
    // Give DB pool time to finish
    await sleep(200);
  }
}

if (require.main === module) {
  runPolicyEngineTestSuite()
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      console.error('\n❌ TEST SUITE FAILED:\n', err);
      process.exit(1);
    });
}

module.exports = runPolicyEngineTestSuite;
