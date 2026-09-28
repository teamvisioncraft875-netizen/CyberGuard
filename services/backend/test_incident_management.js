process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');
const { query, pool } = require('./src/config/db');

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      organization_id: user.organization_id
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runContinuousIncidentManagementTest() {
  let server;
  const testOrgIds = [];
  const testUserIds = [];
  const testIncidentIds = [];
  const results = [];

  function recordResult(stepNum, stepName, passed, details = '') {
    results.push({ stepNum, stepName, passed, details });
    const statusTag = passed ? '✔ PASS' : '✖ FAIL';
    console.log(`[${statusTag}] Step ${stepNum}: ${stepName}`);
    if (details) {
      console.log(`       Details: ${details}`);
    }
  }

  try {
    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  CYBERGUARD — CONTINUOUS INCIDENT & ACTION MANAGEMENT PIPELINE TEST');
    console.log('════════════════════════════════════════════════════════════════════════');

    // 1. Start HTTP Server on ephemeral port
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[INIT] Test server running on ${baseUrl}`);

    // 2. Setup two isolated organizations and users
    const orgARes = await query(`
      INSERT INTO organizations (name, created_at)
      VALUES ('Org Alpha - Incident Mgmt', NOW())
      RETURNING id, name;
    `);
    const orgA = orgARes.rows[0];
    testOrgIds.push(orgA.id);

    const orgBRes = await query(`
      INSERT INTO organizations (name, created_at)
      VALUES ('Org Beta - Tenant Adversary', NOW())
      RETURNING id, name;
    `);
    const orgB = orgBRes.rows[0];
    testOrgIds.push(orgB.id);

    const userARes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('analyst_a_${Date.now()}@alpha.local', 'hash_test', 'employee', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgA.id]);
    const userA = userARes.rows[0];
    testUserIds.push(userA.id);
    const tokenA = createToken(userA);

    const userBRes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('adversary_b_${Date.now()}@beta.local', 'hash_test', 'employee', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgB.id]);
    const userB = userBRes.rows[0];
    testUserIds.push(userB.id);
    const tokenB = createToken(userB);

    console.log(`[SETUP] Created User A (${userA.id}, Org A) and User B (${userB.id}, Org B)\n`);

    // =========================================================================
    // STEP 1: Ingest Threat via POST /api/v1/check/message
    // =========================================================================
    console.log('--- Step 1: Create incident via POST /api/v1/check/message ---');
    const threatPayload = {
      text: "URGENT: Your Chase account is locked. Verify identity at http://chase-security-update.xyz within 1 hour.",
      source_type: "email"
    };

    const resStep1 = await fetch(`${baseUrl}/check/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify(threatPayload)
    });

    const bodyStep1 = await resStep1.json();
    const createdIncidentId = bodyStep1.id;
    if (createdIncidentId) testIncidentIds.push(createdIncidentId);

    if (resStep1.status === 200 && createdIncidentId) {
      recordResult(1, 'Ingest Threat via /api/v1/check/message', true, `Incident ID: ${createdIncidentId}, Risk: ${bodyStep1.risk_level}`);
    } else {
      recordResult(1, 'Ingest Threat via /api/v1/check/message', false, `Status ${resStep1.status}: ${JSON.stringify(bodyStep1)}`);
      throw new Error('Step 1 Failed');
    }

    // =========================================================================
    // STEP 2: Fetch via GET /api/v1/incidents & Confirm Pagination Metadata
    // =========================================================================
    console.log('\n--- Step 2: Fetch incidents list & confirm pagination metadata ---');
    const resStep2 = await fetch(`${baseUrl}/incidents?limit=25&offset=0`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const bodyStep2 = await resStep2.json();

    const items = bodyStep2.data || bodyStep2.incidents || [];
    const foundIncident = items.find(i => i.id === createdIncidentId);

    const step2Pass = resStep2.status === 200 &&
      typeof bodyStep2.total === 'number' &&
      bodyStep2.total >= 1 &&
      bodyStep2.limit === 25 &&
      bodyStep2.offset === 0 &&
      foundIncident !== undefined &&
      Array.isArray(foundIncident.recommended_actions) &&
      Array.isArray(foundIncident.mitre_mappings);

    recordResult(
      2,
      'List incidents with pagination metadata and contract shape',
      step2Pass,
      `Total: ${bodyStep2.total}, Limit: ${bodyStep2.limit}, Offset: ${bodyStep2.offset}, Found in list: ${Boolean(foundIncident)}`
    );
    if (!step2Pass) throw new Error(`Step 2 Failed: ${JSON.stringify(bodyStep2)}`);

    // =========================================================================
    // STEP 3: Fetch via GET /api/v1/incidents/:id & Confirm Signals + MITRE
    // =========================================================================
    console.log('\n--- Step 3: Fetch incident detail & verify detection_signals and mitre_mappings ---');
    const resStep3 = await fetch(`${baseUrl}/incidents/${createdIncidentId}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const incidentDetail = await resStep3.json();

    const step3Pass = resStep3.status === 200 &&
      incidentDetail.id === createdIncidentId &&
      Array.isArray(incidentDetail.detection_signals) &&
      incidentDetail.detection_signals.length > 0 &&
      Array.isArray(incidentDetail.mitre_mappings) &&
      incidentDetail.mitre_mappings.length > 0 &&
      Array.isArray(incidentDetail.recommended_actions) &&
      incidentDetail.recommended_actions.length > 0;

    recordResult(
      3,
      'Retrieve incident details with detection signals, MITRE mappings, and actions',
      step3Pass,
      `Signals: ${incidentDetail.detection_signals?.length}, MITRE: ${incidentDetail.mitre_mappings?.length}, Actions: ${incidentDetail.recommended_actions?.length}`
    );
    if (!step3Pass) throw new Error(`Step 3 Failed: ${JSON.stringify(incidentDetail)}`);

    // Pick target recommended action
    const targetAction = incidentDetail.recommended_actions[0];
    const targetActionId = targetAction.id;
    console.log(`[ACTION SELECTED] Action ID: ${targetActionId}, Current Status: ${targetAction.action_status}, Text: "${targetAction.action_type}"`);

    // =========================================================================
    // STEP 4: PATCH action via /api/v1/actions/:id to action_status: "taken"
    // =========================================================================
    console.log('\n--- Step 4: PATCH action status to "taken" via /api/v1/actions/:id ---');
    const resStep4 = await fetch(`${baseUrl}/actions/${targetActionId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({ action_status: 'taken' })
    });
    const bodyStep4 = await resStep4.json();

    const step4Pass = resStep4.status === 200 &&
      bodyStep4.id === targetActionId &&
      bodyStep4.action_status === 'taken';

    recordResult(
      4,
      'PATCH recommended action status to "taken"',
      step4Pass,
      `HTTP ${resStep4.status}, Updated status: ${bodyStep4.action_status}`
    );
    if (!step4Pass) throw new Error(`Step 4 Failed: ${JSON.stringify(bodyStep4)}`);

    // =========================================================================
    // STEP 5: Direct Database Query to Confirm Persistence
    // =========================================================================
    console.log('\n--- Step 5: Direct database query to verify persistence ---');
    const dbCheckRes = await query(
      `SELECT id, incident_id, action_type, action_status, created_at FROM recommended_actions WHERE id = $1`,
      [targetActionId]
    );
    const dbRow = dbCheckRes.rows[0];

    const step5Pass = dbRow !== undefined && dbRow.action_status === 'taken';
    recordResult(
      5,
      'Verify action_status persistence directly in PostgreSQL',
      step5Pass,
      `DB row action_status: "${dbRow?.action_status}", action_type: "${dbRow?.action_type}"`
    );
    if (!step5Pass) throw new Error(`Step 5 Failed: DB row status is ${dbRow?.action_status}`);

    // =========================================================================
    // STEP 6: Cross-Tenant Rejection Test via Different User (Org B) -> 404
    // =========================================================================
    console.log('\n--- Step 6: Attempt cross-tenant PATCH from User B (different org) -> expect 404 ---');
    const resStep6 = await fetch(`${baseUrl}/actions/${targetActionId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenB}`
      },
      body: JSON.stringify({ action_status: 'dismissed' })
    });
    const bodyStep6 = await resStep6.json();

    // Confirm DB row was NOT modified by unauthorized caller
    const dbVerifyUnchanged = await query(
      `SELECT action_status FROM recommended_actions WHERE id = $1`,
      [targetActionId]
    );
    const currentDbStatus = dbVerifyUnchanged.rows[0]?.action_status;

    const step6Pass = resStep6.status === 404 &&
      bodyStep6.error === 'NOT_FOUND' &&
      currentDbStatus === 'taken';

    recordResult(
      6,
      'Cross-tenant action PATCH rejected with 404 (state unchanged)',
      step6Pass,
      `Status code: ${resStep6.status} (expected 404), Error: "${bodyStep6.error}", DB state intact: "${currentDbStatus}"`
    );
    if (!step6Pass) throw new Error(`Step 6 Failed: status was ${resStep6.status}`);

    // =========================================================================
    // SUMMARY
    // =========================================================================
    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  CONTINUOUS PIPELINE TEST EXECUTION SUMMARY');
    console.log('════════════════════════════════════════════════════════════════════════');
    let allPassed = true;
    for (const r of results) {
      const tag = r.passed ? '[PASS]' : '[FAIL]';
      console.log(`  ${tag.padEnd(8)} Step ${r.stepNum}: ${r.stepName}`);
      if (!r.passed) allPassed = false;
    }
    console.log('────────────────────────────────────────────────────────────────────────');
    if (allPassed) {
      console.log('  🌟 RESULT: ALL 6 STEPS PASSED 100% IN STRICT CONTINUOUS SEQUENCE!');
    } else {
      console.log('  ❌ RESULT: SOME STEPS FAILED');
    }
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } finally {
    // Teardown
    console.log('[CLEANUP] Cleaning up test records...');
    if (testIncidentIds.length > 0) {
      await query(`DELETE FROM detection_signals WHERE incident_id = ANY($1::uuid[])`, [testIncidentIds]).catch(() => {});
      await query(`DELETE FROM recommended_actions WHERE incident_id = ANY($1::uuid[])`, [testIncidentIds]).catch(() => {});
      await query(`DELETE FROM mitre_mappings WHERE incident_id = ANY($1::uuid[])`, [testIncidentIds]).catch(() => {});
      await query(`DELETE FROM incident_evidence WHERE incident_id = ANY($1::uuid[])`, [testIncidentIds]).catch(() => {});
      await query(`DELETE FROM incidents WHERE id = ANY($1::uuid[])`, [testIncidentIds]).catch(() => {});
    }
    if (testUserIds.length > 0) {
      await query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [testUserIds]).catch(() => {});
    }
    if (testOrgIds.length > 0) {
      await query(`DELETE FROM organizations WHERE id = ANY($1::uuid[])`, [testOrgIds]).catch(() => {});
    }
    if (server) {
      server.close();
    }
    await pool.end();
    console.log('[CLEANUP] Test resources released.');
  }
}

runContinuousIncidentManagementTest().catch((err) => {
  console.error('[TEST FATAL ERROR]', err.message);
  process.exit(1);
});
