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

async function runGuardianHandshakeTest() {
  let server;
  const testUserIds = [];
  const testIncidentIds = [];
  const testLinkIds = [];
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
    console.log('  CYBERGUARD — GUARDIAN MODE TWO-STEP HANDSHAKE VERIFICATION TEST');
    console.log('════════════════════════════════════════════════════════════════════════\n');

    // 1. Start ephemeral HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[INIT] Test server running on ${baseUrl}`);

    // 2. Create test users: User A (Guardian), User B (Dependent), User C (Declining Dependent)
    const timestamp = Date.now();
    const userARes = await query(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES ($1, 'hash_pass_123', 'individual', NOW())
      RETURNING id, email, role;
    `, [`guardian_a_${timestamp}@example.com`]);
    const userA = userARes.rows[0];
    testUserIds.push(userA.id);

    const userBRes = await query(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES ($1, 'hash_pass_123', 'individual', NOW())
      RETURNING id, email, role;
    `, [`dependent_b_${timestamp}@example.com`]);
    const userB = userBRes.rows[0];
    testUserIds.push(userB.id);

    const userCRes = await query(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES ($1, 'hash_pass_123', 'individual', NOW())
      RETURNING id, email, role;
    `, [`dependent_c_${timestamp}@example.com`]);
    const userC = userCRes.rows[0];
    testUserIds.push(userC.id);

    // 3. Create high-risk incidents for User B and User C
    const incBRes = await query(`
      INSERT INTO incidents (user_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, 'phishing', 'sms', 'high', 82.5, 'Critical SMS phishing attack targeting bank credentials', 'investigating', NOW())
      RETURNING id, user_id, threat_type, risk_level;
    `, [userB.id]);
    const incB = incBRes.rows[0];
    testIncidentIds.push(incB.id);

    const incCRes = await query(`
      INSERT INTO incidents (user_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, 'deepfake', 'audio', 'critical', 94.0, 'Synthetic voice clone attempting wire transfer', 'investigating', NOW())
      RETURNING id, user_id, threat_type, risk_level;
    `, [userC.id]);
    const incC = incCRes.rows[0];
    testIncidentIds.push(incC.id);

    const tokenA = createToken(userA);
    const tokenB = createToken(userB);
    const tokenC = createToken(userC);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 1: User A links User B as a dependent -> status: 'pending'
    // ─────────────────────────────────────────────────────────────────────────
    const linkRes = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        guardian_user_id: userA.id,
        dependent_user_id: userB.id
      })
    });
    const linkData = await linkRes.json();
    testLinkIds.push(linkData.link_id);

    const step1Pass = linkRes.status === 201 && linkData.status === 'pending' && linkData.link_id;
    recordResult(
      1,
      'User A links User B as a dependent (creates link with status: pending)',
      step1Pass,
      `HTTP ${linkRes.status}, link_id=${linkData.link_id}, status='${linkData.status}'`
    );
    if (!step1Pass) throw new Error(`Step 1 failed: ${JSON.stringify(linkData)}`);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 2: Confirm GET /guardian/alerts for User A shows nothing yet
    // ─────────────────────────────────────────────────────────────────────────
    const alertsPendingRes = await fetch(`${baseUrl}/guardian/alerts`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const alertsPendingData = await alertsPendingRes.json();

    const step2Pass = alertsPendingRes.status === 200 && Array.isArray(alertsPendingData) && alertsPendingData.length === 0;
    recordResult(
      2,
      'Confirm GET /guardian/alerts for User A shows 0 alerts while link is pending',
      step2Pass,
      `HTTP ${alertsPendingRes.status}, alerts returned=${alertsPendingData.length}`
    );
    if (!step2Pass) throw new Error(`Step 2 failed: expected 0 alerts, got ${alertsPendingData.length}`);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 3: Confirm User A (guardian) cannot call the accept endpoint themselves
    // ─────────────────────────────────────────────────────────────────────────
    const selfAcceptRes = await fetch(`${baseUrl}/guardian/link/${linkData.link_id}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const selfAcceptData = await selfAcceptRes.json();

    // Must be rejected with 404 (or 403) to prevent guardian self-approving
    const step3Pass = selfAcceptRes.status === 404 || selfAcceptRes.status === 403;
    recordResult(
      3,
      'Confirm User A (guardian) cannot self-approve the link request (rejected with 404/403)',
      step3Pass,
      `HTTP ${selfAcceptRes.status}, error='${selfAcceptData.error}'`
    );
    if (!step3Pass) throw new Error(`Step 3 failed: guardian self-approval was not rejected, got HTTP ${selfAcceptRes.status}`);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 4: User B (the dependent) accepts the pending guardian link
    // ─────────────────────────────────────────────────────────────────────────
    const acceptRes = await fetch(`${baseUrl}/guardian/link/${linkData.link_id}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    const acceptData = await acceptRes.json();

    const step4Pass = acceptRes.status === 200 && acceptData.status === 'active' && acceptData.link_id === linkData.link_id;
    recordResult(
      4,
      'User B (designated dependent) accepts the pending link -> status becomes active',
      step4Pass,
      `HTTP ${acceptRes.status}, status='${acceptData.status}'`
    );
    if (!step4Pass) throw new Error(`Step 4 failed: ${JSON.stringify(acceptData)}`);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 5: Confirm GET /guardian/alerts for User A now returns User B's alert
    // ─────────────────────────────────────────────────────────────────────────
    const alertsActiveRes = await fetch(`${baseUrl}/guardian/alerts`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const alertsActiveData = await alertsActiveRes.json();

    const foundIncident = Array.isArray(alertsActiveData) && alertsActiveData.find(a => a.alert_id === incB.id);
    const step5Pass = alertsActiveRes.status === 200 && alertsActiveData.length >= 1 && !!foundIncident;
    recordResult(
      5,
      'Confirm GET /guardian/alerts for User A now returns User B incident alerts',
      step5Pass,
      `HTTP ${alertsActiveRes.status}, count=${alertsActiveData.length}, matching alert_id=${foundIncident ? foundIncident.alert_id : 'none'}`
    );
    if (!step5Pass) throw new Error(`Step 5 failed: alerts did not contain expected incident ${incB.id}`);

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 6: Edge Cases: Re-accept rejection (400) & Decline flow (status: revoked)
    // ─────────────────────────────────────────────────────────────────────────
    // 6a. Attempt to re-accept an already active link -> 400 Bad Request
    const reAcceptRes = await fetch(`${baseUrl}/guardian/link/${linkData.link_id}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    const reAcceptData = await reAcceptRes.json();
    const step6aPass = reAcceptRes.status === 400 && reAcceptData.error === 'INVALID_STATUS';

    // 6b. Link User A -> User C, then User C declines
    const linkCRes = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        guardian_user_id: userA.id,
        dependent_user_id: userC.id
      })
    });
    const linkCData = await linkCRes.json();
    testLinkIds.push(linkCData.link_id);

    const declineRes = await fetch(`${baseUrl}/guardian/link/${linkCData.link_id}/decline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenC}` }
    });
    const declineData = await declineRes.json();
    const step6bPass = declineRes.status === 200 && declineData.status === 'revoked';

    const step6Pass = step6aPass && step6bPass;
    recordResult(
      6,
      'Validate edge cases: Re-accept rejected (400) and Dependent decline supported (200, status: revoked)',
      step6Pass,
      `Re-accept: HTTP ${reAcceptRes.status} (${reAcceptData.error}), Decline: HTTP ${declineRes.status} (${declineData.status})`
    );
    if (!step6Pass) throw new Error(`Step 6 failed`);

  } catch (err) {
    console.error('\n[FATAL TEST FAILURE]:', err.message);
    process.exitCode = 1;
  } finally {
    // Teardown
    console.log('\n[TEARDOWN] Cleaning up test fixtures...');
    try {
      if (testLinkIds.length > 0) {
        await query(`DELETE FROM guardian_links WHERE id = ANY($1::uuid[])`, [testLinkIds]);
      }
      if (testIncidentIds.length > 0) {
        await query(`DELETE FROM incidents WHERE id = ANY($1::uuid[])`, [testIncidentIds]);
      }
      if (testUserIds.length > 0) {
        await query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [testUserIds]);
      }
      console.log('✔ Cleanup completed successfully.');
    } catch (cleanupErr) {
      console.error('Teardown error:', cleanupErr.message);
    }

    if (server) {
      await new Promise(resolve => server.close(resolve));
    }

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('                          FINAL TEST SUMMARY');
    console.log('════════════════════════════════════════════════════════════════════════');
    const allPassed = results.length > 0 && results.every(r => r.passed);
    results.forEach(r => {
      console.log(`[${r.passed ? 'PASS' : 'FAIL'}] Step ${r.stepNum}: ${r.stepName}`);
    });
    console.log(`\nTOTAL: ${results.filter(r => r.passed).length}/${results.length} steps passed.`);
    console.log(allPassed ? 'RESULT: SUCCESS (All steps verified)\n' : 'RESULT: FAILURE\n');

    await pool.end();
  }
}

runGuardianHandshakeTest();
