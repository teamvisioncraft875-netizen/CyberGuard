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

async function runTenantIsolationVerification() {
  let server;
  const testOrgIds = [];
  const testUserIds = [];
  const testIncidentIds = [];
  const testLinkIds = [];

  try {
    // 1. Start HTTP Server on ephemeral port
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[Test Suite] Running against test server on port ${port}`);

    // 2. Setup isolated test organizations
    const orgARes = await query(`
      INSERT INTO organizations (name, created_at)
      VALUES ('Test Org Alpha - Tenant A', NOW())
      RETURNING id, name;
    `);
    const orgA = orgARes.rows[0];
    testOrgIds.push(orgA.id);

    const orgBRes = await query(`
      INSERT INTO organizations (name, created_at)
      VALUES ('Test Org Beta - Tenant B', NOW())
      RETURNING id, name;
    `);
    const orgB = orgBRes.rows[0];
    testOrgIds.push(orgB.id);

    console.log(`[Setup] Org A: ${orgA.id}, Org B: ${orgB.id}`);

    // 3. Setup test users for Org A and Org B
    // Admin A & Employee A
    const adminARes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('admin_a_${Date.now()}@alpha.local', 'hash_test', 'admin', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgA.id]);
    const adminA = adminARes.rows[0];
    testUserIds.push(adminA.id);

    const employeeARes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('emp_a_${Date.now()}@alpha.local', 'hash_test', 'employee', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgA.id]);
    const employeeA = employeeARes.rows[0];
    testUserIds.push(employeeA.id);

    // Admin B & Employee B
    const adminBRes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('admin_b_${Date.now()}@beta.local', 'hash_test', 'admin', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgB.id]);
    const adminB = adminBRes.rows[0];
    testUserIds.push(adminB.id);

    const employeeBRes = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('emp_b_${Date.now()}@beta.local', 'hash_test', 'employee', $1, NOW())
      RETURNING id, email, role, organization_id;
    `, [orgB.id]);
    const employeeB = employeeBRes.rows[0];
    testUserIds.push(employeeB.id);

    console.log(`[Setup] Users created for Org A and Org B`);

    // Tokens
    const tokenAdminA = createToken(adminA);
    const tokenEmpA = createToken(employeeA);
    const tokenAdminB = createToken(adminB);
    const tokenEmpB = createToken(employeeB);

    // 4. Seed test incidents
    // Incident A1 belonging to Org A (user: employeeA)
    const incA1Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'phishing', 'email', 'high', 0.85, 'Tenant A test incident', 'open', NOW())
      RETURNING id;
    `, [employeeA.id, orgA.id]);
    const incA1 = incA1Res.rows[0];
    testIncidentIds.push(incA1.id);

    // Incident A2 belonging to Org A (user: adminA)
    const incA2Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'deepfake', 'audio', 'critical', 0.92, 'Tenant A admin incident', 'open', NOW())
      RETURNING id;
    `, [adminA.id, orgA.id]);
    const incA2 = incA2Res.rows[0];
    testIncidentIds.push(incA2.id);

    // Add MITRE mapping for A1
    await query(`
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name)
      VALUES ($1, 'T1566', 'Phishing: Spearphishing');
    `, [incA1.id]);

    // Incident B1 belonging to Org B (user: employeeB)
    const incB1Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'malicious_url', 'url', 'critical', 0.99, 'Tenant B test incident', 'open', NOW())
      RETURNING id;
    `, [employeeB.id, orgB.id]);
    const incB1 = incB1Res.rows[0];
    testIncidentIds.push(incB1.id);

    // Add MITRE mapping for B1
    await query(`
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name)
      VALUES ($1, 'T1204', 'User Execution: Malicious URL');
    `, [incB1.id]);

    console.log(`[Setup] Incidents and MITRE mappings seeded`);

    // ==========================================
    // TEST 1: Incident Scoping & Tenant Isolation
    // ==========================================
    console.log('\n--- Running Test 1: Incidents ---');

    // 1a. Non-admin (employeeA) lists incidents: must only see own incident (incA1), not incA2 or incB1
    const res1a = await fetch(`${baseUrl}/incidents`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    const bodyEmpA = await res1a.json();
    const listEmpA = Array.isArray(bodyEmpA) ? bodyEmpA : (bodyEmpA.incidents || bodyEmpA.data || []);
    console.log(`1a. Employee A list count: ${listEmpA.length}, total: ${bodyEmpA.total}`);
    if (listEmpA.length !== 1 || listEmpA[0].id !== incA1.id || bodyEmpA.total !== 1) {
      throw new Error(`1a FAIL: Employee A saw unauthorized incidents: ${JSON.stringify(bodyEmpA)}`);
    }
    console.log('✔ 1a PASS: Non-admin query forced to WHERE user_id = req.user.id with total count');

    // 1b. Admin A lists incidents with malicious org query param: ?organization_id=${orgB.id}
    // Must IGNORE orgB.id and force WHERE organization_id = orgA.id
    const res1b = await fetch(`${baseUrl}/incidents?organization_id=${orgB.id}`, {
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    const bodyAdminA = await res1b.json();
    const listAdminA = Array.isArray(bodyAdminA) ? bodyAdminA : (bodyAdminA.incidents || bodyAdminA.data || []);
    console.log(`1b. Admin A list count: ${listAdminA.length}, total: ${bodyAdminA.total}`);
    const adminAIds = listAdminA.map(i => i.id);
    if (!adminAIds.includes(incA1.id) || !adminAIds.includes(incA2.id) || adminAIds.includes(incB1.id) || bodyAdminA.total !== 2) {
      throw new Error(`1b FAIL: Admin A saw cross-tenant incidents or missed org incidents: ${JSON.stringify(adminAIds)}`);
    }
    console.log('✔ 1b PASS: Admin query forced to WHERE organization_id = req.user.organization_id (client query param ignored)');

    // 1c. Admin A attempts to update incident B1 in Org B: must fail with 404
    const res1c = await fetch(`${baseUrl}/incidents/${incB1.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenAdminA}`
      },
      body: JSON.stringify({ status: 'resolved' })
    });
    console.log(`1c. Admin A updating Org B incident status code: ${res1c.status}`);
    if (res1c.status !== 404) {
      throw new Error(`1c FAIL: Cross-tenant update should have returned 404, got ${res1c.status}`);
    }
    // Confirm incB1 remains 'open' in DB
    const checkB1 = await query(`SELECT status FROM incidents WHERE id = $1`, [incB1.id]);
    if (checkB1.rows[0].status !== 'open') {
      throw new Error(`1c FAIL: Incident B1 was modified across tenants!`);
    }
    console.log('✔ 1c PASS: Cross-tenant incident update rejected with 404; state unchanged');

    // 1d. Admin A updates own org incident A1: succeeds with 200
    const res1d = await fetch(`${baseUrl}/incidents/${incA1.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenAdminA}`
      },
      body: JSON.stringify({ status: 'resolved' })
    });
    const updateRes = await res1d.json();
    console.log(`1d. Admin A updating Org A incident status code: ${res1d.status}, status: ${updateRes.status}`);
    if (res1d.status !== 200 || updateRes.status !== 'resolved') {
      throw new Error(`1d FAIL: Valid org incident update failed: ${JSON.stringify(updateRes)}`);
    }
    console.log('✔ 1d PASS: Admin update succeeded for own organization incident');

    // 1e. Non-admin (Employee A) fetches own incident A1 via GET /incidents/:id -> 200
    const res1e = await fetch(`${baseUrl}/incidents/${incA1.id}`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    const detailEmpA = await res1e.json();
    if (res1e.status !== 200 || detailEmpA.id !== incA1.id || !Array.isArray(detailEmpA.detection_signals) || !Array.isArray(detailEmpA.evidence)) {
      throw new Error(`1e FAIL: Non-admin fetch of own incident failed: ${JSON.stringify(detailEmpA)}`);
    }
    console.log('✔ 1e PASS: Non-admin fetched own incident with detection_signals and evidence arrays');

    // 1f. Non-admin (Employee A) attempts to fetch Org B incident B1 via GET /incidents/:id -> 404 (not 403)
    const res1f = await fetch(`${baseUrl}/incidents/${incB1.id}`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    if (res1f.status !== 404) {
      throw new Error(`1f FAIL: Cross-tenant GET by non-admin should return 404, got ${res1f.status}`);
    }
    console.log('✔ 1f PASS: Non-admin fetch of cross-tenant incident returned 404 (not 403)');

    // 1g. Admin A attempts to fetch Org B incident B1 via GET /incidents/:id -> 404 (not 403)
    const res1g = await fetch(`${baseUrl}/incidents/${incB1.id}`, {
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    if (res1g.status !== 404) {
      throw new Error(`1g FAIL: Cross-org GET by admin should return 404, got ${res1g.status}`);
    }
    console.log('✔ 1g PASS: Admin fetch of cross-tenant incident returned 404 (not 403)');

    // 1h. Non-existent ID or invalid UUID returns 404
    const res1h = await fetch(`${baseUrl}/incidents/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    if (res1h.status !== 404) {
      throw new Error(`1h FAIL: Non-existent incident should return 404, got ${res1h.status}`);
    }
    const res1h_invalid = await fetch(`${baseUrl}/incidents/invalid-uuid-format`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    if (res1h_invalid.status !== 404) {
      throw new Error(`1h FAIL: Invalid UUID should return 404, got ${res1h_invalid.status}`);
    }
    console.log('✔ 1h PASS: Non-existent and invalid UUID returned 404');

    // ==========================================
    // TEST 2: Telemetry Scoping & Target Verification
    // ==========================================
    console.log('\n--- Running Test 2: Telemetry ---');

    // 2a. Employee A sends login-event with spoofed user_id = employeeB.id
    // Must ignore employeeB.id and accept as Employee A
    const res2a = await fetch(`${baseUrl}/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpA}`
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        location: 'US-East',
        device_id: 'dev_123',
        failed_attempts: 0,
        user_id: employeeB.id
      })
    });
    if (res2a.status !== 201) {
      throw new Error(`2a FAIL: Non-admin login telemetry failed: status ${res2a.status}`);
    }
    console.log('✔ 2a PASS: Non-admin telemetry ignores spoofed client user_id');

    // 2b. Admin A sends login-event for employeeB.id (different org): must return 403 Forbidden
    const res2b = await fetch(`${baseUrl}/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenAdminA}`
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        location: 'US-East',
        device_id: 'dev_123',
        failed_attempts: 1,
        user_id: employeeB.id
      })
    });
    console.log(`2b. Admin A reporting telemetry for Org B user status code: ${res2b.status}`);
    if (res2b.status !== 403) {
      throw new Error(`2b FAIL: Admin telemetry for cross-org user should return 403, got ${res2b.status}`);
    }
    console.log('✔ 2b PASS: Admin cross-org telemetry rejected with 403 Forbidden');

    // 2c. Admin A sends system-event for employeeB.id (different org): must return 403 Forbidden
    const res2c = await fetch(`${baseUrl}/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenAdminA}`
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        event_type: 'process',
        details: { proc: 'svchost' },
        user_id: employeeB.id
      })
    });
    console.log(`2c. Admin A reporting system telemetry for Org B user status code: ${res2c.status}`);
    if (res2c.status !== 403) {
      throw new Error(`2c FAIL: Admin system telemetry for cross-org user should return 403, got ${res2c.status}`);
    }
    console.log('✔ 2c PASS: Admin cross-org system telemetry rejected with 403 Forbidden');

    // 2d. Admin A sends login-event for employeeA.id (same org): must succeed with 201
    const res2d = await fetch(`${baseUrl}/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenAdminA}`
      },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        location: 'US-East',
        device_id: 'dev_123',
        failed_attempts: 0,
        user_id: employeeA.id
      })
    });
    if (res2d.status !== 201) {
      throw new Error(`2d FAIL: Admin same-org telemetry failed: status ${res2d.status}`);
    }
    console.log('✔ 2d PASS: Admin same-org telemetry verified and accepted with 201');

    // ==========================================
    // TEST 3: Guardian Mode Identity & Scoping
    // ==========================================
    console.log('\n--- Running Test 3: Guardian Mode ---');

    // 3a. Employee A tries to link Employee B to Admin B (neither is Employee A): must return 403
    const res3a = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpA}`
      },
      body: JSON.stringify({
        guardian_user_id: employeeB.id,
        dependent_user_id: adminB.id
      })
    });
    console.log(`3a. Arbitrary guardian link status code: ${res3a.status}`);
    if (res3a.status !== 403) {
      throw new Error(`3a FAIL: Linking arbitrary third-party users should return 403, got ${res3a.status}`);
    }
    console.log('✔ 3a PASS: Arbitrary guardian linking rejected with 403 Forbidden');

    // 3b. Employee A links himself as guardian of Admin A (legitimate relationship): returns 201
    const res3b = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpA}`
      },
      body: JSON.stringify({
        guardian_user_id: employeeA.id,
        dependent_user_id: adminA.id
      })
    });
    const linkRes = await res3b.json();
    console.log(`3b. Legitimate link status code: ${res3b.status}`);
    if (res3b.status !== 201) {
      throw new Error(`3b FAIL: Legitimate guardian link failed: ${JSON.stringify(linkRes)}`);
    }
    testLinkIds.push(linkRes.link_id);
    console.log('✔ 3b PASS: Caller-involved guardian link created with 201');

    // Admin A (the dependent) accepts the pending guardian link
    const res3bAccept = await fetch(`${baseUrl}/guardian/link/${linkRes.link_id}/accept`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${tokenAdminA}`
      }
    });
    if (res3bAccept.status !== 200) {
      throw new Error(`3b FAIL: Dependent failed to accept link: ${res3bAccept.status}`);
    }
    console.log('✔ 3b PASS: Dependent accepted guardian link with 200');

    // 3c. Employee A queries dependent alerts:
    // Admin A has incident incA2 (critical, deepfake).
    // Employee A should see incA2, but NOT incA1 (own incident, not dependent's) and NOT incB1 (Tenant B).
    const res3c = await fetch(`${baseUrl}/guardian/alerts`, {
      headers: { Authorization: `Bearer ${tokenEmpA}` }
    });
    const alerts = await res3c.json();
    console.log(`3c. Dependent alerts count: ${alerts.length}`);
    const alertIncidentIds = alerts.map(a => a.alert_id);
    if (!alertIncidentIds.includes(incA2.id) || alertIncidentIds.includes(incB1.id)) {
      throw new Error(`3c FAIL: Dependent alerts scoping failed: ${JSON.stringify(alerts)}`);
    }
    console.log('✔ 3c PASS: Guardian alerts correctly scoped to active dependents with risk IN (high, critical)');

    // ==========================================
    // TEST 4: Analytics Aggregation Scoping
    // ==========================================
    console.log('\n--- Running Test 4: Analytics ---');

    // 4a. Overview: Admin A vs Admin B
    const res4aA = await fetch(`${baseUrl}/analytics/overview`, {
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    const overviewA = await res4aA.json();

    const res4aB = await fetch(`${baseUrl}/analytics/overview`, {
      headers: { Authorization: `Bearer ${tokenAdminB}` }
    });
    const overviewB = await res4aB.json();

    console.log(`4a. Admin A total incidents: ${overviewA.total_incidents}, Admin B total incidents: ${overviewB.total_incidents}`);
    // Org A total includes 2 seeded incidents + 2 incidents auto-created by the login anomaly engine from Step 2's telemetry events.
    // In Org B we have incB1 = 1 incident
    if (overviewA.total_incidents !== 4 || overviewB.total_incidents !== 1) {
      throw new Error(`4a FAIL: Overview tenant scoping failed: Org A has ${overviewA.total_incidents}, Org B has ${overviewB.total_incidents}`);
    }
    console.log('✔ 4a PASS: Analytics overview accurately scoped by organization');

    // 4b. Trends: Admin A vs Admin B
    const res4bA = await fetch(`${baseUrl}/analytics/trends`, {
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    const trendsA = await res4bA.json();
    const totalTrendsIncidentsA = trendsA.reduce((sum, t) => sum + t.incidents, 0);

    const res4bB = await fetch(`${baseUrl}/analytics/trends`, {
      headers: { Authorization: `Bearer ${tokenAdminB}` }
    });
    const trendsB = await res4bB.json();
    const totalTrendsIncidentsB = trendsB.reduce((sum, t) => sum + t.incidents, 0);

    console.log(`4b. Trends total incidents: Org A = ${totalTrendsIncidentsA}, Org B = ${totalTrendsIncidentsB}`);
    if (totalTrendsIncidentsA !== 4 || totalTrendsIncidentsB !== 1) {
      throw new Error(`4b FAIL: Analytics trends tenant scoping failed`);
    }
    console.log('✔ 4b PASS: Analytics trends accurately scoped by organization');

    // 4c. MITRE breakdown: Admin A (T1566) vs Admin B (T1204)
    const res4cA = await fetch(`${baseUrl}/analytics/mitre`, {
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    const mitreA = await res4cA.json();

    const res4cB = await fetch(`${baseUrl}/analytics/mitre`, {
      headers: { Authorization: `Bearer ${tokenAdminB}` }
    });
    const mitreB = await res4cB.json();

    console.log(`4c. Mitre A: ${JSON.stringify(mitreA)}, Mitre B: ${JSON.stringify(mitreB)}`);
    const mitreTechniquesA = mitreA.map(m => m.technique_id);
    const mitreTechniquesB = mitreB.map(m => m.technique_id);
    if (!mitreTechniquesA.includes('T1566') || mitreTechniquesA.includes('T1204')) {
      throw new Error(`4c FAIL: Mitre A leaked technique T1204 from Tenant B!`);
    }
    if (!mitreTechniquesB.includes('T1204') || mitreTechniquesB.includes('T1566')) {
      throw new Error(`4c FAIL: Mitre B leaked technique T1566 from Tenant A!`);
    }
    console.log('✔ 4c PASS: MITRE technique aggregates strictly isolated via JOIN incidents');

    // ==========================================
    // TEST 5: Check Endpoints Sourcing
    // ==========================================
    console.log('\n--- Running Test 5: Check Endpoints ---');

    // 5a. Employee A checks message: Incident created in DB must have user_id = employeeA.id and organization_id = orgA.id
    const res5a = await fetch(`${baseUrl}/check/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpA}`
      },
      body: JSON.stringify({
        text: 'Urgent: Click here to verify your banking credentials immediately',
        source_type: 'email'
      })
    });
    const checkMsgRes = await res5a.json();
    if (res5a.status !== 200 || !checkMsgRes.risk_level) {
      throw new Error(`5a FAIL: Check message failed: ${JSON.stringify(checkMsgRes)}`);
    }
    // Verify latest incident in DB for employeeA
    const incMsgDb = await query(`
      SELECT * FROM incidents WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1;
    `, [employeeA.id]);
    const createdMsgInc = incMsgDb.rows[0];
    testIncidentIds.push(createdMsgInc.id);
    if (createdMsgInc.user_id !== employeeA.id || createdMsgInc.organization_id !== orgA.id) {
      throw new Error(`5a FAIL: Created incident did not source auth credentials! user: ${createdMsgInc.user_id}, org: ${createdMsgInc.organization_id}`);
    }
    console.log('✔ 5a PASS: checkMessage sourced user_id and organization_id strictly from auth session');

    // 5b. Employee B checks URL: Incident created in DB must have user_id = employeeB.id and organization_id = orgB.id
    const res5b = await fetch(`${baseUrl}/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpB}`
      },
      body: JSON.stringify({
        url: 'http://malicious-update-paypal-security.com'
      })
    });
    const checkUrlRes = await res5b.json();
    if (res5b.status !== 200 || !checkUrlRes.risk_level) {
      throw new Error(`5b FAIL: Check URL failed: ${JSON.stringify(checkUrlRes)}`);
    }
    const incUrlDb = await query(`
      SELECT * FROM incidents WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1;
    `, [employeeB.id]);
    const createdUrlInc = incUrlDb.rows[0];
    testIncidentIds.push(createdUrlInc.id);
    if (createdUrlInc.user_id !== employeeB.id || createdUrlInc.organization_id !== orgB.id) {
      throw new Error(`5b FAIL: Created URL incident did not source auth credentials!`);
    }
    console.log('✔ 5b PASS: checkUrl sourced user_id and organization_id strictly from auth session');

    // 5c. Employee A checks media: Incident created in DB must have user_id = employeeA.id and organization_id = orgA.id
    const res5c = await fetch(`${baseUrl}/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenEmpA}`
      },
      body: JSON.stringify({
        file_url: 'https://cdn.example.com/audio/voice-sample.wav',
        media_type: 'audio'
      })
    });
    const checkMediaRes = await res5c.json();
    if (res5c.status !== 200 || !checkMediaRes.risk_level) {
      throw new Error(`5c FAIL: Check media failed: ${JSON.stringify(checkMediaRes)}`);
    }
    const incMediaDb = await query(`
      SELECT * FROM incidents WHERE user_id = $1 AND threat_type = 'deepfake' ORDER BY created_at DESC LIMIT 1;
    `, [employeeA.id]);
    const createdMediaInc = incMediaDb.rows[0];
    testIncidentIds.push(createdMediaInc.id);
    if (createdMediaInc.user_id !== employeeA.id || createdMediaInc.organization_id !== orgA.id) {
      throw new Error(`5c FAIL: Created media incident did not source auth credentials!`);
    }
    console.log('✔ 5c PASS: checkMedia sourced user_id and organization_id strictly from auth session');

    console.log('\n=============================================');
    console.log('ALL 5 TENANT ISOLATION TESTS PASSED 100%!');
    console.log('=============================================\n');

  } catch (err) {
    console.error('\n❌ VERIFICATION TEST FAILED:', err);
    process.exitCode = 1;
  } finally {
    // Teardown: clean up test data in reverse order of FKs
    console.log('[Cleanup] Cleaning up test records...');
    try {
      if (testLinkIds.length > 0) {
        await query(`DELETE FROM guardian_links WHERE id = ANY($1::uuid[])`, [testLinkIds]);
      }
      if (testIncidentIds.length > 0) {
        await query(`DELETE FROM mitre_mappings WHERE incident_id = ANY($1::uuid[])`, [testIncidentIds]);
        await query(`DELETE FROM incidents WHERE id = ANY($1::uuid[])`, [testIncidentIds]);
      }
      if (testUserIds.length > 0) {
        await query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [testUserIds]);
      }
      if (testOrgIds.length > 0) {
        await query(`DELETE FROM organizations WHERE id = ANY($1::uuid[])`, [testOrgIds]);
      }
      console.log('[Cleanup] Test database cleanup completed.');
    } catch (cleanupErr) {
      console.error('[Cleanup Error]', cleanupErr);
    }

    if (server) {
      server.close();
    }
    await pool.end();
  }
}

runTenantIsolationVerification();
