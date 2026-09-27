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

async function runIncidentEndpointTests() {
  let server;
  const testOrgIds = [];
  const testUserIds = [];
  const testIncidentIds = [];

  try {
    // 1. Start HTTP Server
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[Incident Tests] Server started on port ${port}`);

    // 2. Create test orgs & users
    const org1Res = await query(`INSERT INTO organizations (name, created_at) VALUES ('Org Incidents 1', NOW()) RETURNING id;`);
    const org2Res = await query(`INSERT INTO organizations (name, created_at) VALUES ('Org Incidents 2', NOW()) RETURNING id;`);
    const org1Id = org1Res.rows[0].id;
    const org2Id = org2Res.rows[0].id;
    testOrgIds.push(org1Id, org2Id);

    const user1Res = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('user1_${Date.now()}@test.local', 'hash', 'employee', $1, NOW())
      RETURNING id, role, organization_id;
    `, [org1Id]);
    const user1 = user1Res.rows[0];
    testUserIds.push(user1.id);
    const tokenUser1 = createToken(user1);

    const user2Res = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('user2_${Date.now()}@test.local', 'hash', 'employee', $1, NOW())
      RETURNING id, role, organization_id;
    `, [org2Id]);
    const user2 = user2Res.rows[0];
    testUserIds.push(user2.id);
    const tokenUser2 = createToken(user2);

    const admin1Res = await query(`
      INSERT INTO users (email, password_hash, role, organization_id, created_at)
      VALUES ('admin1_${Date.now()}@test.local', 'hash', 'admin', $1, NOW())
      RETURNING id, role, organization_id;
    `, [org1Id]);
    const admin1 = admin1Res.rows[0];
    testUserIds.push(admin1.id);
    const tokenAdmin1 = createToken(admin1);

    // 3. Seed incidents with signals, recommended actions, mitre mappings, and evidence
    const inc1Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'phishing', 'email', 'high', 82.5, 'Test incident 1 for user1', 'open', NOW())
      RETURNING id;
    `, [user1.id, org1Id]);
    const inc1Id = inc1Res.rows[0].id;
    testIncidentIds.push(inc1Id);

    const inc2Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'malicious_url', 'url', 'critical', 95.0, 'Test incident 2 for user1', 'investigating', NOW())
      RETURNING id;
    `, [user1.id, org1Id]);
    const inc2Id = inc2Res.rows[0].id;
    testIncidentIds.push(inc2Id);

    const inc3Res = await query(`
      INSERT INTO incidents (user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
      VALUES ($1, $2, 'deepfake', 'audio', 'critical', 90.0, 'Test incident 3 for user2 Org2', 'open', NOW())
      RETURNING id;
    `, [user2.id, org2Id]);
    const inc3Id = inc3Res.rows[0].id;
    testIncidentIds.push(inc3Id);

    // Add technical signals to inc1
    await query(`
      INSERT INTO detection_signals (incident_id, signal_name, signal_value, weight)
      VALUES ($1, 'urgency_score', '0.92', 0.8), ($1, 'credential_solicitation', 'true', 0.9);
    `, [inc1Id]);

    // Add recommended actions to inc1
    await query(`
      INSERT INTO recommended_actions (incident_id, action_type, action_status, created_at)
      VALUES ($1, 'Quarantine message', 'pending', NOW()), ($1, 'Block sender domain', 'pending', NOW());
    `, [inc1Id]);

    // Add MITRE mapping to inc1
    await query(`
      INSERT INTO mitre_mappings (incident_id, technique_id, technique_name)
      VALUES ($1, 'T1566', 'Phishing');
    `, [inc1Id]);

    // Add incident evidence to inc1
    await query(`
      INSERT INTO incident_evidence (incident_id, evidence_type, evidence_data, metadata, created_at)
      VALUES ($1, 'email_header', 'Received: from mail.attacker.xyz', '{"spf": "fail"}', NOW());
    `, [inc1Id]);

    console.log('[Setup] Test data successfully seeded.');

    // =========================================================================
    // TEST 1: GET /api/v1/incidents (listIncidents)
    // =========================================================================
    console.log('\n--- 1. Testing GET /api/v1/incidents pagination & shape ---');

    // 1a. User1 lists incidents: must see 2 incidents with total=2
    const res1 = await fetch(`${baseUrl}/incidents`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    const data1 = await res1.json();
    console.log(`1a. Status: ${res1.status}, total: ${data1.total}, limit: ${data1.limit}, offset: ${data1.offset}, count: ${data1.data?.length}`);
    if (res1.status !== 200) throw new Error(`1a FAIL: Expected 200, got ${res1.status}`);
    if (data1.total !== 2 || data1.limit !== 25 || data1.offset !== 0 || data1.data?.length !== 2) {
      throw new Error(`1a FAIL: Incorrect pagination shape: ${JSON.stringify(data1)}`);
    }

    // Verify item schema matches API contract Section 2 exactly
    const item1 = data1.data.find(i => i.id === inc1Id);
    if (!item1) throw new Error(`1a FAIL: inc1Id missing from results`);
    const expectedKeys = ['id', 'threat_type', 'source_type', 'risk_level', 'risk_score', 'explanation', 'status', 'created_at', 'recommended_actions', 'mitre_mappings'];
    for (const key of expectedKeys) {
      if (item1[key] === undefined) throw new Error(`1a FAIL: Key '${key}' missing in incident item`);
    }
    if (item1.recommended_actions.length !== 2) throw new Error(`1a FAIL: expected 2 recommended actions, got ${item1.recommended_actions.length}`);
    if (item1.mitre_mappings.length !== 1) throw new Error(`1a FAIL: expected 1 mitre mapping, got ${item1.mitre_mappings.length}`);
    console.log('✔ 1a PASS: List endpoint returns exact API contract shape with batch-joined child records and total count');

    // 1b. Pagination limit & offset
    const res1b = await fetch(`${baseUrl}/incidents?limit=1&offset=1`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    const data1b = await res1b.json();
    console.log(`1b. limit=1&offset=1 -> returned ${data1b.data?.length} items, total=${data1b.total}`);
    if (data1b.data?.length !== 1 || data1b.total !== 2 || data1b.limit !== 1 || data1b.offset !== 1) {
      throw new Error(`1b FAIL: Pagination parameters not honored: ${JSON.stringify(data1b)}`);
    }
    console.log('✔ 1b PASS: ?limit and ?offset query params correctly paginate results');

    // 1c. Limit capping: limit=200 should be capped at 100
    const res1c = await fetch(`${baseUrl}/incidents?limit=200`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    const data1c = await res1c.json();
    if (data1c.limit !== 100) {
      throw new Error(`1c FAIL: Expected limit to be clamped to 100, got ${data1c.limit}`);
    }
    console.log('✔ 1c PASS: ?limit=200 correctly clamped to max 100');

    // =========================================================================
    // TEST 2: GET /api/v1/incidents/:id (getIncidentById)
    // =========================================================================
    console.log('\n--- 2. Testing GET /api/v1/incidents/:id ---');

    // 2a. Fetch detail with signals, evidence, actions, mitre
    const res2a = await fetch(`${baseUrl}/incidents/${inc1Id}`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    const detail2a = await res2a.json();
    console.log(`2a. Status: ${res2a.status}, id: ${detail2a.id}`);
    if (res2a.status !== 200) throw new Error(`2a FAIL: Expected 200, got ${res2a.status}`);
    if (detail2a.id !== inc1Id) throw new Error(`2a FAIL: ID mismatch`);
    if (!Array.isArray(detail2a.detection_signals) || detail2a.detection_signals.length !== 2) {
      throw new Error(`2a FAIL: detection_signals array incorrect: ${JSON.stringify(detail2a.detection_signals)}`);
    }
    if (!Array.isArray(detail2a.evidence) || detail2a.evidence.length !== 1) {
      throw new Error(`2a FAIL: evidence array incorrect: ${JSON.stringify(detail2a.evidence)}`);
    }
    if (!Array.isArray(detail2a.recommended_actions) || detail2a.recommended_actions.length !== 2) {
      throw new Error(`2a FAIL: recommended_actions array incorrect`);
    }
    if (!Array.isArray(detail2a.mitre_mappings) || detail2a.mitre_mappings.length !== 1) {
      throw new Error(`2a FAIL: mitre_mappings array incorrect`);
    }
    // Verify detection signal item shape
    const sig = detail2a.detection_signals[0];
    if (sig.signal_name === undefined || sig.signal_value === undefined || sig.weight === undefined) {
      throw new Error(`2a FAIL: signal item missing fields: ${JSON.stringify(sig)}`);
    }
    console.log('✔ 2a PASS: getIncidentById returns full incident + detection_signals + evidence + actions + mitre');

    // 2b. Empty evidence returns empty array [] (inc2 has no evidence rows)
    const res2b = await fetch(`${baseUrl}/incidents/${inc2Id}`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    const detail2b = await res2b.json();
    if (!Array.isArray(detail2b.evidence) || detail2b.evidence.length !== 0) {
      throw new Error(`2b FAIL: Expected empty evidence array [], got: ${JSON.stringify(detail2b.evidence)}`);
    }
    console.log('✔ 2b PASS: Incidents with no evidence rows return evidence: []');

    // 2c. Non-admin accessing another user's incident -> returns 404 (NOT 403)
    const res2c = await fetch(`${baseUrl}/incidents/${inc3Id}`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    console.log(`2c. Non-admin cross-user fetch status: ${res2c.status}`);
    if (res2c.status !== 404) {
      throw new Error(`2c FAIL: Expected 404 for cross-user incident access, got ${res2c.status}`);
    }
    console.log('✔ 2c PASS: Cross-user incident access returned 404 Not Found (no existence leak)');

    // 2d. Admin Org 1 accessing Org 2 incident -> returns 404 (NOT 403)
    const res2d = await fetch(`${baseUrl}/incidents/${inc3Id}`, {
      headers: { Authorization: `Bearer ${tokenAdmin1}` }
    });
    console.log(`2d. Admin cross-org fetch status: ${res2d.status}`);
    if (res2d.status !== 404) {
      throw new Error(`2d FAIL: Expected 404 for cross-org incident access by admin, got ${res2d.status}`);
    }
    console.log('✔ 2d PASS: Cross-org incident access by admin returned 404 Not Found');

    // 2e. Non-existent UUID -> returns 404
    const res2e = await fetch(`${baseUrl}/incidents/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    if (res2e.status !== 404) {
      throw new Error(`2e FAIL: Non-existent UUID should return 404, got ${res2e.status}`);
    }
    // 2f. Malformed ID -> returns 404
    const res2f = await fetch(`${baseUrl}/incidents/not-a-valid-uuid`, {
      headers: { Authorization: `Bearer ${tokenUser1}` }
    });
    if (res2f.status !== 404) {
      throw new Error(`2f FAIL: Malformed UUID should return 404, got ${res2f.status}`);
    }
    console.log('✔ 2e/2f PASS: Non-existent and malformed incident IDs cleanly return 404');

    console.log('\n=============================================');
    console.log('ALL INCIDENT ENDPOINT TESTS PASSED 100%!');
    console.log('=============================================\n');

  } finally {
    // Cleanup
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
  }
}

runIncidentEndpointTests().catch((err) => {
  console.error('[TEST SUITE FAILURE]', err);
  process.exit(1);
});
