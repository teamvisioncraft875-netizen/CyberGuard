process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { app } = require('./src');
const db = require('./src/config/db');
const AuditLog = require('./src/models/AuditLog');
const { AUDIT_ACTIONS } = require('./src/services/auditService');

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

async function runAuditLoggingTestSuite() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 1A AUDIT LOGGING VERIFICATION SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdIncidentIds = [];
  const createdActionIds = [];
  const createdLinkIds = [];
  const createdAuditLogIds = [];

  const timestamp = Date.now();
  const rawAdminPassword = 'SuperSecretAdminP@ss123!';
  const wrongPassword = 'WrongPasswordAttempt999!';

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
    // Test 1: AuditLog Model Immutability Contract
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: AuditLog Model Immutability Contract ---');
    assert.strictEqual(typeof AuditLog.create, 'function', 'AuditLog.create must be an exported function');
    assert.strictEqual(typeof AuditLog.list, 'function', 'AuditLog.list must be an exported function');
    assert.strictEqual(AuditLog.update, undefined, 'AuditLog must NOT expose an update method');
    assert.strictEqual(AuditLog.delete, undefined, 'AuditLog must NOT expose a delete method');
    assert.strictEqual(AuditLog.destroy, undefined, 'AuditLog must NOT expose a destroy method');
    assert.strictEqual(AuditLog.remove, undefined, 'AuditLog must NOT expose a remove method');
    assert.strictEqual(AuditLog.updateStatus, undefined, 'AuditLog must NOT expose an updateStatus method');
    console.log('✔ [PASS] AuditLog exposes only create() and list() (Append-only guarantee)');

    // ──────────────────────────────────────────────────────────────────────────
    // Setup Organizations and Users for Org A and Org B
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n[SETUP] Creating test organizations and user accounts...');
    const orgARes = await db.query(
      `INSERT INTO organizations (name, created_at) VALUES ($1, NOW()) RETURNING id, name;`,
      [`Test Org Alpha ${timestamp}`]
    );
    const orgA = orgARes.rows[0];
    createdOrgIds.push(orgA.id);

    const orgBRes = await db.query(
      `INSERT INTO organizations (name, created_at) VALUES ($1, NOW()) RETURNING id, name;`,
      [`Test Org Beta ${timestamp}`]
    );
    const orgB = orgBRes.rows[0];
    createdOrgIds.push(orgB.id);

    const passwordHash = await bcrypt.hash(rawAdminPassword, 10);

    // Admin A (Org A)
    const adminARes = await db.query(
      `INSERT INTO users (email, password_hash, role, organization_id, created_at)
       VALUES ($1, $2, 'admin', $3, NOW()) RETURNING id, email, role, organization_id;`,
      [`admin_a_${timestamp}@alpha.internal`, passwordHash, orgA.id]
    );
    const adminA = adminARes.rows[0];
    createdUserIds.push(adminA.id);
    const adminAToken = createToken(adminA);

    // Employee A (Org A)
    const empARes = await db.query(
      `INSERT INTO users (email, password_hash, role, organization_id, created_at)
       VALUES ($1, $2, 'employee', $3, NOW()) RETURNING id, email, role, organization_id;`,
      [`emp_a_${timestamp}@alpha.internal`, passwordHash, orgA.id]
    );
    const employeeA = empARes.rows[0];
    createdUserIds.push(employeeA.id);
    const employeeAToken = createToken(employeeA);

    // Admin B (Org B)
    const adminBRes = await db.query(
      `INSERT INTO users (email, password_hash, role, organization_id, created_at)
       VALUES ($1, $2, 'admin', $3, NOW()) RETURNING id, email, role, organization_id;`,
      [`admin_b_${timestamp}@beta.internal`, passwordHash, orgB.id]
    );
    const adminB = adminBRes.rows[0];
    createdUserIds.push(adminB.id);
    const adminBToken = createToken(adminB);

    // Dependent User (individual)
    const depUserRes = await db.query(
      `INSERT INTO users (email, password_hash, role, organization_id, created_at)
       VALUES ($1, $2, 'individual', NULL, NOW()) RETURNING id, email, role, organization_id;`,
      [`dependent_${timestamp}@cyberguard.internal`, passwordHash]
    );
    const dependentUser = depUserRes.rows[0];
    createdUserIds.push(dependentUser.id);
    const dependentToken = createToken(dependentUser);

    console.log(`[SETUP] Org A: ${orgA.id}, Org B: ${orgB.id}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Failed and Successful Login Auditing + Sensitive Data Stripping
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Login Auditing & Secret Scrubbing ---');
    
    // 2a. Failed Login
    const failedLoginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: adminA.email.toUpperCase(), // Test lowercasing
        password: wrongPassword
      })
    });
    assert.strictEqual(failedLoginRes.status, 401, 'Failed login should return 401');

    // 2b. Successful Login
    const successLoginRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: adminA.email,
        password: rawAdminPassword
      })
    });
    assert.strictEqual(successLoginRes.status, 200, 'Successful login should return 200');
    const successBody = await successLoginRes.json();
    assert.ok(successBody.accessToken || successBody.token, 'Successful login should return token');

    // Wait for fire-and-forget logging
    await sleep(250);

    // Fetch audit log entries from DB for Admin A email
    const loginLogsRes = await db.query(
      `SELECT * FROM audit_logs 
       WHERE action IN ('auth:login_failed', 'auth:login_success')
         AND (details->>'attempted_email' = $1 OR user_id = $2)
       ORDER BY created_at ASC;`,
      [adminA.email.toLowerCase(), adminA.id]
    );

    assert.ok(loginLogsRes.rows.length >= 2, `Expected at least 2 login audit rows, got ${loginLogsRes.rows.length}`);
    loginLogsRes.rows.forEach((r) => createdAuditLogIds.push(r.id));

    const failedRow = loginLogsRes.rows.find((r) => r.action === 'auth:login_failed');
    const successRow = loginLogsRes.rows.find((r) => r.action === 'auth:login_success');

    assert.ok(failedRow, 'Must have recorded auth:login_failed');
    assert.strictEqual(failedRow.details.attempted_email, adminA.email.toLowerCase(), 'Email must be logged in lowercase');
    assert.strictEqual(failedRow.details.password, undefined, 'Password field must not exist');

    assert.ok(successRow, 'Must have recorded auth:login_success');
    assert.strictEqual(successRow.user_id, adminA.id, 'User ID must match authenticated admin');

    // Stringify all returned rows and assert no password or token value appears anywhere
    const serializedLogs = JSON.stringify(loginLogsRes.rows);
    assert.ok(!serializedLogs.includes(rawAdminPassword), 'CRITICAL: Raw password must NEVER appear in serialized logs');
    assert.ok(!serializedLogs.includes(wrongPassword), 'CRITICAL: Attempted wrong password must NEVER appear in serialized logs');
    assert.ok(!serializedLogs.includes(successBody.accessToken), 'CRITICAL: Access token must NEVER appear in serialized logs');
    if (successBody.refreshToken) {
      assert.ok(!serializedLogs.includes(successBody.refreshToken), 'CRITICAL: Refresh token must NEVER appear in serialized logs');
    }
    console.log('✔ [PASS] Failed & successful login rows created with strict credential & token redaction');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Admin Incident Status Update Auditing (Before/After)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Admin Incident Status Update Auditing ---');
    const incidentRes = await db.query(
      `INSERT INTO incidents (organization_id, user_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at)
       VALUES ($1, $2, 'phishing', 'email', 'high', 78, 'Suspicious phishing message detected', 'open', NOW())
       RETURNING id, status, organization_id;`,
      [orgA.id, adminA.id]
    );
    const incidentA = incidentRes.rows[0];
    createdIncidentIds.push(incidentA.id);

    const updateIncRes = await fetch(`${baseUrl}/incidents/${incidentA.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminAToken}`
      },
      body: JSON.stringify({ status: 'investigating' })
    });
    assert.strictEqual(updateIncRes.status, 200, 'Admin updating incident status should return 200');

    await sleep(200);

    const incAuditRes = await db.query(
      `SELECT * FROM audit_logs 
       WHERE resource_type = 'incident' AND resource_id = $1 AND action = 'incident:status_updated';`,
      [incidentA.id]
    );
    assert.strictEqual(incAuditRes.rows.length, 1, 'Must have recorded exactly one incident status audit log');
    const incAudit = incAuditRes.rows[0];
    createdAuditLogIds.push(incAudit.id);

    assert.strictEqual(incAudit.actor_type, 'admin', 'Actor type must be admin');
    assert.strictEqual(incAudit.details.previous_status, 'open', 'Previous status must be open');
    assert.strictEqual(incAudit.details.new_status, 'investigating', 'New status must be investigating');
    console.log('✔ [PASS] Incident status update logged with previous_status and new_status');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Action Status PATCH and Guardian Accept/Revoke Flow Auditing
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Action PATCH & Guardian Flow Auditing ---');

    // 4a. Recommended Action Status Update
    const actionDbRes = await db.query(
      `INSERT INTO recommended_actions (incident_id, action_type, action_status, created_at)
       VALUES ($1, 'isolate_endpoint', 'pending', NOW())
       RETURNING id, action_status, incident_id;`,
      [incidentA.id]
    );
    const actionA = actionDbRes.rows[0];
    createdActionIds.push(actionA.id);

    const actionPatchRes = await fetch(`${baseUrl}/actions/${actionA.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminAToken}`
      },
      body: JSON.stringify({ action_status: 'taken' })
    });
    assert.strictEqual(actionPatchRes.status, 200, 'Admin patching action status should return 200');

    await sleep(200);

    const actionAuditRes = await db.query(
      `SELECT * FROM audit_logs 
       WHERE resource_type = 'action' AND resource_id = $1 AND action = 'action:status_updated';`,
      [actionA.id]
    );
    assert.strictEqual(actionAuditRes.rows.length, 1, 'Must have recorded action status audit log');
    createdAuditLogIds.push(actionAuditRes.rows[0].id);
    assert.strictEqual(actionAuditRes.rows[0].details.previous_status, 'pending');
    assert.strictEqual(actionAuditRes.rows[0].details.new_status, 'taken');
    console.log('✔ [PASS] Recommended action status PATCH logged with before/after state');

    // 4b. Guardian Accept & Revoke Flow
    // Create link
    const linkCreateRes = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${dependentToken}`
      },
      body: JSON.stringify({
        guardian_user_id: adminA.id,
        dependent_user_id: dependentUser.id
      })
    });
    assert.strictEqual(linkCreateRes.status, 201, 'Creating guardian link should return 201');
    const linkBody = await linkCreateRes.json();
    const linkId = linkBody.link_id;
    createdLinkIds.push(linkId);

    // Accept link by dependent
    const linkAcceptRes = await fetch(`${baseUrl}/guardian/link/${linkId}/accept`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${dependentToken}`
      }
    });
    assert.strictEqual(linkAcceptRes.status, 200, 'Accepting guardian link should return 200');

    // Revoke link by guardian (Admin A)
    const linkRevokeRes = await fetch(`${baseUrl}/guardian/link/${linkId}/revoke`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${adminAToken}`
      }
    });
    assert.strictEqual(linkRevokeRes.status, 200, 'Revoking guardian link should return 200');

    await sleep(250);

    const guardianAuditsRes = await db.query(
      `SELECT * FROM audit_logs 
       WHERE resource_type = 'guardian_link' AND resource_id = $1
       ORDER BY created_at ASC;`,
      [linkId]
    );
    assert.ok(guardianAuditsRes.rows.length >= 3, `Expected at least 3 guardian audit rows, got ${guardianAuditsRes.rows.length}`);
    guardianAuditsRes.rows.forEach((r) => createdAuditLogIds.push(r.id));

    const createdAudit = guardianAuditsRes.rows.find((r) => r.action === AUDIT_ACTIONS.GUARDIAN_LINK_CREATED);
    const acceptedAudit = guardianAuditsRes.rows.find((r) => r.action === AUDIT_ACTIONS.GUARDIAN_LINK_ACCEPTED);
    const revokedAudit = guardianAuditsRes.rows.find((r) => r.action === AUDIT_ACTIONS.GUARDIAN_LINK_REVOKED);

    assert.ok(createdAudit, 'Must record GUARDIAN_LINK_CREATED');
    assert.ok(acceptedAudit, 'Must record GUARDIAN_LINK_ACCEPTED');
    assert.ok(revokedAudit, 'Must record GUARDIAN_LINK_REVOKED');
    assert.strictEqual(acceptedAudit.details.new_status, 'active');
    assert.strictEqual(revokedAudit.details.new_status, 'revoked');
    console.log('✔ [PASS] Guardian link create, accept, and revoke flow logged with full status transitions');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: Tenant Isolation & RBAC on GET /api/v1/audit-logs
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Tenant Isolation & RBAC on GET /api/v1/audit-logs ---');

    // 5a. Admin A queries audit logs -> Sees only Org A logs
    const orgALogsRes = await fetch(`${baseUrl}/audit-logs?limit=50`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${adminAToken}` }
    });
    assert.strictEqual(orgALogsRes.status, 200, 'Admin A should be allowed to view audit logs');
    const orgALogsData = await orgALogsRes.json();
    assert.ok(Array.isArray(orgALogsData.logs), 'Response must contain logs array');
    assert.ok(orgALogsData.total > 0, 'Org A must have at least one audit log');
    assert.strictEqual(orgALogsData.limit, 50, 'Limit should match requested');
    // Check that every single row belongs to Org A
    orgALogsData.logs.forEach((log) => {
      assert.strictEqual(log.organization_id, orgA.id, `All logs must belong to Org A (${orgA.id})`);
    });

    // 5b. Admin B queries audit logs -> Must see NONE of Org A's logs
    const orgBLogsRes = await fetch(`${baseUrl}/audit-logs?limit=50`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${adminBToken}` }
    });
    assert.strictEqual(orgBLogsRes.status, 200, 'Admin B should be allowed to view audit logs');
    const orgBLogsData = await orgBLogsRes.json();
    orgBLogsData.logs.forEach((log) => {
      assert.notStrictEqual(log.organization_id, orgA.id, 'CRITICAL: Admin B must NEVER see Org A logs');
    });

    // 5c. Employee A queries audit logs -> Strictly 403 Forbidden
    const empLogsRes = await fetch(`${baseUrl}/audit-logs`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${employeeAToken}` }
    });
    assert.strictEqual(empLogsRes.status, 403, 'Employee must be rejected with 403 Forbidden');

    // 5d. Individual user queries audit logs -> Strictly 403 Forbidden
    const indLogsRes = await fetch(`${baseUrl}/audit-logs`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${dependentToken}` }
    });
    assert.strictEqual(indLogsRes.status, 403, 'Individual user must be rejected with 403 Forbidden');

    // 5e. Unauthenticated request -> Strictly 401 Unauthorized
    const unauthLogsRes = await fetch(`${baseUrl}/audit-logs`, {
      method: 'GET'
    });
    assert.strictEqual(unauthLogsRes.status, 401, 'Unauthenticated request must be rejected with 401');

    console.log('✔ [PASS] Tenant isolation and RBAC strictly enforced on GET /api/v1/audit-logs');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Audit Service Resilience (Fire-and-forget non-blocking guarantee)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Resilience (Audit Failure Never Blocks Flow) ---');
    const originalCreate = AuditLog.create;
    AuditLog.create = async () => {
      throw new Error('Simulated Database Outage / RLS Violation in AuditLog.create');
    };

    try {
      const resilientLoginRes = await fetch(`${baseUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: adminA.email,
          password: rawAdminPassword
        })
      });

      assert.strictEqual(resilientLoginRes.status, 200, 'Login must succeed with 200 even when AuditLog throws');
      const resilientData = await resilientLoginRes.json();
      assert.ok(resilientData.accessToken || resilientData.token, 'Tokens must be returned cleanly');
      console.log('✔ [PASS] Application remains 100% operational when AuditLog.create throws');
    } finally {
      AuditLog.create = originalCreate;
    }

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL AUDIT LOGGING TESTS PASSED (6/6)');
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } finally {
    // Teardown HTTP Server
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }

    console.log('[CLEANUP] Tearing down test artifacts from live database...');
    for (const id of createdAuditLogIds) {
      try { await db.query(`DELETE FROM audit_logs WHERE id = $1;`, [id]); } catch (_) {}
    }
    for (const id of createdLinkIds) {
      try { await db.query(`DELETE FROM guardian_links WHERE id = $1;`, [id]); } catch (_) {}
    }
    for (const id of createdActionIds) {
      try { await db.query(`DELETE FROM recommended_actions WHERE id = $1;`, [id]); } catch (_) {}
    }
    for (const id of createdIncidentIds) {
      try { await db.query(`DELETE FROM incidents WHERE id = $1;`, [id]); } catch (_) {}
    }
    for (const id of createdUserIds) {
      try { await db.query(`DELETE FROM users WHERE id = $1;`, [id]); } catch (_) {}
    }
    for (const id of createdOrgIds) {
      try { await db.query(`DELETE FROM organizations WHERE id = $1;`, [id]); } catch (_) {}
    }
    console.log('[CLEANUP] Complete.');
    await db.pool.end();
  }
}

runAuditLoggingTestSuite()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error('\n❌ AUDIT LOGGING TEST SUITE FAILED:', err);
    process.exit(1);
  });
