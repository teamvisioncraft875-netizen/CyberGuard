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
const AuditLog = require('./src/models/AuditLog');
const notificationService = require('./src/services/notificationService');
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

async function waitFor(conditionFn, timeoutMs = 4000, intervalMs = 100) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await conditionFn();
    if (res) return res;
    await sleep(intervalMs);
  }
  return await conditionFn();
}

async function runNotificationsTestSuite() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — PHASE 1C NOTIFICATION SERVICE & APPROVAL SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdPolicyIds = [];
  const createdIncidentIds = [];
  const createdActionIds = [];
  const createdAuditLogIds = [];

  const timestamp = Date.now();
  const rawAdminPassword = 'SuperSecretAdminP@ss123!';

  // Store original sendActionNotification to restore in finally block
  const originalSendActionNotification = notificationService.sendActionNotification;
  const capturedNotificationCalls = [];

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
    // Setup: Seed Organization and Admin User
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Setup: Seed Organization and Admin User ---');
    const orgRes = await db.query(
      `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
      [`Org Notif Test ${timestamp}`]
    );
    const org = orgRes.rows[0];
    createdOrgIds.push(org.id);

    const passwordHash = await bcrypt.hash(rawAdminPassword, 10);
    const adminRes = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id)
       VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin_notif_${timestamp}@cyberguard.internal`, passwordHash, org.id]
    );
    const admin = adminRes.rows[0];
    createdUserIds.push(admin.id);

    const adminToken = createToken(admin);
    console.log(`[SETUP] Org: ${org.id}, Admin: ${admin.id} (${admin.email})`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: Hook & Mock sendActionNotification
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 1: Mock Notification Hook & Action Creation ---');
    notificationService.sendActionNotification = async function (action, incident, policy) {
      capturedNotificationCalls.push({ action, incident, policy });
      return true;
    };

    // Create policy for organization
    const policy = await ResponsePolicy.create({
      organization_id: org.id,
      name: 'Phishing Shadow Notification Policy',
      enabled: true,
      rules: [
        {
          threat_type: 'phishing',
          min_score: 70,
          action_type: 'notify_admin',
          action_mode: 'shadow',
          requires_approval: false,
          auto_execute_after_mins: 0
        }
      ]
    });
    createdPolicyIds.push(policy.id);

    // Trigger incident creation with sensitive details to verify scrubbing
    const incident = await persistDetectionIncident({
      user: admin,
      threatType: 'phishing',
      sourceType: 'email',
      mlResult: {
        risk_score: 85,
        risk_level: 'High',
        explanation: 'Suspicious credential harvest portal targeting employee credentials.',
        confidence: 90,
        signals: {
          user_password: 'SuperSensitivePassword123!',
          bearer_token: 'eySecretJwtToken1234567890',
          domain: 'phishing-target.net'
        }
      },
      recommendedActions: ['notify_admin']
    });
    createdIncidentIds.push(incident.id);

    // Wait for the hook to capture the notification
    const hookTriggered = await waitFor(() => capturedNotificationCalls.length > 0, 4000);
    assert.ok(hookTriggered, 'Expected sendActionNotification to be called via PolicyEngine hook');

    const captured = capturedNotificationCalls[0];
    createdActionIds.push(captured.action.id);

    assert.strictEqual(captured.action.status, 'proposed');
    assert.strictEqual(captured.action.action_mode, 'shadow');
    assert.strictEqual(captured.action.action_type, 'notify_admin');
    assert.strictEqual(captured.incident.threat_type, 'phishing');
    console.log(`[PASS] Notification hook called with action ID: ${captured.action.id}`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Verify Email Template, Threat Data & Secret Scrubbing
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Email Template Content & Credential Scrubbing ---');
    const shadowEmail = notificationService.formatActionEmail(captured.action, captured.incident, policy);

    // Assert subject includes "simulated"
    assert.ok(
      shadowEmail.subject.toLowerCase().includes('simulated action') ||
      shadowEmail.subject.toLowerCase().includes('simulated'),
      `Expected "simulated" in subject, got: "${shadowEmail.subject}"`
    );
    console.log(`[PASS] Shadow subject contains simulated indicator: "${shadowEmail.subject}"`);

    // Assert body contains threat type and risk score
    assert.ok(
      shadowEmail.text.toLowerCase().includes('phishing'),
      'Expected email body to contain threat type "phishing"'
    );
    assert.ok(
      shadowEmail.text.includes('85'),
      'Expected email body to contain risk score "85"'
    );
    assert.ok(
      shadowEmail.text.includes(captured.incident.id),
      'Expected email body to contain dashboard incident link'
    );
    console.log('[PASS] Email body contains threat_type, risk_score, and dashboard link');

    // Assert body does NOT contain passwords or tokens
    assert.ok(
      !shadowEmail.text.includes('SuperSensitivePassword123!'),
      'Security failure: plain password found in notification text!'
    );
    assert.ok(
      !shadowEmail.text.includes('eySecretJwtToken1234567890'),
      'Security failure: secret token found in notification text!'
    );
    assert.ok(
      !shadowEmail.html.includes('SuperSensitivePassword123!'),
      'Security failure: plain password found in notification HTML!'
    );
    console.log('[PASS] Secret scrubbing verified: passwords and tokens completely absent from email');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Pending Approval Email Format (Approve Button / Link)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Pending Approval Email Template ---');
    const pendingAction = {
      ...captured.action,
      status: 'pending_approval',
      action_mode: 'live'
    };

    const pendingEmail = notificationService.formatActionEmail(pendingAction, captured.incident, policy);
    assert.ok(
      pendingEmail.subject.toLowerCase().includes('approval required'),
      `Expected "approval required" in subject, got: "${pendingEmail.subject}"`
    );
    assert.ok(
      pendingEmail.text.includes(`/admin/actions/${pendingAction.id}/approve`),
      'Expected plain text email to contain action approval link'
    );
    assert.ok(
      pendingEmail.html.includes(`/admin/actions/${pendingAction.id}/approve`),
      'Expected HTML email to contain action approval button/link'
    );
    console.log('[PASS] Pending approval email includes approval button and link');

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: POST /api/v1/admin/actions/:id/approve Endpoint
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Admin Approve Endpoint & Audit Logging ---');
    // Call approval endpoint
    const approveRes = await fetch(`${baseUrl}/admin/actions/${captured.action.id}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ approved: true })
    });

    assert.strictEqual(approveRes.status, 200, `Expected 200 OK, got ${approveRes.status}`);
    const approveJson = await approveRes.json();
    assert.strictEqual(approveJson.success, true);
    assert.strictEqual(approveJson.action.id, captured.action.id);
    assert.strictEqual(approveJson.action.status, 'approved');
    assert.strictEqual(approveJson.action.approved_by_id, admin.id);
    assert.ok(approveJson.action.approved_at, 'Expected approved_at to be populated');
    console.log(`[PASS] Action status updated to 'approved' by admin: ${admin.id}`);

    // Verify audit log entry was created
    const auditRes = await db.query(
      `SELECT * FROM public.audit_logs WHERE resource_id = $1 AND action = 'response_action:approved';`,
      [captured.action.id]
    );
    assert.ok(auditRes.rows.length > 0, 'Expected audit_log entry for response_action:approved');
    const auditEntry = auditRes.rows[0];
    createdAuditLogIds.push(auditEntry.id);
    assert.strictEqual(auditEntry.organization_id, org.id);
    assert.strictEqual(auditEntry.user_id, admin.id);
    assert.strictEqual(auditEntry.actor_type, 'admin');
    console.log(`[PASS] Audit log verified: action=${auditEntry.action}, actor=${auditEntry.actor_type}`);

    // Test rejection flow
    const rejectRes = await fetch(`${baseUrl}/admin/actions/${captured.action.id}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ approved: false })
    });
    assert.strictEqual(rejectRes.status, 200);
    const rejectJson = await rejectRes.json();
    assert.strictEqual(rejectJson.action.status, 'rejected');
    console.log(`[PASS] Action status updated to 'rejected' when approved=false`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 4 PHASE 1C NOTIFICATION & APPROVAL TESTS PASSED! ✓');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    // Restore original method
    notificationService.sendActionNotification = originalSendActionNotification;

    // Teardown
    console.log('--- Teardown: Cleaning up test records ---');
    try {
      if (createdAuditLogIds.length > 0) {
        await db.query(`DELETE FROM public.audit_logs WHERE id = ANY($1::uuid[]);`, [createdAuditLogIds]);
      }
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
    await sleep(200);
  }
}

if (require.main === module) {
  runNotificationsTestSuite()
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      console.error('\n❌ TEST SUITE FAILED:\n', err);
      process.exit(1);
    });
}

module.exports = runNotificationsTestSuite;
