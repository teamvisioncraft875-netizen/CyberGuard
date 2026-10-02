process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { app } = require('./src');
const db = require('./src/config/db');
const { detectSecrets, SECRET_PATTERNS } = require('./src/services/secretDetector');
const PolicyEngine = require('./src/services/PolicyEngine');
const ResponseAction = require('./src/models/ResponseAction');
const Incident = require('./src/models/Incident');
const AuditLog = require('./src/models/AuditLog');
const notificationService = require('./src/services/notificationService');

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

async function runSecretDetectionTestSuite() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — SECRET & CREDENTIAL EXPOSURE DETECTION TEST SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdOrgIds = [];
  const createdUserIds = [];
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
    // Unit Tests: Pattern & Severity Detection
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Unit Test 1: detectSecrets("AWS_KEY=AKIAIOSFODNN7EXAMPLE") returns critical severity ---');
    const awsKeySecrets = detectSecrets('AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    assert(Array.isArray(awsKeySecrets), 'Expected an array of detected secrets');
    assert.strictEqual(awsKeySecrets.length, 1, 'Expected 1 secret detected');
    assert.strictEqual(awsKeySecrets[0].secret_type, 'AWS_KEY');
    assert.strictEqual(awsKeySecrets[0].severity, 'critical');
    assert.strictEqual(awsKeySecrets[0].score, 95);
    assert(awsKeySecrets[0].location.includes('line 1'), 'Expected location with line 1');
    assert(!awsKeySecrets[0].excerpt.includes('AKIAIOSFODNN7EXAMPLE'), 'Excerpt must NOT contain raw secret');
    console.log('✔ Passed: AWS_KEY returns critical severity with redacted excerpt:', awsKeySecrets[0].excerpt);

    console.log('\n--- Unit Test 2: detectSecrets("DATABASE_PASSWORD=mysecret123") returns critical severity ---');
    const dbPassSecrets = detectSecrets('DATABASE_PASSWORD=mysecret123');
    assert(Array.isArray(dbPassSecrets), 'Expected an array of detected secrets');
    assert.strictEqual(dbPassSecrets.length, 1, 'Expected 1 secret detected');
    assert.strictEqual(dbPassSecrets[0].secret_type, 'DATABASE_PASSWORD');
    assert.strictEqual(dbPassSecrets[0].severity, 'critical');
    assert.strictEqual(dbPassSecrets[0].score, 95);
    assert(!dbPassSecrets[0].excerpt.includes('mysecret123'), 'Excerpt must NOT contain raw secret');
    console.log('✔ Passed: DATABASE_PASSWORD returns critical severity with redacted excerpt:', dbPassSecrets[0].excerpt);

    console.log('\n--- Unit Test 3: detectSecrets("normal string with no secrets") returns empty array ---');
    const cleanSecrets = detectSecrets('normal string with no secrets in standard business communication');
    assert(Array.isArray(cleanSecrets), 'Expected an array');
    assert.strictEqual(cleanSecrets.length, 0, 'Expected 0 secrets detected');
    console.log('✔ Passed: Clean string returns empty array');

    console.log('\n--- Unit Test 4: Pattern Catalog Comprehensive Coverage ---');
    const testCases = [
      { input: 'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', expectedType: 'AWS_SECRET', expectedSev: 'critical' },
      { input: 'DATABASE_URL=postgres://app_user:s3cr3tP@ssw0rd@db.internal.net:5432/production', expectedType: 'DATABASE_URL', expectedSev: 'critical' },
      { input: 'MONGODB_URI=mongodb+srv://admin:clust3rp@ss@cluster0.mongodb.net/test', expectedType: 'MONGODB_URI', expectedSev: 'critical' },
      { input: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----', expectedType: 'RSA_PRIVATE_KEY', expectedSev: 'critical' },
      { input: '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----', expectedType: 'SSH_PRIVATE_KEY', expectedSev: 'critical' },
      { input: 'GITHUB_TOKEN=ghp_ABC1234567890abcdefghijklmnopqrstuv', expectedType: 'GITHUB_TOKEN', expectedSev: 'high' },
      { input: 'STRIPE_KEY=sk_live_51Abcdefghijklmnopqrstuvwx1234567890', expectedType: 'STRIPE_KEY', expectedSev: 'high' },
      { input: 'SLACK_TOKEN=xoxb-123456789012-1234567890123-456789abcdefABCDEF', expectedType: 'SLACK_TOKEN', expectedSev: 'high' },
      { input: 'JWT_SECRET=super_secret_jwt_signing_key_never_share', expectedType: 'JWT_SECRET', expectedSev: 'high' },
      { input: 'API_TOKEN=api_token_very_secret_xyz123abc456def789', expectedType: 'API_TOKEN', expectedSev: 'high' }
    ];

    for (const tc of testCases) {
      const results = detectSecrets(tc.input);
      assert(results.length > 0, `Expected detection for ${tc.expectedType}`);
      const found = results.find((r) => r.secret_type === tc.expectedType);
      assert(found, `Expected ${tc.expectedType} in detections`);
      assert.strictEqual(found.severity, tc.expectedSev);
      console.log(`  ✔ Catalog match: ${found.secret_type} -> severity=${found.severity}, score=${found.score}`);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Integration Setup: Two Organizations & Admins
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Setup: Seed Two Separate Organizations and Admin Users ---');
    const passwordHash = await bcrypt.hash(rawAdminPassword, 10);

    const org1Res = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`Org 1 Secret Test ${timestamp}`]);
    const org1 = org1Res.rows[0];
    createdOrgIds.push(org1.id);

    const admin1Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id) VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin1_secret_${timestamp}@cyberguard.internal`, passwordHash, org1.id]
    );
    const admin1 = admin1Res.rows[0];
    createdUserIds.push(admin1.id);
    const admin1Token = createToken(admin1);

    const org2Res = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`Org 2 Secret Test ${timestamp}`]);
    const org2 = org2Res.rows[0];
    createdOrgIds.push(org2.id);

    const admin2Res = await db.query(
      `INSERT INTO public.users (email, password_hash, role, organization_id) VALUES ($1, $2, 'admin', $3) RETURNING *;`,
      [`admin2_secret_${timestamp}@cyberguard.internal`, passwordHash, org2.id]
    );
    const admin2 = admin2Res.rows[0];
    createdUserIds.push(admin2.id);
    const admin2Token = createToken(admin2);

    console.log(`[SETUP] Org1 (${org1.name}) Admin: ${admin1.email}`);
    console.log(`[SETUP] Org2 (${org2.name}) Admin: ${admin2.email}`);

    // Mock notification hook
    notificationService.sendActionNotification = async (action, incident, policy) => {
      capturedNotificationCalls.push({ action, incident, policy });
      return originalSendActionNotification(action, incident, policy);
    };

    // ──────────────────────────────────────────────────────────────────────────
    // Integration Test: POST /api/v1/check/secret
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: POST /check/secret with exposed AWS key creates incident & does NOT return raw secret ---');
    const rawSecretValue = 'AKIAIOSFODNN7EXAMPLE';
    const postPayload = {
      input: `export AWS_ACCESS_KEY_ID=${rawSecretValue}\nexport DB_NAME=testdb`,
      context: 'Developer committed test env file'
    };

    const checkRes = await fetch(`${baseUrl}/check/secret`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      },
      body: JSON.stringify(postPayload)
    });

    assert.strictEqual(checkRes.status, 200, `Expected 200 OK, got ${checkRes.status}`);
    const checkBody = await checkRes.json();
    const rawResponseText = JSON.stringify(checkBody);

    assert.strictEqual(checkBody.risk_level, 'critical', 'Expected risk_level to be critical');
    assert.strictEqual(checkBody.risk_score, 95, 'Expected risk_score to be 95');
    assert(checkBody.signals.secret_types.includes('AWS_KEY'), 'Signals must include AWS_KEY');
    assert(checkBody.detected_secrets.some((s) => s.secret_type === 'AWS_KEY' && s.severity === 'critical'), 'Detected secrets must include AWS_KEY');

    // CRITICAL GUARDRAIL: Raw secret value MUST NOT be present anywhere in the HTTP response JSON
    assert(!rawResponseText.includes(rawSecretValue), 'Response MUST NOT contain the raw secret value!');
    console.log('✔ Passed: Response risk_level=critical, signals contain AWS_KEY');
    console.log('✔ Passed: Response string thoroughly inspected — raw secret value is completely absent');

    const incidentId = checkBody.id;
    assert(incidentId, 'Expected an incident ID to be returned');
    createdIncidentIds.push(incidentId);

    // ──────────────────────────────────────────────────────────────────────────
    // Policy Engine & Notification Verification
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Policy Engine triggers response_action & notification has "Exposed Secret" subject ---');
    const actionRecords = await waitFor(async () => {
      const res = await ResponseAction.list({ organization_id: org1.id, incident_id: incidentId });
      if (res.actions && res.actions.length >= 2) return res.actions;
      return null;
    }, 4000, 100);

    assert(actionRecords && actionRecords.length >= 2, 'Expected PolicyEngine to create notify_admin and notify_user actions');
    for (const a of actionRecords) {
      createdActionIds.push(a.id);
    }

    const adminAction = actionRecords.find((a) => a.action_type === 'notify_admin');
    const userAction = actionRecords.find((a) => a.action_type === 'notify_user');

    assert(adminAction, 'Expected notify_admin action');
    assert.strictEqual(adminAction.action_mode, 'shadow', 'Action must be in shadow mode');
    console.log(`✔ Passed: Policy engine created shadow action: ${adminAction.action_type} (mode=${adminAction.action_mode})`);

    assert(userAction, 'Expected notify_user action since score >= 85');
    assert.strictEqual(userAction.action_mode, 'shadow', 'Action must be in shadow mode');
    console.log(`✔ Passed: Policy engine created shadow action: ${userAction.action_type} (mode=${userAction.action_mode})`);

    // Verify email notification subject
    const capturedNotif = await waitFor(() => {
      return capturedNotificationCalls.find((call) => call.incident.id === incidentId);
    }, 4000, 100);

    assert(capturedNotif, 'Expected notification to be triggered for the incident');
    const { formatActionEmail } = notificationService;
    const formattedEmail = formatActionEmail(capturedNotif.action, capturedNotif.incident, capturedNotif.policy);
    console.log(`[NOTIF SUBJECT] "${formattedEmail.subject}"`);
    assert(formattedEmail.subject.includes('Exposed Secret'), 'Notification subject MUST include "Exposed Secret"');
    console.log('✔ Passed: Email notification subject includes "Exposed Secret"');

    // ──────────────────────────────────────────────────────────────────────────
    // Multi-Tenant Isolation: Admin 1 vs Admin 2
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 7: Tenant Isolation — admin1 sees incident, admin2 does NOT ---');
    const admin1GetRes = await fetch(`${baseUrl}/incidents/${incidentId}`, {
      headers: { Authorization: `Bearer ${admin1Token}` }
    });
    assert.strictEqual(admin1GetRes.status, 200, `Admin 1 should fetch incident (got ${admin1GetRes.status})`);
    const admin1Incident = await admin1GetRes.json();
    assert.strictEqual(admin1Incident.id, incidentId);
    assert.strictEqual(admin1Incident.threat_type, 'exposed_secret');
    console.log('✔ Passed: admin1 successfully retrieved incident within their organization');

    const admin2GetRes = await fetch(`${baseUrl}/incidents/${incidentId}`, {
      headers: { Authorization: `Bearer ${admin2Token}` }
    });
    assert.strictEqual(admin2GetRes.status, 404, `Admin 2 from different org must receive 404 (got ${admin2GetRes.status})`);
    console.log('✔ Passed: admin2 received 404 Not Found due to strict tenant isolation');

    // ──────────────────────────────────────────────────────────────────────────
    // Telemetry Pipeline Integration Test
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 8: Telemetry ingestion detects exposed secrets in environment_variables and writes audit log ---');
    const telemetryPayload = {
      timestamp: new Date().toISOString(),
      event_type: 'environment_variables',
      telemetry_type: 'environment_variables',
      details: {
        raw_env: 'NODE_ENV=production\nSTRIPE_KEY=sk_live_51SecretStripeKeyLive123456789\nPORT=3000'
      }
    };

    const telemetryRes = await fetch(`${baseUrl}/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${admin1Token}`
      },
      body: JSON.stringify(telemetryPayload)
    });

    assert.strictEqual(telemetryRes.status, 201, `Telemetry ingestion expected 201 Created (got ${telemetryRes.status})`);
    const telemetryBody = await telemetryRes.json();
    assert.strictEqual(telemetryBody.anomaly_detected, true);
    assert(telemetryBody.incident_id, 'Expected incident_id in telemetry response');

    // Check that telemetry incident was created
    const telemetryIncident = await waitFor(async () => {
      const incs = await Incident.findAll({
        organization_id: org1.id,
        category: 'exposed_secret'
      });
      const found = incs.find((i) => i.source_type === 'telemetry');
      return found || null;
    }, 4000, 100);

    assert(telemetryIncident, 'Expected telemetry incident to be created with threat_type exposed_secret');
    createdIncidentIds.push(telemetryIncident.id);
    console.log(`✔ Passed: Telemetry incident created with id: ${telemetryIncident.id}`);

    // Verify audit log entry
    const auditEntry = await waitFor(async () => {
      const res = await AuditLog.list({ organization_id: org1.id });
      return res.logs.find((l) => l.action === 'telemetry:secret_exposure_detected');
    }, 4000, 100);

    assert(auditEntry, 'Expected audit log entry for telemetry secret exposure');
    createdAuditLogIds.push(auditEntry.id);
    assert.strictEqual(auditEntry.action, 'telemetry:secret_exposure_detected');
    assert.strictEqual(auditEntry.details?.message, 'Secret exposure detected in system telemetry');
    assert(!JSON.stringify(auditEntry.details).includes('sk_live_51SecretStripeKeyLive123456789'), 'Audit log MUST NOT contain the raw secret!');
    console.log('✔ Passed: Audit log written: "Secret exposure detected in system telemetry" without raw secret leakage');

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL SECRET DETECTION TESTS PASSED (8/8)');
    console.log('════════════════════════════════════════════════════════════════════════\n');
  } finally {
    // Restore notificationService mock
    notificationService.sendActionNotification = originalSendActionNotification;

    // Teardown HTTP server
    if (server) {
      server.close();
    }

    // Teardown created DB test records
    console.log('\n--- Teardown: Cleaning seeded test data ---');
    try {
      for (const id of createdActionIds) {
        await db.query(`DELETE FROM public.response_actions WHERE id = $1;`, [id]);
      }
      for (const id of createdAuditLogIds) {
        await db.query(`DELETE FROM public.audit_logs WHERE id = $1;`, [id]);
      }
      for (const id of createdIncidentIds) {
        await db.query(`DELETE FROM public.response_actions WHERE incident_id = $1;`, [id]);
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = $1;`, [id]);
        await db.query(`DELETE FROM public.incident_evidence WHERE incident_id = $1;`, [id]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = $1;`, [id]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = $1;`, [id]);
        await db.query(`DELETE FROM public.incidents WHERE id = $1;`, [id]);
      }
      for (const id of createdUserIds) {
        await db.query(`DELETE FROM public.users WHERE id = $1;`, [id]);
      }
      for (const id of createdOrgIds) {
        await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [id]);
      }
      console.log('✔ Cleanup complete.');
    } catch (cleanupErr) {
      console.error('[CLEANUP ERROR]', cleanupErr.message);
    }
  }
}

runSecretDetectionTestSuite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\n✖ TEST SUITE FAILED:', err);
    process.exit(1);
  });
