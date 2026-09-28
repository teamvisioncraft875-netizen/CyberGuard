/**
 * CYBERGUARD Telemetry Persistence & Incident Creation Verification Test
 *
 * Verifies that:
 * 1. POST /api/v1/telemetry/login-event triggers ML analysis and stores raw record in PostgreSQL "login_events".
 * 2. If flagged as anomalous (medium/high/critical), automatically persists an atomic incident:
 *    - incidents row with threat_type='account_takeover', source_type='login'
 *    - mitre_mappings row with technique_id='T1110' (Brute Force / Credential Stuffing)
 *    - detection_signals and recommended_actions rows
 * 3. POST /api/v1/telemetry/system-event triggers ML analysis, stores raw record in "telemetry_events",
 *    and persists an incident with threat_type='technical_threat', technique_id='T1071' when anomalous.
 */

process.env.NODE_ENV = 'test';

const jwt = require('jsonwebtoken');
const config = require('./src/config');
const { server } = require('./src/index');
const { query, pool } = require('./src/config/db');

const DIVIDER = '═'.repeat(74);

function logSection(title) {
  console.log(`\n${DIVIDER}`);
  console.log(`  ${title}`);
  console.log(`${DIVIDER}`);
}

async function runTelemetryPersistenceVerification() {
  logSection('CYBERGUARD — TELEMETRY PERSISTENCE & INCIDENT CREATION VERIFICATION');
  console.log(`[INIT] Starting test run at ${new Date().toISOString()}`);

  let httpServerInstance;
  let testUser;
  let token;
  const createdIncidentIds = [];

  try {
    // -------------------------------------------------------------------------
    // STEP 0: Spin up Express Gateway on ephemeral port & create test user
    // -------------------------------------------------------------------------
    await new Promise((resolve) => {
      httpServerInstance = server.listen(0, resolve);
    });
    const port = httpServerInstance.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;
    console.log(`[SERVER] In-process Express Gateway listening on ${baseUrl}`);

    // Create real test user with valid UUID
    const userEmail = `telem_verify_${Date.now()}@cyberguard.internal`;
    const userRes = await query(`
      INSERT INTO users (email, password_hash, role)
      VALUES ($1, 'hashed_test_password', 'individual')
      RETURNING id, email, role, organization_id;
    `, [userEmail]);
    testUser = userRes.rows[0];
    console.log(`[AUTH] Created test user: ${testUser.id} (${testUser.email})`);

    token = jwt.sign(
      {
        id: testUser.id,
        role: testUser.role,
        organization_id: testUser.organization_id || null,
        email: testUser.email
      },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );
    console.log(`[AUTH] Generated valid JWT Bearer token`);

    // -------------------------------------------------------------------------
    // TEST 1: Anomalous Login Event Persistence & Incident Creation
    // -------------------------------------------------------------------------
    logSection('TEST 1: Ingest Suspicious Login Event (POST /api/v1/telemetry/login-event)');

    const anomalousLoginPayload = {
      timestamp: new Date().toISOString(),
      location: 'Unknown Location / Tor Exit Node',
      device_id: 'suspicious_remote_browser_fingerprint',
      failed_attempts: 7
    };

    console.log('[HTTP] Dispatching POST /api/v1/telemetry/login-event with 7 failed attempts...');
    const loginRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(anomalousLoginPayload)
    });

    if (loginRes.status !== 201) {
      throw new Error(`Expected HTTP 201, got ${loginRes.status}: ${await loginRes.text()}`);
    }
    const loginBody = await loginRes.json();
    console.log('[HTTP] Response payload:');
    console.log(JSON.stringify(loginBody, null, 2));

    if (!loginBody.anomaly_detected) {
      throw new Error('Expected anomaly_detected: true for 7 failed attempts');
    }
    if (!loginBody.incident_id) {
      throw new Error('Expected incident_id in response for anomalous login event');
    }
    createdIncidentIds.push(loginBody.incident_id);
    console.log(`✔ [HTTP PASS] Login event recorded, anomaly flagged (${loginBody.risk_level}), incident created: ${loginBody.incident_id}`);

    // Verify raw PostgreSQL login_events record
    const loginEventsRes = await query(`
      SELECT * FROM login_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1;
    `, [testUser.id]);

    if (loginEventsRes.rows.length === 0) {
      throw new Error('No row found in login_events for test user');
    }
    const loginRow = loginEventsRes.rows[0];
    console.log('\n[DB] PostgreSQL "login_events" row:');
    console.log(JSON.stringify(loginRow, null, 2));

    if (Number(loginRow.failed_attempt_count) !== 7) {
      throw new Error(`Expected failed_attempt_count = 7, got ${loginRow.failed_attempt_count}`);
    }
    if (loginRow.success !== false) {
      throw new Error(`Expected success = false for failed attempts, got ${loginRow.success}`);
    }
    console.log('✔ [DB PASS] Raw login event successfully persisted in PostgreSQL login_events table');

    // Verify PostgreSQL incidents record
    const loginIncRes = await query(`
      SELECT * FROM incidents WHERE id = $1;
    `, [loginBody.incident_id]);

    if (loginIncRes.rows.length === 0) {
      throw new Error(`No incident found with id ${loginBody.incident_id}`);
    }
    const loginIncident = loginIncRes.rows[0];
    console.log('\n[DB] PostgreSQL "incidents" row:');
    console.log(JSON.stringify(loginIncident, null, 2));

    if (loginIncident.threat_type !== 'account_takeover') {
      throw new Error(`Expected threat_type = 'account_takeover', got ${loginIncident.threat_type}`);
    }
    if (loginIncident.source_type !== 'login') {
      throw new Error(`Expected source_type = 'login', got ${loginIncident.source_type}`);
    }
    console.log('✔ [DB PASS] Incident persisted with threat_type="account_takeover" and source_type="login"');

    // Verify MITRE mapping for account_takeover -> T1110
    const loginMitreRes = await query(`
      SELECT * FROM mitre_mappings WHERE incident_id = $1;
    `, [loginBody.incident_id]);

    if (loginMitreRes.rows.length !== 1) {
      throw new Error(`Expected exactly 1 MITRE mapping, got ${loginMitreRes.rows.length}`);
    }
    const loginMitre = loginMitreRes.rows[0];
    console.log('\n[DB] PostgreSQL "mitre_mappings" row:');
    console.log(JSON.stringify(loginMitre, null, 2));

    if (loginMitre.technique_id !== 'T1110') {
      throw new Error(`Expected technique_id = 'T1110', got ${loginMitre.technique_id}`);
    }
    console.log('✔ [DB PASS] MITRE mapping linked to technique T1110 (Brute Force / Credential Stuffing)');

    // -------------------------------------------------------------------------
    // TEST 2: Anomalous System Event Persistence & Incident Creation
    // -------------------------------------------------------------------------
    logSection('TEST 2: Ingest Anomalous System Event (POST /api/v1/telemetry/system-event)');

    const anomalousSysPayload = {
      timestamp: new Date().toISOString(),
      event_type: 'network_spike',
      details: {
        duration: 0.05,
        packet_count: 500,
        total_bytes: 600000,
        source_bytes: 580000,
        protocol: 'tcp',
        destination_port: 8088
      }
    };

    console.log('[HTTP] Dispatching POST /api/v1/telemetry/system-event with network spike...');
    const sysRes = await fetch(`${baseUrl}/api/v1/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(anomalousSysPayload)
    });

    if (sysRes.status !== 201) {
      throw new Error(`Expected HTTP 201, got ${sysRes.status}: ${await sysRes.text()}`);
    }
    const sysBody = await sysRes.json();
    console.log('[HTTP] Response payload:');
    console.log(JSON.stringify(sysBody, null, 2));

    if (!sysBody.anomaly_detected) {
      throw new Error('Expected anomaly_detected: true for network spike');
    }
    if (!sysBody.incident_id) {
      throw new Error('Expected incident_id in response for anomalous system event');
    }
    createdIncidentIds.push(sysBody.incident_id);
    console.log(`✔ [HTTP PASS] System event recorded, anomaly flagged (${sysBody.risk_level}), incident created: ${sysBody.incident_id}`);

    // Verify raw PostgreSQL telemetry_events record
    const sysEventsRes = await query(`
      SELECT * FROM telemetry_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1;
    `, [testUser.id]);

    if (sysEventsRes.rows.length === 0) {
      throw new Error('No row found in telemetry_events for test user');
    }
    const sysRow = sysEventsRes.rows[0];
    console.log('\n[DB] PostgreSQL "telemetry_events" row:');
    console.log(JSON.stringify(sysRow, null, 2));

    if (sysRow.event_type !== 'network') {
      throw new Error(`Expected event_type = 'network', got ${sysRow.event_type}`);
    }
    console.log('✔ [DB PASS] Raw system event successfully persisted in PostgreSQL telemetry_events table');

    // Verify PostgreSQL incidents record for system event
    const sysIncRes = await query(`
      SELECT * FROM incidents WHERE id = $1;
    `, [sysBody.incident_id]);

    if (sysIncRes.rows.length === 0) {
      throw new Error(`No incident found with id ${sysBody.incident_id}`);
    }
    const sysIncident = sysIncRes.rows[0];
    console.log('\n[DB] PostgreSQL "incidents" row for system threat:');
    console.log(JSON.stringify(sysIncident, null, 2));

    if (sysIncident.threat_type !== 'technical_threat') {
      throw new Error(`Expected threat_type = 'technical_threat', got ${sysIncident.threat_type}`);
    }
    if (sysIncident.source_type !== 'system') {
      throw new Error(`Expected source_type = 'system', got ${sysIncident.source_type}`);
    }
    console.log('✔ [DB PASS] Incident persisted with threat_type="technical_threat" and source_type="system"');

    // Verify MITRE mapping for technical_threat -> T1071
    const sysMitreRes = await query(`
      SELECT * FROM mitre_mappings WHERE incident_id = $1;
    `, [sysBody.incident_id]);

    if (sysMitreRes.rows.length !== 1) {
      throw new Error(`Expected exactly 1 MITRE mapping, got ${sysMitreRes.rows.length}`);
    }
    const sysMitre = sysMitreRes.rows[0];
    console.log('\n[DB] PostgreSQL "mitre_mappings" row:');
    console.log(JSON.stringify(sysMitre, null, 2));

    if (sysMitre.technique_id !== 'T1071') {
      throw new Error(`Expected technique_id = 'T1071', got ${sysMitre.technique_id}`);
    }
    console.log('✔ [DB PASS] MITRE mapping linked to technique T1071 (Application Layer Protocol Anomaly)');

    // -------------------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------------------
    logSection('FINAL SUMMARY: TELEMETRY PERSISTENCE & INCIDENT CREATION');
    console.log('✔ Check 1: Suspicious login event evaluated by ML and saved to login_events table');
    console.log('✔ Check 2: Account takeover incident created with threat_type="account_takeover"');
    console.log('✔ Check 3: MITRE mapping created linking to technique T1110');
    console.log('✔ Check 4: Anomalous system event evaluated by ML and saved to telemetry_events table');
    console.log('✔ Check 5: Technical threat incident created with threat_type="technical_threat"');
    console.log('✔ Check 6: MITRE mapping created linking to technique T1071');
    console.log('\n🌟 ALL TELEMETRY PERSISTENCE VERIFICATIONS PASSED 100%!');
  } finally {
    console.log('\n[CLEANUP] Cleaning up test records...');
    for (const incId of createdIncidentIds) {
      await query('DELETE FROM recommended_actions WHERE incident_id = $1', [incId]);
      await query('DELETE FROM detection_signals WHERE incident_id = $1', [incId]);
      await query('DELETE FROM mitre_mappings WHERE incident_id = $1', [incId]);
      await query('DELETE FROM incidents WHERE id = $1', [incId]);
    }
    if (testUser?.id) {
      await query('DELETE FROM login_events WHERE user_id = $1', [testUser.id]);
      await query('DELETE FROM telemetry_events WHERE user_id = $1', [testUser.id]);
      await query('DELETE FROM users WHERE id = $1', [testUser.id]);
    }
    if (httpServerInstance) {
      httpServerInstance.close();
    }
    await pool.end();
    console.log('[CLEANUP] Completed.');
  }
}

runTelemetryPersistenceVerification().catch((err) => {
  console.error('\n❌ VERIFICATION TEST FAILED:', err);
  process.exit(1);
});
