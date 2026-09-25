/**
 * CYBERGUARD End-to-End MITRE ATT&CK Integration Verification Test
 *
 * Verifies that:
 * 1. POST /api/v1/check/message triggers real ML inference and creates an incident record.
 * 2. An incident row is persisted in PostgreSQL "incidents" within an atomic transaction.
 * 3. Exactly one "mitre_mappings" row is created linking the incident to its MITRE technique.
 * 4. GET /api/v1/analytics/mitre returns real-time aggregated metrics reflecting the new incident.
 * 5. Rollback works atomically: simulated failure in MITRE persistence rolls back the entire
 *    transaction leaving zero orphaned incidents, detection signals, or recommended actions.
 * 6. Centralized mapping covers 100% of all supported threat types in the taxonomy.
 * 7. Zero duplicate MITRE records are created across the pipeline.
 */

process.env.NODE_ENV = 'test';

const jwt = require('jsonwebtoken');
const config = require('./src/config');
const { server } = require('./src/index');
const { query, pool } = require('./src/config/db');
const MitreMapping = require('./src/models/MitreMapping');

// Formatting & Presentation Helpers
const DIVIDER = '═'.repeat(74);
const SUB_DIVIDER = '─'.repeat(74);

function logSection(title) {
  console.log(`\n${DIVIDER}`);
  console.log(`  ${title}`);
  console.log(`${DIVIDER}`);
}

async function runMitreIntegrationVerification() {
  logSection('CYBERGUARD — MITRE ATT&CK INTEGRATION VERIFICATION');
  console.log(`[INIT] Starting end-to-end verification run at ${new Date().toISOString()}`);

  let httpServerInstance;
  let testUser;
  let createdIncidentId;
  const checks = [];

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

    // Create a real, isolated test user in PostgreSQL
    const uniqueUserEmail = `mitre_test_${Date.now()}@cyberguard.internal`;
    const userRes = await query(`
      INSERT INTO users (email, password_hash, role)
      VALUES ($1, 'hashed_test_password', 'individual')
      RETURNING id, email, role, organization_id;
    `, [uniqueUserEmail]);
    testUser = userRes.rows[0];
    console.log(`[AUTH] Created dedicated test user: ${testUser.id} (${testUser.email})`);

    // Generate authenticated JWT session token
    const token = jwt.sign(
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
    // STEP 1: Create real phishing incident via POST /api/v1/check/message
    // -------------------------------------------------------------------------
    logSection('STEP 1: Ingest Threat Message via Detection Pipeline');
    console.log(`[HTTP] Dispatching POST /api/v1/check/message to real ML service & DB pipeline...`);

    const phishingPayload = {
      text: 'URGENT: Your account has been suspended due to unauthorized access. Click here immediately to verify: https://secure-account-verification.xyz/login',
      source_type: 'email'
    };

    const checkRes = await fetch(`${baseUrl}/api/v1/check/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(phishingPayload)
    });

    const checkBody = await checkRes.json();
    console.log(`[HTTP] Status Code : ${checkRes.status}`);
    console.log(`[HTTP] Response Body:\n${JSON.stringify(checkBody, null, 2)}`);

    createdIncidentId = checkBody.id;
    const step1Passed = checkRes.status === 200 && typeof createdIncidentId === 'string' && createdIncidentId.length > 0;
    console.log(`\n${step1Passed ? '✔' : '✖'} STEP 1 VERDICT: ${step1Passed ? 'Incident created successfully' : 'Failed to create incident'}`);

    // -------------------------------------------------------------------------
    // STEP 2: Query PostgreSQL directly for incidents row
    // -------------------------------------------------------------------------
    logSection('STEP 2: Verify PostgreSQL "incidents" Row Persistence');
    console.log(`[DB] Querying "incidents" table directly for ID: ${createdIncidentId}`);

    const incidentQuery = await query('SELECT * FROM incidents WHERE id = $1;', [createdIncidentId]);
    const incidentRow = incidentQuery.rows[0];

    if (incidentRow) {
      console.log(`[DB] Incident record retrieved from PostgreSQL:`);
      console.log(`     id          : ${incidentRow.id}`);
      console.log(`     threat_type : ${incidentRow.threat_type}`);
      console.log(`     source_type : ${incidentRow.source_type}`);
      console.log(`     risk_level  : ${incidentRow.risk_level}`);
      console.log(`     risk_score  : ${incidentRow.risk_score}`);
      console.log(`     status      : ${incidentRow.status}`);
    } else {
      console.log(`✖ [DB] Incident row not found in database!`);
    }

    const step2Passed = Boolean(
      incidentRow &&
      incidentRow.id === createdIncidentId &&
      incidentRow.threat_type === 'phishing'
    );
    console.log(`\n${step2Passed ? '✔' : '✖'} STEP 2 VERDICT: ${step2Passed ? 'Incident persisted with threat_type=phishing' : 'Incident verification failed'}`);

    // -------------------------------------------------------------------------
    // STEP 3: Query PostgreSQL mitre_mappings for the incident
    // -------------------------------------------------------------------------
    logSection('STEP 3: Verify PostgreSQL "mitre_mappings" Record');
    console.log(`[DB] Querying "mitre_mappings" table directly for incident_id: ${createdIncidentId}`);

    const mitreQuery = await query('SELECT * FROM mitre_mappings WHERE incident_id = $1;', [createdIncidentId]);
    const mitreRows = mitreQuery.rows;

    console.log(`[DB] Mapping rows returned: ${mitreRows.length}`);
    for (const [idx, row] of mitreRows.entries()) {
      console.log(`[DB] Mapping #${idx + 1}:`);
      console.log(`     mapping id     : ${row.id}`);
      console.log(`     incident_id    : ${row.incident_id}`);
      console.log(`     technique_id   : ${row.technique_id}`);
      console.log(`     technique_name : ${row.technique_name}`);
    }

    const exactlyOneMapping = mitreRows.length === 1;
    const correctMapping = exactlyOneMapping &&
      mitreRows[0].technique_id === 'T1566' &&
      mitreRows[0].technique_name === 'Phishing';

    console.log(`\n${exactlyOneMapping ? '✔' : '✖'} Cardinality Check : Exactly one mapping row exists (${mitreRows.length} found)`);
    console.log(`${correctMapping ? '✔' : '✖'} Taxonomy Check    : threat_type=phishing -> technique_id=T1566, technique_name="Phishing"`);

    // -------------------------------------------------------------------------
    // STEP 4: Call GET /api/v1/analytics/mitre & Verify Aggregation
    // -------------------------------------------------------------------------
    logSection('STEP 4: Call GET /api/v1/analytics/mitre Endpoint');
    console.log(`[HTTP] Dispatching GET /api/v1/analytics/mitre...`);

    const analyticsRes = await fetch(`${baseUrl}/api/v1/analytics/mitre`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const analyticsBody = await analyticsRes.json();
    console.log(`[HTTP] Status Code: ${analyticsRes.status}`);
    console.log(`[HTTP] Analytics Payload:\n${JSON.stringify(analyticsBody, null, 2)}`);

    const phishingAggregate = Array.isArray(analyticsBody)
      ? analyticsBody.find((item) => item.technique_id === 'T1566')
      : null;

    const step4Passed = analyticsRes.status === 200 &&
      phishingAggregate !== null &&
      phishingAggregate.technique_name === 'Phishing' &&
      parseInt(phishingAggregate.incident_count, 10) >= 1;

    console.log(`\n${step4Passed ? '✔' : '✖'} STEP 4 VERDICT: ${step4Passed ? 'Analytics returned aggregated MITRE technique T1566 with incident_count >= 1' : 'MITRE analytics aggregation failed'}`);

    // -------------------------------------------------------------------------
    // STEP 5: Rollback Verification (Forced Failure in MITRE Insert)
    // -------------------------------------------------------------------------
    logSection('STEP 5: Transaction Rollback Verification on MITRE Failure');
    console.log(`[ROLLBACK] Testing all-or-nothing atomicity. If MITRE persistence fails,`);
    console.log(`           incidents, detection_signals, recommended_actions must all roll back.\n`);

    // Baseline database counts
    const countQuery = async () => ({
      incidents: parseInt((await query('SELECT COUNT(*)::int FROM incidents;')).rows[0].count, 10),
      mitre: parseInt((await query('SELECT COUNT(*)::int FROM mitre_mappings;')).rows[0].count, 10),
      signals: parseInt((await query('SELECT COUNT(*)::int FROM detection_signals;')).rows[0].count, 10),
      actions: parseInt((await query('SELECT COUNT(*)::int FROM recommended_actions;')).rows[0].count, 10),
    });

    const beforeCounts = await countQuery();
    console.log(`[DB] Row counts BEFORE forced failure:`);
    console.log(`     incidents           : ${beforeCounts.incidents}`);
    console.log(`     mitre_mappings      : ${beforeCounts.mitre}`);
    console.log(`     detection_signals   : ${beforeCounts.signals}`);
    console.log(`     recommended_actions : ${beforeCounts.actions}`);

    // Temporarily monkey-patch MitreMapping.create to simulate database failure
    const originalMitreCreate = MitreMapping.create;
    MitreMapping.create = async function () {
      console.log(`  [SIMULATION] Triggering SIMULATED_MITRE_DATABASE_FAILURE inside transaction block...`);
      throw new Error('SIMULATED_MITRE_DATABASE_FAILURE');
    };

    let rollbackStatus = null;
    let rollbackBody = null;
    try {
      const rollbackRes = await fetch(`${baseUrl}/api/v1/check/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          text: 'Security notification: Suspicious session detected from external host.',
          source_type: 'email'
        })
      });
      rollbackStatus = rollbackRes.status;
      rollbackBody = await rollbackRes.json();
    } finally {
      // Always restore original method immediately
      MitreMapping.create = originalMitreCreate;
    }

    console.log(`\n[HTTP] Status during forced failure : ${rollbackStatus} (Expected: 500)`);
    console.log(`[HTTP] Response payload               : ${JSON.stringify(rollbackBody)}`);

    const afterCounts = await countQuery();
    console.log(`\n[DB] Row counts AFTER forced failure:`);
    console.log(`     incidents           : ${afterCounts.incidents}`);
    console.log(`     mitre_mappings      : ${afterCounts.mitre}`);
    console.log(`     detection_signals   : ${afterCounts.signals}`);
    console.log(`     recommended_actions : ${afterCounts.actions}`);

    const deltas = {
      incidents: afterCounts.incidents - beforeCounts.incidents,
      mitre: afterCounts.mitre - beforeCounts.mitre,
      signals: afterCounts.signals - beforeCounts.signals,
      actions: afterCounts.actions - beforeCounts.actions
    };

    console.log(`\n[DB] Database Row Deltas (All must be 0):`);
    console.log(`     Δ incidents           : ${deltas.incidents}`);
    console.log(`     Δ mitre_mappings      : ${deltas.mitre}`);
    console.log(`     Δ detection_signals   : ${deltas.signals}`);
    console.log(`     Δ recommended_actions : ${deltas.actions}`);

    const step5Passed = rollbackStatus === 500 &&
      deltas.incidents === 0 &&
      deltas.mitre === 0 &&
      deltas.signals === 0 &&
      deltas.actions === 0;

    console.log(`\n${step5Passed ? '✔' : '✖'} STEP 5 VERDICT: ${step5Passed ? 'Transaction rolled back completely with zero orphaned records' : 'Rollback verification failed'}`);

    // -------------------------------------------------------------------------
    // STEP 6: Threat Mapping Coverage Audit
    // -------------------------------------------------------------------------
    logSection('STEP 6: Threat Mapping Coverage Audit');
    console.log(`[TAXONOMY] Inspecting MitreMapping.THREAT_TO_MITRE registry...`);

    const requiredThreatTypes = [
      'phishing',
      'deepfake',
      'impersonation',
      'account_takeover',
      'malicious_url',
      'technical_threat'
    ];

    const tableRows = [];
    let allThreatTypesCovered = true;

    for (const threatType of requiredThreatTypes) {
      const mapping = MitreMapping.THREAT_TO_MITRE[threatType];
      const hasMapping = Boolean(mapping && mapping.technique_id && mapping.technique_name);
      if (!hasMapping) allThreatTypesCovered = false;

      tableRows.push({
        'Threat Type': threatType,
        'Technique ID': mapping?.technique_id || 'MISSING',
        'Technique Name': mapping?.technique_name || 'MISSING'
      });
    }

    console.log('\nSupported Threat Taxonomy Table:');
    console.table(tableRows);

    const step6Passed = allThreatTypesCovered && Object.keys(MitreMapping.THREAT_TO_MITRE).length >= requiredThreatTypes.length;
    console.log(`${step6Passed ? '✔' : '✖'} STEP 6 VERDICT: ${step6Passed ? '100% of supported threat types are mapped to MITRE ATT&CK techniques' : 'Coverage audit failed'}`);

    // -------------------------------------------------------------------------
    // FINAL SUMMARY: Compile all 7 PASS/FAIL checks
    // -------------------------------------------------------------------------
    logSection('FINAL SUMMARY: MITRE ATT&CK Integration Verification');

    checks.push(
      {
        name: 'Incident persisted successfully',
        proof: `Incident row ID ${createdIncidentId} created via /api/v1/check/message and verified in PostgreSQL`,
        pass: step1Passed && step2Passed
      },
      {
        name: 'MITRE mapping persisted successfully',
        proof: `Mapping row ID ${mitreRows[0]?.id} recorded in mitre_mappings table inside atomic transaction`,
        pass: exactlyOneMapping
      },
      {
        name: 'Correct phishing→T1566 mapping',
        proof: `phishing resolved to technique_id="T1566" and technique_name="Phishing"`,
        pass: correctMapping
      },
      {
        name: 'Analytics endpoint returns aggregated MITRE results',
        proof: `GET /api/v1/analytics/mitre returned T1566 aggregate with count=${phishingAggregate?.incident_count}`,
        pass: step4Passed
      },
      {
        name: 'Transaction rollback works correctly',
        proof: `Forced failure returned 500 and all database row deltas remained 0 (incidents, mitre, signals, actions)`,
        pass: step5Passed
      },
      {
        name: 'All supported threat types mapped',
        proof: `All 6 required threat types (phishing, deepfake, impersonation, account_takeover, malicious_url, technical_threat) mapped (100% coverage)`,
        pass: step6Passed
      },
      {
        name: 'No duplicate mapping rows created',
        proof: `Single mapping row found for incident ${createdIncidentId} (count = ${mitreRows.length})`,
        pass: mitreRows.length === 1
      }
    );

    console.log(SUB_DIVIDER);
    let allPassed = true;
    for (const [index, check] of checks.entries()) {
      const statusIcon = check.pass ? '✔ PASS' : '✖ FAIL';
      if (!check.pass) allPassed = false;
      console.log(`[${statusIcon}] Check ${index + 1}: ${check.name}`);
      console.log(`       Proof: ${check.proof}`);
    }
    console.log(SUB_DIVIDER);

    if (allPassed) {
      console.log('\n🌟 ALL MITRE INTEGRATION VERIFICATIONS PASSED');
      console.log('   Every incident created automatically generates a valid MITRE ATT&CK mapping with full transaction atomicity.\n');
      process.exitCode = 0;
    } else {
      console.error('\n❌ MITRE INTEGRATION VERIFICATION FAILED');
      console.error('   One or more integration checks failed.\n');
      process.exitCode = 1;
    }

  } catch (error) {
    console.error('\n[FATAL ERROR IN MITRE INTEGRATION TEST]:', error);
    process.exitCode = 1;
  } finally {
    // -------------------------------------------------------------------------
    // CLEANUP: Close server, delete test incident & test user, close pool
    // -------------------------------------------------------------------------
    console.log('[CLEANUP] Tearing down test resources...');

    if (httpServerInstance) {
      await new Promise((resolve) => httpServerInstance.close(resolve)).catch(() => {});
    }

    if (createdIncidentId) {
      await query('DELETE FROM detection_signals WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM recommended_actions WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM mitre_mappings WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM incidents WHERE id = $1;', [createdIncidentId]).catch(() => {});
      console.log(`[CLEANUP] Deleted test incident ${createdIncidentId} and child records`);
    }

    if (testUser?.id) {
      await query('DELETE FROM users WHERE id = $1;', [testUser.id]).catch(() => {});
      console.log(`[CLEANUP] Deleted test user ${testUser.id}`);
    }

    await pool.end().catch(() => {});
    console.log('[CLEANUP] Database pool closed. Verification script complete.');
  }
}

runMitreIntegrationVerification();
