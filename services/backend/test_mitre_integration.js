const http = require('http');
const jwt = require('jsonwebtoken');
const { app } = require('./src/index');
const { query, pool } = require('./src/config/db');
const config = require('./src/config');
const MitreMapping = require('./src/models/MitreMapping');

async function main() {
  console.log('====================================================');
  console.log('CYBERGUARD — MITRE ATT&CK INTEGRATION VERIFICATION');
  console.log('====================================================\n');

  // 0. Ensure we have an active test user in the DB
  const userRes = await query(`
    SELECT id, email, role, organization_id 
    FROM users 
    LIMIT 1;
  `);

  let testUser = userRes.rows[0];
  if (!testUser) {
    const orgRes = await query(`SELECT id FROM organizations LIMIT 1;`);
    const orgId = orgRes.rows[0]?.id || null;
    const inserted = await query(`
      INSERT INTO users (email, password_hash, role, organization_id)
      VALUES ('analyst@enterprise.com', 'dummyhash', 'admin', $1)
      RETURNING id, email, role, organization_id;
    `, [orgId]);
    testUser = inserted.rows[0];
  }

  const jwtSecret = config.JWT_SECRET || process.env.JWT_SECRET || 'cyberguard-dev-secret-key';
  const authToken = jwt.sign({
    id: testUser.id,
    email: testUser.email,
    role: testUser.role,
    organization_id: testUser.organization_id
  }, jwtSecret, { expiresIn: '1h' });

  // Spin up temporary HTTP server on random port
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[Setup] In-process server listening on ${baseUrl}`);
  console.log(`[Setup] Authenticated Test User ID: ${testUser.id} (${testUser.role})\n`);

  try {
    // -------------------------------------------------------------------------
    // VERIFICATION 1 & 2: Create real incident via detection pipeline & verify rows
    // -------------------------------------------------------------------------
    console.log('--- Step 1 & 2: Create real incident via detection pipeline (checkMessage) ---');
    const checkMessagePayload = {
      text: 'URGENT: Your bank account has been locked. Verify identity at https://secure-bank-login.xyz immediately.',
      source_type: 'email'
    };

    const checkRes = await fetch(`${baseUrl}/api/v1/check/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify(checkMessagePayload)
    });

    const checkBody = await checkRes.json();
    console.log(`POST /api/v1/check/message Status: ${checkRes.status}`);
    console.log('Response Payload:', JSON.stringify(checkBody, null, 2));

    if (checkRes.status !== 200 || !checkBody.id) {
      throw new Error(`Failed to create incident via checkMessage: ${JSON.stringify(checkBody)}`);
    }

    const createdIncidentId = checkBody.id;

    // Direct DB query: verify incident row
    const incidentRows = await query(`SELECT * FROM incidents WHERE id = $1;`, [createdIncidentId]);
    const incidentRow = incidentRows.rows[0];
    console.log('\n[Database Verification] Incident Row:');
    console.log({
      id: incidentRow.id,
      threat_type: incidentRow.threat_type,
      source_type: incidentRow.source_type,
      risk_level: incidentRow.risk_level,
      risk_score: incidentRow.risk_score,
      status: incidentRow.status,
      created_at: incidentRow.created_at
    });

    // Direct DB query: verify mitre_mappings row
    const mitreRows = await query(`SELECT * FROM mitre_mappings WHERE incident_id = $1;`, [createdIncidentId]);
    console.log('\n[Database Verification] Mitre Mapping Row(s):');
    console.log(mitreRows.rows);

    if (mitreRows.rows.length !== 1) {
      throw new Error(`Expected exactly 1 mitre_mappings row for incident, found ${mitreRows.rows.length}`);
    }

    const mapping = mitreRows.rows[0];
    if (mapping.technique_id !== 'T1566' || mapping.technique_name !== 'Phishing') {
      throw new Error(`Mismatch in technique mapping: expected T1566 / Phishing, got ${mapping.technique_id} / ${mapping.technique_name}`);
    }
    console.log(`\n✔ Step 1 & 2 SUCCESS: Incident and MITRE mapping persisted with technique_id=${mapping.technique_id}, technique_name="${mapping.technique_name}"`);

    // -------------------------------------------------------------------------
    // VERIFICATION 3: Verify GET /api/v1/analytics/mitre
    // -------------------------------------------------------------------------
    console.log('\n--- Step 3: Verify GET /api/v1/analytics/mitre returns non-empty results ---');
    const mitreAnalyticsRes = await fetch(`${baseUrl}/api/v1/analytics/mitre`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    const mitreAnalyticsBody = await mitreAnalyticsRes.json();
    console.log(`GET /api/v1/analytics/mitre Status: ${mitreAnalyticsRes.status}`);
    console.log('Analytics Response:', JSON.stringify(mitreAnalyticsBody, null, 2));

    if (mitreAnalyticsRes.status !== 200 || !Array.isArray(mitreAnalyticsBody)) {
      throw new Error(`Invalid response from /api/v1/analytics/mitre: ${JSON.stringify(mitreAnalyticsBody)}`);
    }

    const phishingAggregate = mitreAnalyticsBody.find(r => r.technique_id === 'T1566');
    if (!phishingAggregate || phishingAggregate.incident_count < 1) {
      throw new Error(`Expected T1566 with incident_count >= 1 in analytics, got: ${JSON.stringify(phishingAggregate)}`);
    }
    console.log(`✔ Step 3 SUCCESS: GET /api/v1/analytics/mitre returned aggregated results including ${phishingAggregate.technique_id} (${phishingAggregate.technique_name}): count=${phishingAggregate.incident_count}`);

    // -------------------------------------------------------------------------
    // VERIFICATION 4: Demonstrate rollback behavior on forced MITRE failure
    // -------------------------------------------------------------------------
    console.log('\n--- Step 4: Demonstrate Rollback Behavior on Forced MITRE Persistence Failure ---');
    
    // Count rows before forced failure
    const beforeCounts = {
      incidents: parseInt((await query('SELECT COUNT(*)::int FROM incidents;')).rows[0].count, 10),
      mitre: parseInt((await query('SELECT COUNT(*)::int FROM mitre_mappings;')).rows[0].count, 10),
      signals: parseInt((await query('SELECT COUNT(*)::int FROM detection_signals;')).rows[0].count, 10),
      actions: parseInt((await query('SELECT COUNT(*)::int FROM recommended_actions;')).rows[0].count, 10),
    };
    console.log('Database row counts BEFORE forced rollback test:', beforeCounts);

    // Mock MitreMapping.create to force an intentional error during the transaction
    const originalMitreCreate = MitreMapping.create;
    MitreMapping.create = async function (data, client) {
      console.log('  [Mock MitreMapping.create] Triggering intentional simulation failure inside transaction...');
      throw new Error('SIMULATED_MITRE_DATABASE_FAILURE: Unique constraint or database error during MITRE insert');
    };

    let rollbackReqStatus = null;
    let rollbackReqBody = null;
    try {
      const failedCheckRes = await fetch(`${baseUrl}/api/v1/check/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({
          text: 'Security alert: Suspicious login attempt from unknown browser.',
          source_type: 'email'
        })
      });

      rollbackReqStatus = failedCheckRes.status;
      rollbackReqBody = await failedCheckRes.json();
    } finally {
      // Restore original MitreMapping.create immediately
      MitreMapping.create = originalMitreCreate;
    }

    console.log(`POST /api/v1/check/message status during forced failure: ${rollbackReqStatus}`);
    console.log('Response body:', rollbackReqBody);

    if (rollbackReqStatus !== 500) {
      throw new Error(`Expected HTTP 500 on transaction failure, got ${rollbackReqStatus}`);
    }

    // Count rows after forced failure
    const afterCounts = {
      incidents: parseInt((await query('SELECT COUNT(*)::int FROM incidents;')).rows[0].count, 10),
      mitre: parseInt((await query('SELECT COUNT(*)::int FROM mitre_mappings;')).rows[0].count, 10),
      signals: parseInt((await query('SELECT COUNT(*)::int FROM detection_signals;')).rows[0].count, 10),
      actions: parseInt((await query('SELECT COUNT(*)::int FROM recommended_actions;')).rows[0].count, 10),
    };
    console.log('Database row counts AFTER forced rollback test:', afterCounts);

    const delta = {
      incidents: afterCounts.incidents - beforeCounts.incidents,
      mitre: afterCounts.mitre - beforeCounts.mitre,
      signals: afterCounts.signals - beforeCounts.signals,
      actions: afterCounts.actions - beforeCounts.actions
    };
    console.log('Row count deltas (must all be 0):', delta);

    if (delta.incidents !== 0 || delta.mitre !== 0 || delta.signals !== 0 || delta.actions !== 0) {
      throw new Error(`ROLLBACK FAILED: Partial data was leaked to the database! Deltas: ${JSON.stringify(delta)}`);
    }

    console.log('✔ Step 4 SUCCESS: Transaction rolled back completely. 0 orphaned incidents, signals, actions, or mitre_mappings.');

    // Clean up created test incident
    await query(`DELETE FROM incidents WHERE id = $1;`, [createdIncidentId]);
    console.log(`\n[Cleanup] Test incident ${createdIncidentId} deleted (cascade cleaned up mitre_mappings).`);

    console.log('\n====================================================');
    console.log('ALL 4 MITRE INTEGRATION VERIFICATIONS PASSED (100%)');
    console.log('====================================================\n');
  } finally {
    server.close();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('\n❌ VERIFICATION TEST FAILED:', err);
  process.exit(1);
});
