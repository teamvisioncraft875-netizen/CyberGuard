process.env.NODE_ENV = 'test';
const assert = require('assert');
const db = require('../src/config/db');
const Organization = require('../src/models/Organization');
const ResponsePolicy = require('../src/models/ResponsePolicy');
const Incident = require('../src/models/Incident');
const ddosDetectionService = require('../src/services/ddosDetectionService');

async function runDDoSDeduplicationTest() {
  console.log('========================================================================');
  console.log('CYBERGUARD — CRITICAL FIX #1: DDoS Incident Deduplication Verification');
  console.log('========================================================================');

  // 1. Setup isolated test organization & policy
  const org = await Organization.create({
    name: 'DDoS Dedup Org ' + Math.random().toString(36).substring(7)
  });
  const orgId = org.id;

  const policy = await ResponsePolicy.create({
    organization_id: orgId,
    name: 'Auto Mitigate DDoS',
    rules: [
      {
        threat_type: 'ddos',
        min_score: 90,
        action_type: 'block_ip',
        action_mode: 'shadow',
        auto_execute_after_mins: 5,
        target_filter: { user_roles: ['*'] }
      }
    ],
    is_enabled: true
  });

  const targetIp = '203.0.113.88';

  try {
    // -------------------------------------------------------------------------
    // STEP 0: Verify initial state (0 incidents)
    // -------------------------------------------------------------------------
    console.log('\n[Step 0] Checking baseline state...');
    const initialIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    console.log(`Initial incidents in org: ${initialIncidents.rows[0].count}`);
    assert.strictEqual(initialIncidents.rows[0].count, 0, 'Initial incident count must be 0');

    // -------------------------------------------------------------------------
    // STEP 1: First Attack Simulation
    // -------------------------------------------------------------------------
    console.log('\n[Step 1] Triggering first attack (600 requests from 203.0.113.88)...');
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'request_spike',
      source_ip: targetIp,
      count: 600,
      window_start: new Date(Date.now() - 5 * 60 * 1000),
      window_end: new Date()
    });

    const firstScanResults = await ddosDetectionService.detectRequestSpike(orgId, 5);
    const firstMatch = firstScanResults.find((r) => r.source_ip === targetIp);
    assert.ok(firstMatch, 'First scan must detect request spike');
    assert.ok(firstMatch.incident_id, 'First scan must create an incident');
    const firstIncidentId = firstMatch.incident_id;
    console.log(`✅ First scan created incident: ${firstIncidentId}`);

    // Allow async PolicyEngine to record proposed response actions
    await new Promise((resolve) => setTimeout(resolve, 350));

    // Verify exactly 1 incident exists
    const afterFirstIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    console.log(`Incidents count after attack 1: ${afterFirstIncidents.rows[0].count}`);
    assert.strictEqual(afterFirstIncidents.rows[0].count, 1, 'Exactly 1 incident should exist after first attack');

    // Check MITRE mappings, response actions, audit logs
    const mitreCount1 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.mitre_mappings WHERE incident_id = $1;`,
      [firstIncidentId]
    );
    assert.strictEqual(mitreCount1.rows[0].count, 1, 'Exactly 1 MITRE mapping after attack 1');

    const actionCount1 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.response_actions WHERE incident_id = $1;`,
      [firstIncidentId]
    );
    assert.strictEqual(actionCount1.rows[0].count, 1, 'Exactly 1 response action after attack 1');

    const auditCount1 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.audit_logs WHERE action = 'ddos_incident_created' AND resource_id = $1;`,
      [firstIncidentId]
    );
    assert.strictEqual(auditCount1.rows[0].count, 1, 'Exactly 1 audit log entry after attack 1');

    // -------------------------------------------------------------------------
    // STEP 2: Second Attack Simulation (Same IP within 15 minutes)
    // -------------------------------------------------------------------------
    console.log('\n[Step 2] Triggering second attack from SAME IP (203.0.113.88)...');
    // Spy on console.log to confirm the deduplication log message
    let reusedLogFound = false;
    const originalConsoleLog = console.log;
    console.log = (...args) => {
      const msg = args.join(' ');
      if (msg.includes('[DDoS] Reusing existing incident')) {
        reusedLogFound = true;
      }
      originalConsoleLog(...args);
    };

    const secondScanResults = await ddosDetectionService.detectRequestSpike(orgId, 5);
    console.log = originalConsoleLog; // restore

    const secondMatch = secondScanResults.find((r) => r.source_ip === targetIp);
    assert.ok(secondMatch, 'Second scan must detect threat');
    const secondIncidentId = secondMatch.incident_id;
    console.log(`Second scan returned incident ID: ${secondIncidentId}`);

    // Verify second scan returns the existing incident ID
    assert.strictEqual(
      secondIncidentId,
      firstIncidentId,
      'Second scan MUST return existing incident ID (deduplication)'
    );
    assert.strictEqual(reusedLogFound, true, "Must log '[DDoS] Reusing existing incident'");

    // Allow time for any errant async jobs
    await new Promise((resolve) => setTimeout(resolve, 350));

    // Verify incident count is STILL 1
    const afterSecondIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    console.log(`Incidents count after attack 2: ${afterSecondIncidents.rows[0].count}`);
    assert.strictEqual(afterSecondIncidents.rows[0].count, 1, 'Incident count MUST remain 1 after second attack!');

    // -------------------------------------------------------------------------
    // STEP 3: Verify Downstream Deduplication (No duplicates)
    // -------------------------------------------------------------------------
    console.log('\n[Step 3] Verifying no duplicate side-effects...');
    const actionCount2 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.response_actions WHERE incident_id = $1;`,
      [firstIncidentId]
    );
    console.log(`Response actions count: ${actionCount2.rows[0].count} (expected 1)`);
    assert.strictEqual(actionCount2.rows[0].count, 1, 'No duplicate policy response actions!');

    const mitreCount2 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.mitre_mappings WHERE incident_id = $1;`,
      [firstIncidentId]
    );
    console.log(`MITRE mappings count: ${mitreCount2.rows[0].count} (expected 1)`);
    assert.strictEqual(mitreCount2.rows[0].count, 1, 'No duplicate MITRE mappings!');

    const auditCount2 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.audit_logs WHERE action = 'ddos_incident_created' AND resource_id = $1;`,
      [firstIncidentId]
    );
    console.log(`Audit log ddos_incident_created entries: ${auditCount2.rows[0].count} (expected 1)`);
    assert.strictEqual(auditCount2.rows[0].count, 1, 'No duplicate audit entries!');

    // -------------------------------------------------------------------------
    // STEP 4: Direct createDDoSIncident call deduplication
    // -------------------------------------------------------------------------
    console.log('\n[Step 4] Direct createDDoSIncident() call for same IP...');
    const directResult = await ddosDetectionService.createDDoSIncident(
      orgId,
      'request_spike',
      targetIp,
      { count: 999 }
    );
    assert.strictEqual(
      directResult.id,
      firstIncidentId,
      'Direct call must return existing incident ID'
    );
    const afterDirectIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    assert.strictEqual(afterDirectIncidents.rows[0].count, 1, 'Incidents count must remain 1');
    console.log('✅ Direct call deduplicated successfully');

    // -------------------------------------------------------------------------
    // STEP 5: Different IP creates a NEW incident
    // -------------------------------------------------------------------------
    console.log('\n[Step 5] Triggering attack from DIFFERENT IP (203.0.113.89)...');
    const diffIp = '203.0.113.89';
    const diffResult = await ddosDetectionService.createDDoSIncident(
      orgId,
      'request_spike',
      diffIp,
      { count: 650 }
    );
    assert.notStrictEqual(diffResult.id, firstIncidentId, 'Different IP must create new incident');
    const afterDiffIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    assert.strictEqual(afterDiffIncidents.rows[0].count, 2, 'Incidents count must now be 2');
    console.log(`✅ Different IP correctly created new incident: ${diffResult.id}`);

    // -------------------------------------------------------------------------
    // STEP 6: Resolved incident allows a new incident to be created
    // -------------------------------------------------------------------------
    console.log('\n[Step 6] Resolving original incident and re-attacking...');
    await db.query(`UPDATE public.incidents SET status = 'resolved' WHERE id = $1;`, [firstIncidentId]);

    const postResolveResult = await ddosDetectionService.createDDoSIncident(
      orgId,
      'request_spike',
      targetIp,
      { count: 750 }
    );
    assert.notStrictEqual(
      postResolveResult.id,
      firstIncidentId,
      'Resolved incident must NOT be reused; new incident should be opened'
    );
    const finalIncidents = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    assert.strictEqual(finalIncidents.rows[0].count, 3, 'Total incidents must now be 3');
    console.log(`✅ Resolved incident was not reused, new incident created: ${postResolveResult.id}`);

    console.log('\n========================================================================');
    console.log('🎉 ALL DEDUP VERIFICATION CHECKS PASSED WITH ZERO ERRORS! 🎉');
    console.log('========================================================================');
  } finally {
    console.log('\nCleaning up verification resources...');
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgId]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
  }
}

runDDoSDeduplicationTest().catch((err) => {
  console.error('❌ Deduplication test failed with error:', err);
  process.exit(1);
});
