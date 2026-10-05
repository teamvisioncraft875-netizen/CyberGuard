process.env.NODE_ENV = 'test';
const assert = require('assert');
const db = require('../src/config/db');
const Organization = require('../src/models/Organization');
const ResponsePolicy = require('../src/models/ResponsePolicy');
const ddosDetectionService = require('../src/services/ddosDetectionService');

async function runRaceConditionSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — CRITICAL FIX #2: Concurrent DDoS Scan Race Condition Tests');
  console.log('========================================================================');

  // Setup isolated test organization & automated response policy
  const org = await Organization.create({
    name: 'DDoS Race Test Org ' + Math.random().toString(36).substring(7)
  });
  const orgId = org.id;

  await ResponsePolicy.create({
    organization_id: orgId,
    name: 'Auto DDoS Mitigation Policy',
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

  try {
    // =========================================================================
    // SCENARIO 1: 20 CONCURRENT CALLS (SAME ORG, SAME IP, SAME METRIC)
    // =========================================================================
    console.log('\n[Scenario 1] Spawning 20 concurrent createDDoSIncident() calls for SAME IP...');
    const targetIp1 = '198.51.100.201';

    const promisesS1 = Array.from({ length: 20 }, (_, idx) =>
      ddosDetectionService.createDDoSIncident(orgId, 'request_spike', targetIp1, {
        count: 600 + idx,
        endpoint: '/api/v1/login'
      })
    );

    const resultsS1 = await Promise.all(promisesS1);
    console.log(`All 20 concurrent calls resolved. Verifying results...`);

    // All 20 calls should return the same incident ID
    const firstId = resultsS1[0].id;
    assert.ok(firstId, 'First returned incident must have valid ID');
    for (let i = 1; i < resultsS1.length; i++) {
      assert.strictEqual(
        resultsS1[i].id,
        firstId,
        `Concurrent call ${i + 1} must return identical incident ID`
      );
    }

    // Verify database counts
    const incRes1 = await db.query(
      `SELECT id FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    console.log(`Incidents in DB: ${incRes1.rows.length} (Expected: 1)`);
    assert.strictEqual(incRes1.rows.length, 1, 'Exactly 1 incident must exist');

    const actRes1 = await db.query(
      `SELECT id FROM public.response_actions WHERE incident_id = $1;`,
      [firstId]
    );
    console.log(`Response actions in DB: ${actRes1.rows.length} (Expected: 1)`);
    assert.strictEqual(actRes1.rows.length, 1, 'Exactly 1 response action must exist');

    const mitreRes1 = await db.query(
      `SELECT id FROM public.mitre_mappings WHERE incident_id = $1;`,
      [firstId]
    );
    console.log(`MITRE mappings in DB: ${mitreRes1.rows.length} (Expected: 1)`);
    assert.strictEqual(mitreRes1.rows.length, 1, 'Exactly 1 MITRE mapping must exist');

    const auditRes1 = await db.query(
      `SELECT id FROM public.audit_logs WHERE action = 'ddos_incident_created' AND resource_id = $1;`,
      [firstId]
    );
    console.log(`Audit log entries in DB: ${auditRes1.rows.length} (Expected: 1)`);
    assert.strictEqual(auditRes1.rows.length, 1, 'Exactly 1 audit entry must exist');

    console.log('✅ Scenario 1 (20 Concurrent Calls, Same IP) PASSED');

    // =========================================================================
    // SCENARIO 2: 20 CONCURRENT CALLS (DIFFERENT SOURCE IPs)
    // =========================================================================
    console.log('\n[Scenario 2] Spawning 20 concurrent calls with DIFFERENT source IPs...');
    const promisesS2 = Array.from({ length: 20 }, (_, idx) => {
      const distinctIp = `198.51.100.${idx + 10}`;
      return ddosDetectionService.createDDoSIncident(orgId, 'request_spike', distinctIp, {
        count: 700
      });
    });

    const resultsS2 = await Promise.all(promisesS2);
    const returnedIdsS2 = new Set(resultsS2.map((r) => r.id));
    console.log(`Distinct incident IDs returned: ${returnedIdsS2.size} (Expected: 20)`);
    assert.strictEqual(returnedIdsS2.size, 20, '20 distinct incidents must be returned');

    // Total incidents in org should now be 1 (from Scenario 1) + 20 = 21
    const incRes2 = await db.query(
      `SELECT COUNT(*)::INT AS count FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos';`,
      [orgId]
    );
    console.log(`Total incidents in org: ${incRes2.rows[0].count} (Expected: 21)`);
    assert.strictEqual(incRes2.rows[0].count, 21, '20 new incidents created for distinct IPs');

    console.log('✅ Scenario 2 (20 Concurrent Calls, Different IPs) PASSED');

    // =========================================================================
    // SCENARIO 3: SIMULATE TRANSACTION FAILURE MIDWAY (ROLLBACK VERIFICATION)
    // =========================================================================
    console.log('\n[Scenario 3] Simulating mid-transaction failure & verifying rollback...');
    const failIp = '198.51.254.' + Math.floor(Math.random() * 200 + 10);

    let errorThrown = false;
    try {
      await ddosDetectionService.createDDoSIncident(orgId, 'request_spike', failIp, {
        count: 999,
        _simulate_failure: true
      });
    } catch (e) {
      errorThrown = true;
      console.log(`Expected transaction failure caught: "${e.message}"`);
    }
    assert.strictEqual(errorThrown, true, 'Transaction must throw on failure');

    // Check that NO incident exists for failIp
    const failInc = await db.query(
      `SELECT i.* FROM public.incidents i WHERE organization_id = $1 AND explanation ILIKE '%' || $2 || '%';`,
      [orgId, failIp]
    );
    console.log(`Incidents matching failIp: ${failInc.rows.length} (Expected: 0)`);
    assert.strictEqual(failInc.rows.length, 0, 'No incident should be left after rollback');

    // Check that NO evidence exists for failIp
    const failEv = await db.query(
      `SELECT * FROM public.incident_evidence WHERE metadata->>'source_ip' = $1;`,
      [failIp]
    );
    console.log(`Evidence matching failIp: ${failEv.rows.length} (Expected: 0)`);
    assert.strictEqual(failEv.rows.length, 0, 'No evidence should be left after rollback');

    // Check that NO ddos_metrics exists for failIp
    const failMetric = await db.query(
      `SELECT * FROM public.ddos_metrics WHERE organization_id = $1 AND source_ip = $2;`,
      [orgId, failIp]
    );
    console.log(`Metrics matching failIp: ${failMetric.rows.length} (Expected: 0)`);
    assert.strictEqual(failMetric.rows.length, 0, 'No metrics should be left after rollback');

    // Check that NO audit log exists for failIp
    const failAudit = await db.query(
      `SELECT * FROM public.audit_logs WHERE organization_id = $1 AND ip_address = $2 AND action = 'ddos_incident_created';`,
      [orgId, failIp]
    );
    console.log(`Audit entries matching failIp: ${failAudit.rows.length} (Expected: 0)`);
    assert.strictEqual(failAudit.rows.length, 0, 'No audit logs should be left after rollback');

    console.log('✅ Scenario 3 (Mid-Transaction Failure & Rollback) PASSED');

    // =========================================================================
    // SCENARIO 4: HIGH CONCURRENCY STRESS (100 PARALLEL CALLS)
    // =========================================================================
    console.log('\n[Scenario 4] High Concurrency Stress Test: 100 parallel calls for SAME IP...');
    const stressIp = '198.51.100.250';

    const promisesS4 = Array.from({ length: 100 }, (_, idx) =>
      ddosDetectionService.createDDoSIncident(orgId, 'request_spike', stressIp, {
        count: 500 + idx
      })
    );

    const resultsS4 = await Promise.all(promisesS4);
    const stressFirstId = resultsS4[0].id;
    assert.ok(stressFirstId, 'Valid incident ID returned');

    for (let i = 1; i < resultsS4.length; i++) {
      assert.strictEqual(
        resultsS4[i].id,
        stressFirstId,
        `Parallel call ${i + 1} returned differing incident ID!`
      );
    }

    const stressIncCheck = await db.query(
      `SELECT i.id FROM public.incidents i WHERE organization_id = $1 AND explanation ILIKE '%' || $2 || '%';`,
      [orgId, stressIp]
    );
    console.log(`Incidents in DB for stress IP: ${stressIncCheck.rows.length} (Expected: 1)`);
    assert.strictEqual(stressIncCheck.rows.length, 1, 'STILL ONLY 1 INCIDENT under 100 parallel calls!');

    console.log('✅ Scenario 4 (100 Parallel Calls Stress Test) PASSED');

    console.log('\n========================================================================');
    console.log('🎉 ALL 4 RACE CONDITION SCENARIOS PASSED WITH ZERO CONCURRENCY DEFECTS! 🎉');
    console.log('========================================================================');
  } finally {
    console.log('\nCleaning up verification resources...');
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [orgId]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
  }
}

runRaceConditionSuite().catch((err) => {
  console.error('❌ Race condition test failed with error:', err);
  process.exit(1);
});
