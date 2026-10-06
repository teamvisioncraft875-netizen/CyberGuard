const assert = require('assert');
const db = require('../src/config/db');
const PolicyEngine = require('../src/services/PolicyEngine');
const ResponsePolicy = require('../src/models/ResponsePolicy');
const ResponseAction = require('../src/models/ResponseAction');
const executionService = require('../src/services/executionService');
const incidentThreatIntelService = require('../src/services/incidentThreatIntelService');

/**
 * CYBERGUARD — Task 6: Threat Intelligence Automated Response Policies Test Suite
 *
 * Validates:
 * A. Threat intel conditions evaluate correctly
 * B. Policy matching works
 * C. Action proposals generated
 * D. Metadata stored correctly
 * E. Duplicate prevention works
 * F. Multi-tenant isolation works
 * G. Shadow mode works
 * H. Live mode works
 * I. Audit logs recorded
 * J. Existing policy workflows unaffected
 */

let passed = 0;
let failed = 0;

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  [✅] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [❌] ${name}: ${err.message}`);
    failed++;
  }
}

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Task 6: Threat Intelligence Automated Response Policies');
  console.log('========================================================================\n');

  let testOrgAId = null;
  let testOrgBId = null;
  let testDeviceId = null;
  let policyAId = null;
  let policyBId = null;
  let incidentAId = null;
  let incidentBId = null;
  let indicatorId = null;
  let matchId = null;

  const testIpValue = `203.0.113.${Math.floor(Math.random() * 200 + 30)}`;

  console.log('--- TEST GROUP 1: FIXTURE SETUP & TENANT INITIALIZATION ---');

  await testAsync('1A: Prepares test tenant organizations and registered device', async () => {
    const orgARes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Policy Org A') RETURNING id;`
    );
    testOrgAId = orgARes.rows[0].id;

    const orgBRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Policy Org B') RETURNING id;`
    );
    testOrgBId = orgBRes.rows[0].id;

    const devRes = await db.query(
      `INSERT INTO devices (organization_id, hostname, status, device_id)
       VALUES ($1, 'soc-workstation-01', 'active', 'dev-ti-test-01') RETURNING id;`,
      [testOrgAId]
    );
    testDeviceId = devRes.rows[0].id;

    assert.ok(testOrgAId);
    assert.ok(testOrgBId);
    assert.ok(testDeviceId);
  });

  await testAsync('1B: Prepares test indicator and incident records', async () => {
    // 1. Insert Threat Indicator with unique test IP
    await db.query(`DELETE FROM public.threat_indicators WHERE indicator_value = $1;`, [testIpValue]);
    const indRes = await db.query(
      `INSERT INTO threat_indicators (
        indicator_type, indicator_value, severity, confidence_score, threat_actor, is_active
      ) VALUES ($1, $2, $3, $4, $5, true) RETURNING id;`,
      ['ip', testIpValue, 'critical', 95, 'APT29']
    );
    indicatorId = indRes.rows[0].id;

    // 2. Insert Incident for Org A
    const incARes = await db.query(
      `INSERT INTO incidents (
        organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id;`,
      [testOrgAId, 'technical_threat', 'system', 'critical', 90, 'C2 traffic detected to malicious IP', 'open']
    );
    incidentAId = incARes.rows[0].id;

    // 3. Insert Incident for Org B
    const incBRes = await db.query(
      `INSERT INTO incidents (
        organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id;`,
      [testOrgBId, 'technical_threat', 'system', 'low', 30, 'Low risk event in Org B', 'open']
    );
    incidentBId = incBRes.rows[0].id;

    // 4. Insert IOC Match for Org A
    const matchRes = await db.query(
      `INSERT INTO incident_ioc_matches (
        organization_id, incident_id, indicator_id, matched_value, match_context,
        reputation_score, severity, feed_source, matched_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING id;`,
      [testOrgAId, incidentAId, indicatorId, testIpValue, 'source_ip', 95, 'critical', 'AlienVault OTX']
    );
    matchId = matchRes.rows[0].id;

    assert.ok(indicatorId);
    assert.ok(incidentAId);
    assert.ok(incidentBId);
    assert.ok(matchId);
  });

  console.log('\n--- TEST GROUP 2: THREAT INTEL CONDITIONS EVALUATION (CRITERION A) ---');

  await testAsync('2A: validateRules verifies threat intelligence condition fields', async () => {
    // Valid rule with all threat intel conditions
    const validRules = [
      {
        threat_type: '*',
        min_score: 50,
        action_type: 'block_ip',
        threat_intel_match_exists: true,
        threat_intel_confidence_gte: 80,
        threat_intel_severity_equals: 'critical',
        reputation_score_gte: 85,
        malicious_indicator_count_gte: 1
      },
      {
        threat_type: 'technical_threat',
        min_score: 70,
        action_type: 'block_url',
        action_mode: 'live'
      }
    ];
    assert.doesNotThrow(() => PolicyEngine.validateRules(validRules));

    // Invalid threat_intel_match_exists (not boolean)
    assert.throws(
      () => PolicyEngine.validateRules([{ threat_type: '*', min_score: 50, action_type: 'block_ip', threat_intel_match_exists: 'yes' }]),
      /threat_intel_match_exists must be a boolean/
    );

    // Invalid threat_intel_confidence_gte (> 100)
    assert.throws(
      () => PolicyEngine.validateRules([{ threat_type: '*', min_score: 50, action_type: 'block_ip', threat_intel_confidence_gte: 150 }]),
      /threat_intel_confidence_gte must be a number between 0 and 100/
    );

    // Invalid threat_intel_severity_equals (unknown severity)
    assert.throws(
      () => PolicyEngine.validateRules([{ threat_type: '*', min_score: 50, action_type: 'block_ip', threat_intel_severity_equals: 'super_critical' }]),
      /threat_intel_severity_equals must be one of/
    );
  });

  console.log('\n--- TEST GROUP 3: POLICY MATCHING & ACTION PROPOSALS (CRITERIA B, C, D) ---');

  await testAsync('3A: Custom Org policy matches incident with threat intel conditions (CRITERION B)', async () => {
    // Create Policy for Org A requiring confidence >= 90 and critical severity
    const policyA = await ResponsePolicy.create({
      organization_id: testOrgAId,
      name: 'Org A High Confidence Auto Containment',
      enabled: true,
      rules: [
        {
          threat_type: '*',
          min_score: 0,
          threat_intel_match_exists: true,
          threat_intel_confidence_gte: 90,
          threat_intel_severity_equals: 'critical',
          reputation_score_gte: 90,
          malicious_indicator_count_gte: 1,
          action_type: 'block_ip',
          action_mode: 'shadow',
          requires_approval: true
        }
      ]
    });
    policyAId = policyA.id;
    assert.ok(policyAId);

    const applicable = await PolicyEngine.getApplicablePolicies({
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 90
    });

    assert.ok(applicable.length >= 1);
    const ruleMatch = applicable.find((r) => r.policy_id === policyAId);
    assert.ok(ruleMatch, 'Org A custom policy should match incident A');
    assert.strictEqual(ruleMatch.action_type, 'block_ip');
  });

  await testAsync('3B: calculateActions extracts Threat Intel Action Context metadata (CRITERIA C & D)', async () => {
    const applicable = await PolicyEngine.getApplicablePolicies({
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 90
    });

    const calculated = PolicyEngine.calculateActions(
      {
        id: incidentAId,
        organization_id: testOrgAId,
        threat_type: 'technical_threat',
        risk_score: 90
      },
      applicable
    );

    assert.ok(calculated.length >= 1);
    const ipAction = calculated.find((a) => a.action_type === 'block_ip');
    assert.ok(ipAction);
    assert.strictEqual(ipAction.target.ip_address, testIpValue);
    assert.ok(ipAction.metadata);
    assert.strictEqual(ipAction.metadata.indicator_value, testIpValue);
    assert.strictEqual(ipAction.metadata.indicator_type, 'ip');
    assert.strictEqual(ipAction.metadata.confidence_score, 95);
    assert.strictEqual(ipAction.metadata.reputation_score, 95);
    assert.strictEqual(ipAction.metadata.source_feed, 'AlienVault OTX');
    assert.strictEqual(ipAction.metadata.matched_indicator_id, indicatorId);
  });

  await testAsync('3C: Automatic proposal generation for malicious domain and URL (CRITERION C)', async () => {
    const testIncidentWithDomainUrl = {
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'phishing',
      risk_score: 85,
      ioc_matches: [
        {
          indicator_id: '11111111-1111-1111-1111-111111111111',
          indicator_type: 'domain',
          matched_value: 'evil-phish-domain.xyz',
          reputation_score: 92,
          confidence_score: 92,
          severity: 'high',
          feed_source: 'PhishTank'
        },
        {
          indicator_id: '22222222-2222-2222-2222-222222222222',
          indicator_type: 'url',
          matched_value: 'https://evil-phish-domain.xyz/login.php',
          reputation_score: 90,
          confidence_score: 90,
          severity: 'high',
          feed_source: 'URLhaus'
        }
      ]
    };

    const applicable = await PolicyEngine.getApplicablePolicies(testIncidentWithDomainUrl);
    const actions = PolicyEngine.calculateActions(testIncidentWithDomainUrl, applicable);

    const domainAction = actions.find((a) => a.action_type === 'block_domain');
    assert.ok(domainAction, 'Should automatically propose block_domain');
    assert.strictEqual(domainAction.target.domain, 'evil-phish-domain.xyz');
    assert.strictEqual(domainAction.metadata.indicator_value, 'evil-phish-domain.xyz');

    const urlAction = actions.find((a) => a.action_type === 'block_url');
    assert.ok(urlAction, 'Should automatically propose block_url');
    assert.strictEqual(urlAction.target.url, 'https://evil-phish-domain.xyz/login.php');
    assert.strictEqual(urlAction.metadata.indicator_value, 'https://evil-phish-domain.xyz/login.php');
  });

  console.log('\n--- TEST GROUP 4: DUPLICATE PREVENTION (CRITERION E) ---');

  await testAsync('4A: Same incident, indicator, and action_type creates only 1 active action', async () => {
    const incidentObj = {
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 90
    };

    // First proposal run
    const run1 = await PolicyEngine.evaluateAndProposeActions(incidentObj);
    assert.ok(run1.length >= 1);

    // Second proposal run for identical incident & findings
    const run2 = await PolicyEngine.evaluateAndProposeActions(incidentObj);
    // run2 must NOT create additional active actions for the same indicator & action_type
    assert.strictEqual(run2.length, 0, 'Second run must suppress duplicates');

    // DB Verification: Exactly one active action in database for (incident_id, action_type, indicator_value)
    const dbCount = await db.query(
      `SELECT count(*)::int AS count 
       FROM public.response_actions 
       WHERE incident_id = $1 
         AND action_type = 'block_ip' 
         AND metadata->>'indicator_value' = $2
         AND status NOT IN ('rejected', 'failed', 'expired', 'rolled_back');`,
      [incidentAId, testIpValue]
    );
    assert.strictEqual(dbCount.rows[0].count, 1, 'Database must have exactly 1 active response action');
  });

  console.log('\n--- TEST GROUP 5: MULTI-TENANT ISOLATION (CRITERION F) ---');

  await testAsync('5A: Org A policies and findings do not leak to Org B', async () => {
    // Incident B has no IOC matches and score 30
    const applicableB = await PolicyEngine.getApplicablePolicies({
      id: incidentBId,
      organization_id: testOrgBId,
      threat_type: 'technical_threat',
      risk_score: 30
    });

    // Org A's policy must not match Org B
    const leakedPolicy = applicableB.find((r) => r.policy_id === policyAId);
    assert.strictEqual(leakedPolicy, undefined, 'Org A policy must not apply to Org B');

    // Evaluate actions for Org B
    const actionsB = await PolicyEngine.evaluateAndProposeActions({
      id: incidentBId,
      organization_id: testOrgBId,
      threat_type: 'technical_threat',
      risk_score: 30
    });

    // All actions created for Org B must have Org B's organization_id
    for (const act of actionsB) {
      assert.strictEqual(act.organization_id, testOrgBId);
      assert.notStrictEqual(act.organization_id, testOrgAId);
    }
  });

  console.log('\n--- TEST GROUP 6: SHADOW VS LIVE MODE & APPROVAL (CRITERIA G & H) ---');

  const shadowIp = `198.51.100.${Math.floor(Math.random() * 200 + 30)}`;

  await testAsync('6A: Shadow mode creates proposed action with action_mode=shadow', async () => {
    const incidentObj = {
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 90,
      ioc_matches: [
        {
          indicator_id: indicatorId,
          indicator_type: 'ip',
          matched_value: shadowIp,
          reputation_score: 95,
          severity: 'critical'
        }
      ]
    };

    const actions = await PolicyEngine.evaluateAndProposeActions(incidentObj);
    const shadowAction = actions.find((a) => a.metadata?.indicator_value === shadowIp);
    assert.ok(shadowAction);
    assert.strictEqual(shadowAction.action_mode, 'shadow');
    assert.strictEqual(shadowAction.status, 'proposed');
  });

  const liveIp = `203.0.113.${Math.floor(Math.random() * 200 + 30)}`;

  await testAsync('6B: Live mode policy creates action_mode=live and executes when approved', async () => {
    // 1. Create a custom LIVE mode policy for Org A
    const livePolicy = await ResponsePolicy.create({
      organization_id: testOrgAId,
      name: 'Org A Live IP Block Policy',
      enabled: true,
      rules: [
        {
          threat_type: '*',
          min_score: 0,
          threat_intel_match_exists: true,
          threat_intel_confidence_gte: 85,
          action_type: 'block_ip',
          action_mode: 'live',
          requires_approval: true
        }
      ]
    });
    policyBId = livePolicy.id;

    const liveIncident = {
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 92,
      analysis_confidence: 95,
      ioc_matches: [
        {
          indicator_id: indicatorId,
          indicator_type: 'ip',
          matched_value: liveIp,
          reputation_score: 92,
          confidence_score: 92,
          severity: 'high'
        }
      ]
    };

    const actions = await PolicyEngine.evaluateAndProposeActions(liveIncident);
    const liveAction = actions.find((a) => a.metadata?.indicator_value === liveIp);
    assert.ok(liveAction);
    assert.strictEqual(liveAction.action_mode, 'live');
    assert.strictEqual(liveAction.status, 'proposed');

    // Approve the action
    await db.query(
      `UPDATE public.response_actions SET status = 'approved', approved_at = NOW() WHERE id = $1;`,
      [liveAction.id]
    );

    // Fetch approved action and execute live
    const approvedAction = await db.query(
      `SELECT * FROM public.response_actions WHERE id = $1;`,
      [liveAction.id]
    );
    const execResult = await executionService.execute(approvedAction.rows[0], 'system_policy');
    assert.strictEqual(execResult.success, true);
    assert.strictEqual(execResult.result.blocked_ip, liveIp);
  });

  console.log('\n--- TEST GROUP 7: AUDIT LOGGING (CRITERION I) ---');

  await testAsync('7A: Audit logs record threat_policy_triggered, threat_action_proposed, suppressed', async () => {
    const logsRes = await db.query(
      `SELECT action, resource_type, details 
       FROM public.audit_logs 
       WHERE organization_id = $1
         AND action IN ('threat_policy_triggered', 'threat_action_proposed', 'threat_action_suppressed_duplicate')
       ORDER BY created_at DESC 
       LIMIT 10;`,
      [testOrgAId]
    );

    assert.ok(logsRes.rows.length >= 2, 'Must record threat intelligence audit actions');
    const actions = logsRes.rows.map((r) => r.action);
    assert.ok(actions.includes('threat_policy_triggered') || actions.includes('threat_action_proposed'));
    assert.ok(actions.includes('threat_action_suppressed_duplicate'));
  });

  console.log('\n--- TEST GROUP 8: INTEGRATION & EXISTING WORKFLOW SAFETY (CRITERION J) ---');

  await testAsync('8A: incidentThreatIntelService.evaluateIncidentPolicies connects end-to-end', async () => {
    const proposed = await incidentThreatIntelService.evaluateIncidentPolicies({
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'technical_threat',
      risk_score: 90
    });

    assert.ok(Array.isArray(proposed));
  });

  await testAsync('8B: Existing policies without threat intel conditions continue to work normally', async () => {
    const standardPolicy = await ResponsePolicy.create({
      organization_id: testOrgAId,
      name: 'Org A Standard Account Takeover Policy',
      enabled: true,
      rules: [
        {
          threat_type: 'account_takeover',
          min_score: 80,
          action_type: 'revoke_session',
          action_mode: 'shadow',
          requires_approval: false
        }
      ]
    });

    const applicable = await PolicyEngine.getApplicablePolicies({
      id: incidentAId,
      organization_id: testOrgAId,
      threat_type: 'account_takeover',
      risk_score: 85
    });

    const match = applicable.find((r) => r.policy_id === standardPolicy.id);
    assert.ok(match, 'Traditional policy without threat intel conditions must match');
    assert.strictEqual(match.action_type, 'revoke_session');

    await db.query(`DELETE FROM public.response_policies WHERE id = $1;`, [standardPolicy.id]);
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test resources', async () => {
    if (incidentAId || incidentBId) {
      await db.query(`DELETE FROM public.response_actions WHERE incident_id IN ($1, $2);`, [incidentAId, incidentBId]);
      await db.query(`DELETE FROM public.incident_ioc_matches WHERE incident_id IN ($1, $2);`, [incidentAId, incidentBId]);
      await db.query(`DELETE FROM public.incidents WHERE id IN ($1, $2);`, [incidentAId, incidentBId]);
    }
    if (policyAId || policyBId) {
      await db.query(`DELETE FROM public.response_policies WHERE id IN ($1, $2);`, [policyAId, policyBId]);
    }
    if (indicatorId) {
      await db.query(`DELETE FROM public.threat_indicators WHERE id = $1;`, [indicatorId]);
    }
    if (testDeviceId) {
      await db.query(`DELETE FROM public.devices WHERE id = $1;`, [testDeviceId]);
    }
    if (testOrgAId || testOrgBId) {
      await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgAId, testOrgBId]);
    }
  });

  console.log('\n========================================================================');
  console.log(`RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal Test Suite Error:', err);
  process.exit(1);
});
