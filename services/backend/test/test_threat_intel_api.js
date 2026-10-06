const assert = require('assert');
const db = require('../src/config/db');
const threatIntelService = require('../src/services/threatIntelService');
const threatFeedService = require('../src/services/threatFeedService');
const threatIntelController = require('../src/controllers/threatIntelController');
const threatIntelRoutes = require('../src/routes/threatIntelRoutes');

/**
 * CYBERGUARD — Task 5: Threat Intelligence APIs & SOC Dashboard Integration Test Suite
 *
 * Validates:
 * A. Dashboard metrics
 * B. Feed statistics
 * C. Feed health breakdown
 * D. Indicator listing pagination
 * E. Indicator lookup
 * F. Tenant isolation
 * G. Recent IOC matches
 * H. Controller responses
 * I. Route registration
 * J. Audit logs
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

function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    data: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.data = payload;
      return this;
    }
  };
  return res;
}

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Task 5: Threat Intelligence APIs & SOC Dashboard Integration');
  console.log('========================================================================\n');

  let testOrgAId = null;
  let testOrgBId = null;
  let globalFeedId = null;
  let tenantFeedId = null;
  let globalIndicatorId = null;
  let tenantIndicatorId = null;
  let testIncidentId = null;
  let matchId = null;

  console.log('--- TEST GROUP 1: DATABASE FIXTURES & TENANT SETUP ---');

  await testAsync('1A: Prepares test tenant organizations', async () => {
    const orgARes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Intel SOC Org A') RETURNING id;`
    );
    testOrgAId = orgARes.rows[0].id;

    const orgBRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Intel SOC Org B') RETURNING id;`
    );
    testOrgBId = orgBRes.rows[0].id;

    assert.ok(testOrgAId);
    assert.ok(testOrgBId);
  });

  await testAsync('1B: Prepares feeds and threat indicators', async () => {
    // 1. Global Feed
    const feedRes = await db.query(
      `INSERT INTO threat_feeds (
        feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, is_enabled, sync_status, last_sync_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id;`,
      ['Global Emerging Threats', 'global-et-mock', 'text', 'https://example.com/et.txt', 60, true, 'success']
    );
    globalFeedId = feedRes.rows[0].id;

    // 2. Tenant A Private Feed
    const tenantFeedRes = await db.query(
      `INSERT INTO threat_feeds (
        organization_id, feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, is_enabled, sync_status, last_sync_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING id;`,
      [testOrgAId, 'Org A Custom Feed', 'org-a-custom', 'text', 'https://example.com/custom.txt', 120, true, 'success']
    );
    tenantFeedId = tenantFeedRes.rows[0].id;

    // 3. Global Threat Indicator (IP, Critical)
    const ind1 = await threatIntelService.recordIndicator({
      type: 'ip',
      value: '198.51.100.201',
      feed_id: globalFeedId,
      severity: 'critical',
      confidence_score: 95,
      threat_actor: 'FancyBear',
      malware_family: 'Sofacy',
      tags: ['c2', 'apt'],
      organization_id: null
    });
    globalIndicatorId = ind1.id;

    // 4. Tenant A Private Threat Indicator (Domain, High)
    const indTenantA = await threatIntelService.recordIndicator({
      type: 'domain',
      value: 'internal-malware-target.org',
      feed_id: tenantFeedId,
      severity: 'high',
      confidence_score: 80,
      threat_actor: 'Lazarus',
      tags: ['banking', 'swift'],
      organization_id: testOrgAId
    });
    tenantIndicatorId = indTenantA.id;

    // 5. Test Incident for Org A
    const incRes = await db.query(
      `INSERT INTO incidents (
        organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id;`,
      [testOrgAId, 'technical_threat', 'system', 'critical', 95, 'Test incident with IOC match', 'open']
    );
    testIncidentId = incRes.rows[0].id;

    // 6. Test IOC match in incident_ioc_matches
    const matchRes = await db.query(
      `INSERT INTO incident_ioc_matches (
        organization_id, incident_id, indicator_id, matched_value, match_context,
        reputation_score, severity, feed_source, matched_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING id;`,
      [testOrgAId, testIncidentId, globalIndicatorId, '198.51.100.201', 'source_ip', 95, 'critical', 'Global Emerging Threats']
    );
    matchId = matchRes.rows[0].id;

    assert.ok(globalIndicatorId);
    assert.ok(tenantIndicatorId);
    assert.ok(testIncidentId);
    assert.ok(matchId);
  });

  console.log('\n--- TEST GROUP 2: DASHBOARD METRICS (CRITERION A) ---');

  await testAsync('2A: getThreatDashboard returns required metric structure and indicators', async () => {
    const dashboard = await threatIntelService.getThreatDashboard(testOrgAId);

    assert.ok(dashboard);
    assert.strictEqual(typeof dashboard.total_indicators, 'number');
    assert.strictEqual(typeof dashboard.active_indicators, 'number');
    assert.strictEqual(typeof dashboard.expired_indicators, 'number');
    assert.strictEqual(typeof dashboard.malicious_indicators, 'number');
    assert.strictEqual(typeof dashboard.total_feeds, 'number');
    assert.strictEqual(typeof dashboard.healthy_feeds, 'number');
    assert.strictEqual(typeof dashboard.failed_feeds, 'number');
    assert.strictEqual(typeof dashboard.indicators_last_24h, 'number');
    assert.strictEqual(typeof dashboard.matches_last_24h, 'number');
    assert.ok(Array.isArray(dashboard.top_indicator_types));

    // Must see at least 2 indicators (1 global + 1 tenant A)
    assert.ok(dashboard.total_indicators >= 2);
    assert.ok(dashboard.active_indicators >= 2);
    assert.ok(dashboard.malicious_indicators >= 2);
    assert.ok(dashboard.matches_last_24h >= 1);
  });

  console.log('\n--- TEST GROUP 3: FEED STATISTICS & HEALTH (CRITERIA B & C) ---');

  await testAsync('3A: getFeedStatistics computes active feeds, sync count, and success rate', async () => {
    const stats = await threatIntelService.getFeedStatistics(testOrgAId);

    assert.ok(stats);
    assert.ok(stats.active_feeds >= 2);
    assert.strictEqual(typeof stats.sync_success_rate, 'number');
    assert.ok(stats.sync_success_rate >= 0 && stats.sync_success_rate <= 100);
    assert.ok(stats.indicators_ingested >= 2);
  });

  await testAsync('3B: getFeedHealth returns structured breakdown of feeds', async () => {
    const health = await threatIntelService.getFeedHealth(testOrgAId);

    assert.ok(health);
    assert.ok(health.total_feeds >= 2);
    assert.ok(Array.isArray(health.feeds));
    const feedSlugs = health.feeds.map((f) => f.feed_slug);
    assert.ok(feedSlugs.includes('global-et-mock'));
    assert.ok(feedSlugs.includes('org-a-custom'));
  });

  console.log('\n--- TEST GROUP 4: INDICATOR LISTING & LOOKUP (CRITERIA D & E) ---');

  await testAsync('4A: getIndicators supports pagination, sorting, and limit clamping', async () => {
    const page1 = await threatIntelService.getIndicators({
      organization_id: testOrgAId,
      limit: 1,
      offset: 0
    });

    assert.ok(page1);
    assert.strictEqual(page1.limit, 1);
    assert.strictEqual(page1.offset, 0);
    assert.strictEqual(page1.indicators.length, 1);
    assert.ok(page1.total >= 2);

    // Limit clamp test: limit 500 clamped to 100
    const clamped = await threatIntelService.getIndicators({
      organization_id: testOrgAId,
      limit: 500
    });
    assert.strictEqual(clamped.limit, 100);
  });

  await testAsync('4B: getIndicators filters by type and severity', async () => {
    const ipOnly = await threatIntelService.getIndicators({
      organization_id: testOrgAId,
      type: 'ip'
    });
    assert.ok(ipOnly.indicators.every((i) => i.indicator_type === 'ip' || i.indicator_type === 'ipv4'));

    const criticalOnly = await threatIntelService.getIndicators({
      organization_id: testOrgAId,
      severity: 'critical'
    });
    assert.ok(criticalOnly.indicators.every((i) => i.severity === 'critical'));
  });

  await testAsync('4C: getIndicatorById returns indicator details with feed joined', async () => {
    const ind = await threatIntelService.getIndicatorById(globalIndicatorId, testOrgAId);
    assert.ok(ind);
    assert.strictEqual(ind.id, globalIndicatorId);
    assert.strictEqual(ind.indicator_value, '198.51.100.201');
    assert.strictEqual(ind.feed_name, 'Global Emerging Threats');
    assert.strictEqual(ind.threat_actor, 'FancyBear');
  });

  console.log('\n--- TEST GROUP 5: TENANT ISOLATION (CRITERION F) ---');

  await testAsync('5A: Org B cannot access Org A private indicators or private feeds', async () => {
    // Org A can access its private indicator
    const indA = await threatIntelService.getIndicatorById(tenantIndicatorId, testOrgAId);
    assert.ok(indA);

    // Org B CANNOT access Org A's private indicator
    const indB = await threatIntelService.getIndicatorById(tenantIndicatorId, testOrgBId);
    assert.strictEqual(indB, null);

    // Org B indicator list must NOT contain Org A's indicator
    const listB = await threatIntelService.getIndicators({
      organization_id: testOrgBId
    });
    const idsB = listB.indicators.map((i) => i.id);
    assert.strictEqual(idsB.includes(tenantIndicatorId), false);
    // Org B still sees the global indicator
    assert.strictEqual(idsB.includes(globalIndicatorId), true);
  });

  console.log('\n--- TEST GROUP 6: RECENT IOC MATCHES (CRITERION G) ---');

  await testAsync('6A: getRecentMatches returns incident correlation matches with required fields', async () => {
    const matchesA = await threatIntelService.getRecentMatches(testOrgAId);
    assert.ok(matchesA);
    assert.ok(matchesA.total >= 1);
    assert.ok(Array.isArray(matchesA.matches));

    const match = matchesA.matches.find((m) => m.id === matchId);
    assert.ok(match);
    assert.strictEqual(match.incident_id, testIncidentId);
    assert.strictEqual(match.indicator_value, '198.51.100.201');
    assert.strictEqual(match.indicator_type, 'ip');
    assert.strictEqual(match.confidence_score, 95);
    assert.strictEqual(match.source_feed, 'Global Emerging Threats');
    assert.strictEqual(match.threat_level, 'critical');
    assert.ok(match.matched_at);

    // Tenant isolation: Org B sees 0 matches
    const matchesB = await threatIntelService.getRecentMatches(testOrgBId);
    assert.strictEqual(matchesB.matches.some((m) => m.id === matchId), false);
  });

  console.log('\n--- TEST GROUP 7: CONTROLLER RESPONSES & VALIDATION (CRITERION H) ---');

  await testAsync('7A: threatIntelController.getDashboard returns 200 with dashboard metrics', async () => {
    const req = { user: { id: 'u1', organization_id: testOrgAId, role: 'admin' } };
    const res = createMockRes();

    await threatIntelController.getDashboard(req, res);
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.data.total_indicators >= 2);
    assert.ok(res.data.top_indicator_types);
  });

  await testAsync('7B: threatIntelController.listIndicators returns 200 with paginated indicators', async () => {
    const req = {
      user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' },
      query: { limit: '10', offset: '0' }
    };
    const res = createMockRes();

    await threatIntelController.listIndicators(req, res);
    assert.strictEqual(res.statusCode, 200);
    assert.ok(Array.isArray(res.data.indicators));
  });

  await testAsync('7C: threatIntelController.getIndicator handles UUID validation, 404, and 200', async () => {
    // 1. Invalid UUID -> 400
    const invalidReq = {
      user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' },
      params: { id: 'not-a-uuid' }
    };
    const invalidRes = createMockRes();
    await threatIntelController.getIndicator(invalidReq, invalidRes);
    assert.strictEqual(invalidRes.statusCode, 400);
    assert.strictEqual(invalidRes.data.error, 'INVALID_ID');

    // 2. Non-existent UUID -> 404
    const notFoundReq = {
      user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' },
      params: { id: '00000000-0000-0000-0000-000000000000' }
    };
    const notFoundRes = createMockRes();
    await threatIntelController.getIndicator(notFoundReq, notFoundRes);
    assert.strictEqual(notFoundRes.statusCode, 404);
    assert.strictEqual(notFoundRes.data.error, 'NOT_FOUND');

    // 3. Valid UUID -> 200
    const validReq = {
      user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' },
      params: { id: globalIndicatorId }
    };
    const validRes = createMockRes();
    await threatIntelController.getIndicator(validReq, validRes);
    assert.strictEqual(validRes.statusCode, 200);
    assert.strictEqual(validRes.data.id, globalIndicatorId);
  });

  await testAsync('7D: threatIntelController.getFeedHealth and getFeedStatistics return 200', async () => {
    const req = { user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' } };
    const resHealth = createMockRes();
    await threatIntelController.getFeedHealth(req, resHealth);
    assert.strictEqual(resHealth.statusCode, 200);
    assert.ok(resHealth.data.total_feeds >= 2);

    const resStats = createMockRes();
    await threatIntelController.getFeedStatistics(req, resStats);
    assert.strictEqual(resStats.statusCode, 200);
    assert.ok(resStats.data.active_feeds >= 2);
  });

  await testAsync('7E: threatIntelController.getRecentMatches returns 200 with matches', async () => {
    const req = {
      user: { id: 'u1', organization_id: testOrgAId, role: 'analyst' },
      query: { limit: '20' }
    };
    const res = createMockRes();
    await threatIntelController.getRecentMatches(req, res);
    assert.strictEqual(res.statusCode, 200);
    assert.ok(Array.isArray(res.data.matches));
  });

  console.log('\n--- TEST GROUP 8: ROUTE REGISTRATION (CRITERION I) ---');

  await testAsync('8A: threatIntelRoutes loads properly as Express Router with all handlers', () => {
    assert.ok(threatIntelRoutes);
    assert.strictEqual(typeof threatIntelRoutes, 'function');
    assert.ok(threatIntelRoutes.stack);

    // Verify registered route paths
    const routePaths = threatIntelRoutes.stack
      .filter((layer) => layer.route)
      .map((layer) => layer.route.path);

    assert.ok(routePaths.includes('/dashboard'));
    assert.ok(routePaths.includes('/indicators'));
    assert.ok(routePaths.includes('/indicators/:id'));
    assert.ok(routePaths.includes('/feed-health'));
    assert.ok(routePaths.includes('/feed-statistics'));
    assert.ok(routePaths.includes('/matches'));
  });

  console.log('\n--- TEST GROUP 9: AUDIT LOGS PERSISTENCE (CRITERION J) ---');

  await testAsync('9A: Threat intelligence audit logs are recorded in database', async () => {
    const auditRes = await db.query(
      `SELECT action, resource_type, details
       FROM public.audit_logs
       WHERE action IN ('threat_dashboard_viewed', 'threat_indicator_viewed', 'threat_feed_health_viewed')
       ORDER BY created_at DESC
       LIMIT 10;`
    );

    assert.ok(auditRes.rows.length >= 2);
    const actions = auditRes.rows.map((r) => r.action);
    assert.ok(actions.includes('threat_dashboard_viewed'));
    assert.ok(actions.includes('threat_indicator_viewed') || actions.includes('threat_feed_health_viewed'));
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test resources', async () => {
    if (matchId) {
      await db.query(`DELETE FROM public.incident_ioc_matches WHERE id = $1;`, [matchId]);
    }
    if (testIncidentId) {
      await db.query(`DELETE FROM public.incidents WHERE id = $1;`, [testIncidentId]);
    }
    if (globalIndicatorId || tenantIndicatorId) {
      await db.query(`DELETE FROM public.threat_indicators WHERE id IN ($1, $2);`, [globalIndicatorId, tenantIndicatorId]);
    }
    if (globalFeedId || tenantFeedId) {
      await db.query(`DELETE FROM public.threat_feeds WHERE id IN ($1, $2);`, [globalFeedId, tenantFeedId]);
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
