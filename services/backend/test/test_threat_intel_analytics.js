const assert = require('assert');
const db = require('../src/config/db');
const threatIntelAnalyticsService = require('../src/services/threatIntelAnalyticsService');
const reputationService = require('../src/services/reputationService');
const threatIntelAnalyticsController = require('../src/controllers/threatIntelAnalyticsController');
const threatIntelAnalyticsRoutes = require('../src/routes/threatIntelAnalyticsRoutes');
const threatIntelRoutes = require('../src/routes/threatIntelRoutes');

/**
 * CYBERGUARD — Threat Intelligence Analytics & Executive Reporting Test Suite
 *
 * Validates:
 * A. Threat trends calculations (24h, 7d, 30d)
 * B. Top indicators aggregation
 * C. Top malicious domains
 * D. Top malicious IPs
 * E. Feed performance metrics
 * F. IOC correlation effectiveness
 * G. Reputation provider metrics
 * H. Executive summary generation (pure analytics, recommendations derived from metrics)
 * I. Multi-tenant isolation (Org A vs Org B)
 * J. Controller responses (all 8 endpoints)
 * K. Route registration
 * L. Audit log persistence (threat_analytics_viewed, threat_executive_report_viewed)
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
  return {
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
}

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Threat Intelligence Analytics & Executive Reporting Test Suite');
  console.log('========================================================================\n');

  let testOrgAId = null;
  let testOrgBId = null;
  let feedA1Id = null;
  let feedA2Id = null;
  let feedBId = null;
  let indIpId = null;
  let indDomainId = null;
  let indUrlId = null;
  let indShaId = null;
  let indOrgBId = null;
  let incidentA1Id = null;
  let incidentA2Id = null;
  let incidentBId = null;
  const matchIds = [];
  let responseActionId = null;

  try {
    console.log('--- TEST GROUP 1: FIXTURES SETUP & TENANT ISOLATION INITIALIZATION ---');

    await testAsync('1A: Prepares test organizations Org A and Org B', async () => {
      const orgARes = await db.query(
        `INSERT INTO organizations (name) VALUES ('Threat Analytics Org A') RETURNING id;`
      );
      testOrgAId = orgARes.rows[0].id;

      const orgBRes = await db.query(
        `INSERT INTO organizations (name) VALUES ('Threat Analytics Org B') RETURNING id;`
      );
      testOrgBId = orgBRes.rows[0].id;

      assert.ok(testOrgAId);
      assert.ok(testOrgBId);
    });

    await testAsync('1B: Prepares feeds (healthy & circuit broken) for Org A and Org B', async () => {
      // Org A healthy feed
      const f1 = await db.query(
        `INSERT INTO threat_feeds (
          organization_id, feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, is_enabled, sync_status, consecutive_failures, last_sync_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id;`,
        [testOrgAId, 'Org A Verified C2 Feed', 'org-a-c2-feed', 'text', 'https://example.com/c2.txt', 30, true, 'success', 0]
      );
      feedA1Id = f1.rows[0].id;

      // Org A circuit broken feed (consecutive_failures >= 5, sync_status = 'failed')
      const f2 = await db.query(
        `INSERT INTO threat_feeds (
          organization_id, feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, is_enabled, sync_status, consecutive_failures, last_sync_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id;`,
        [testOrgAId, 'Org A Deprecated Feed', 'org-a-deprecated-feed', 'text', 'https://example.com/dead.txt', 60, false, 'failed', 6]
      );
      feedA2Id = f2.rows[0].id;

      // Org B feed
      const fb = await db.query(
        `INSERT INTO threat_feeds (
          organization_id, feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, is_enabled, sync_status, consecutive_failures, last_sync_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id;`,
        [testOrgBId, 'Org B Custom Feed', 'org-b-custom-feed', 'text', 'https://example.com/b.txt', 60, true, 'success', 0]
      );
      feedBId = fb.rows[0].id;

      assert.ok(feedA1Id);
      assert.ok(feedA2Id);
      assert.ok(feedBId);
    });

    await testAsync('1C: Prepares indicators across multiple types for Org A and Org B', async () => {
      const now = new Date();

      // IP indicator for Org A
      const ipRes = await db.query(
        `INSERT INTO threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value, confidence_score, severity, is_active, created_at
        ) VALUES ($1, $2, 'ip', '198.51.100.99', 95, 'critical', true, $3) RETURNING id;`,
        [testOrgAId, feedA1Id, now]
      );
      indIpId = ipRes.rows[0].id;

      // Domain indicator for Org A
      const domRes = await db.query(
        `INSERT INTO threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value, confidence_score, severity, is_active, created_at
        ) VALUES ($1, $2, 'domain', 'evil-command-analytics.com', 88, 'high', true, $3) RETURNING id;`,
        [testOrgAId, feedA1Id, now]
      );
      indDomainId = domRes.rows[0].id;

      // URL indicator for Org A
      const urlRes = await db.query(
        `INSERT INTO threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value, confidence_score, severity, is_active, created_at
        ) VALUES ($1, $2, 'url', 'http://evil-command-analytics.com/payload.exe', 85, 'high', true, $3) RETURNING id;`,
        [testOrgAId, feedA1Id, now]
      );
      indUrlId = urlRes.rows[0].id;

      // SHA256 indicator for Org A
      const shaRes = await db.query(
        `INSERT INTO threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value, confidence_score, severity, is_active, created_at
        ) VALUES ($1, $2, 'sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 75, 'medium', true, $3) RETURNING id;`,
        [testOrgAId, feedA1Id, now]
      );
      indShaId = shaRes.rows[0].id;

      // Org B indicator
      const bRes = await db.query(
        `INSERT INTO threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value, confidence_score, severity, is_active, created_at
        ) VALUES ($1, $2, 'domain', 'org-b-isolated-threat.com', 90, 'high', true, $3) RETURNING id;`,
        [testOrgBId, feedBId, now]
      );
      indOrgBId = bRes.rows[0].id;

      assert.ok(indIpId);
      assert.ok(indDomainId);
      assert.ok(indUrlId);
      assert.ok(indShaId);
      assert.ok(indOrgBId);
    });

    await testAsync('1D: Prepares incidents, matches, and response actions for Org A & B', async () => {
      // Org A Incidents
      const incA1 = await db.query(
        `INSERT INTO incidents (
          organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
        ) VALUES ($1, 'technical_threat', 'system', 'critical', 95, 'APT C2 Traffic Detected', 'investigating', NOW()) RETURNING id;`,
        [testOrgAId]
      );
      incidentA1Id = incA1.rows[0].id;

      const incA2 = await db.query(
        `INSERT INTO incidents (
          organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
        ) VALUES ($1, 'technical_threat', 'system', 'high', 85, 'Suspicious Outbound Beaconing', 'open', NOW()) RETURNING id;`,
        [testOrgAId]
      );
      incidentA2Id = incA2.rows[0].id;

      // Org B Incident
      const incB = await db.query(
        `INSERT INTO incidents (
          organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, created_at
        ) VALUES ($1, 'technical_threat', 'system', 'medium', 50, 'Org B Phishing Lure', 'open', NOW()) RETURNING id;`,
        [testOrgBId]
      );
      incidentBId = incB.rows[0].id;

      // Matches for Org A (linking IP and Domain using valid match_context)
      const m1 = await db.query(
        `INSERT INTO incident_ioc_matches (
          incident_id, organization_id, indicator_id, matched_value, match_context,
          feed_source, reputation_score, severity, matched_at
        ) VALUES ($1, $2, $3, $4, 'source_ip', $5, $6, $7, NOW()) RETURNING id;`,
        [incidentA1Id, testOrgAId, indIpId, '198.51.100.99', 'Org A Verified C2 Feed', 95, 'critical']
      );
      matchIds.push(m1.rows[0].id);

      const m2 = await db.query(
        `INSERT INTO incident_ioc_matches (
          incident_id, organization_id, indicator_id, matched_value, match_context,
          feed_source, reputation_score, severity, matched_at
        ) VALUES ($1, $2, $3, $4, 'url_domain', $5, $6, $7, NOW()) RETURNING id;`,
        [incidentA1Id, testOrgAId, indDomainId, 'evil-command-analytics.com', 'Org A Verified C2 Feed', 88, 'high']
      );
      matchIds.push(m2.rows[0].id);

      const m3 = await db.query(
        `INSERT INTO incident_ioc_matches (
          incident_id, organization_id, indicator_id, matched_value, match_context,
          feed_source, reputation_score, severity, matched_at
        ) VALUES ($1, $2, $3, $4, 'url_domain', $5, $6, $7, NOW()) RETURNING id;`,
        [incidentA2Id, testOrgAId, indDomainId, 'evil-command-analytics.com', 'Org A Verified C2 Feed', 88, 'high']
      );
      matchIds.push(m3.rows[0].id);

      // Org B match
      const mb = await db.query(
        `INSERT INTO incident_ioc_matches (
          incident_id, organization_id, indicator_id, matched_value, match_context,
          feed_source, reputation_score, severity, matched_at
        ) VALUES ($1, $2, $3, $4, 'url_domain', $5, $6, $7, NOW()) RETURNING id;`,
        [incidentBId, testOrgBId, indOrgBId, 'org-b-isolated-threat.com', 'Org B Custom Feed', 90, 'high']
      );
      matchIds.push(mb.rows[0].id);

      // Automated Response Action in Org A (block_ip executed)
      const ra = await db.query(
        `INSERT INTO response_actions (
          organization_id, incident_id, action_type, action_mode, status, target, metadata
        ) VALUES ($1, $2, 'block_ip', 'live', 'executed', '{"ip_address":"198.51.100.99"}'::jsonb, '{"indicator_value":"198.51.100.99"}'::jsonb) RETURNING id;`,
        [testOrgAId, incidentA1Id]
      );
      responseActionId = ra.rows[0].id;

      assert.strictEqual(matchIds.length, 4);
      assert.ok(responseActionId);
    });

    console.log('\n--- TEST GROUP 2: CRITERION A — THREAT TRENDS CALCULATIONS ---');

    await testAsync('2A: Calculates indicators, matches, and enriched incident counts over 24h, 7d, 30d', async () => {
      const trends = await threatIntelAnalyticsService.getThreatTrends(testOrgAId);

      assert.strictEqual(typeof trends.indicators_last_24h, 'number');
      assert.strictEqual(typeof trends.indicators_last_7d, 'number');
      assert.strictEqual(typeof trends.indicators_last_30d, 'number');
      assert.strictEqual(typeof trends.matches_last_24h, 'number');
      assert.strictEqual(typeof trends.matches_last_7d, 'number');
      assert.strictEqual(typeof trends.matches_last_30d, 'number');
      assert.strictEqual(typeof trends.incidents_enriched_last_24h, 'number');
      assert.strictEqual(typeof trends.incidents_enriched_last_7d, 'number');
      assert.strictEqual(typeof trends.incidents_enriched_last_30d, 'number');

      // Org A has at least 4 indicators created in the last 24h
      assert.ok(trends.indicators_last_24h >= 4);
      assert.ok(trends.indicators_last_7d >= 4);
      assert.ok(trends.indicators_last_30d >= 4);

      // Org A has 3 matches in the last 24h
      assert.strictEqual(trends.matches_last_24h, 3);
      assert.strictEqual(trends.matches_last_7d, 3);
      assert.strictEqual(trends.matches_last_30d, 3);

      // Org A has 2 distinct incidents enriched in the last 24h
      assert.strictEqual(trends.incidents_enriched_last_24h, 2);
    });

    console.log('\n--- TEST GROUP 3: CRITERION B — TOP INDICATOR TYPES AGGREGATION ---');

    await testAsync('3A: Aggregates top indicator types ordered by frequency', async () => {
      const topTypes = await threatIntelAnalyticsService.getTopIndicators(testOrgAId, { limit: 10 });

      assert.ok(Array.isArray(topTypes));
      assert.ok(topTypes.length >= 4);

      const types = topTypes.map((t) => t.indicator_type);
      assert.ok(types.includes('ip'));
      assert.ok(types.includes('domain'));
      assert.ok(types.includes('url'));
      assert.ok(types.includes('sha256'));

      topTypes.forEach((item) => {
        assert.ok(item.indicator_type);
        assert.strictEqual(typeof item.count, 'number');
        assert.ok(item.count >= 1);
      });
    });

    console.log('\n--- TEST GROUP 4: CRITERION C — TOP MALICIOUS DOMAINS ---');

    await testAsync('4A: Identifies top malicious domains with match counts and confidence scores', async () => {
      const topDomains = await threatIntelAnalyticsService.getTopMaliciousDomains(testOrgAId, { limit: 5 });

      assert.ok(Array.isArray(topDomains));
      const targetDomain = topDomains.find((d) => d.domain === 'evil-command-analytics.com');
      assert.ok(targetDomain, 'evil-command-analytics.com must be in top malicious domains for Org A');
      assert.strictEqual(targetDomain.match_count, 2, 'Domain was matched in two incidents');
      assert.strictEqual(targetDomain.confidence_score, 88);
    });

    console.log('\n--- TEST GROUP 5: CRITERION D — TOP MALICIOUS IPS ---');

    await testAsync('5A: Identifies top malicious IPs with match counts and confidence scores', async () => {
      const topIPs = await threatIntelAnalyticsService.getTopMaliciousIPs(testOrgAId, { limit: 5 });

      assert.ok(Array.isArray(topIPs));
      const targetIP = topIPs.find((ip) => ip.ip === '198.51.100.99');
      assert.ok(targetIP, '198.51.100.99 must be in top malicious IPs for Org A');
      assert.strictEqual(targetIP.match_count, 1);
      assert.strictEqual(targetIP.confidence_score, 95);
    });

    console.log('\n--- TEST GROUP 6: CRITERION E — FEED PERFORMANCE METRICS ---');

    await testAsync('6A: Computes feed counts, health status, and failure rates', async () => {
      const feedMetrics = await threatIntelAnalyticsService.getFeedPerformanceMetrics(testOrgAId);

      assert.strictEqual(typeof feedMetrics.total_feeds, 'number');
      assert.strictEqual(typeof feedMetrics.healthy_feeds, 'number');
      assert.strictEqual(typeof feedMetrics.failed_feeds, 'number');
      assert.strictEqual(typeof feedMetrics.circuit_broken_feeds, 'number');
      assert.strictEqual(typeof feedMetrics.average_sync_duration, 'number');
      assert.strictEqual(typeof feedMetrics.average_success_rate, 'number');
      assert.strictEqual(typeof feedMetrics.indicators_ingested_last_24h, 'number');

      assert.strictEqual(feedMetrics.total_feeds, 2);
      assert.strictEqual(feedMetrics.healthy_feeds, 1);
      assert.strictEqual(feedMetrics.failed_feeds, 1);
      assert.strictEqual(feedMetrics.circuit_broken_feeds, 1);
      assert.strictEqual(feedMetrics.average_success_rate, 50);
      assert.strictEqual(feedMetrics.indicators_ingested_last_24h, 4);
    });

    console.log('\n--- TEST GROUP 7: CRITERION F — IOC CORRELATION EFFECTIVENESS ---');

    await testAsync('7A: Computes total matches, unique indicators, enrichment ratio, and malicious breakdown', async () => {
      const iocStats = await threatIntelAnalyticsService.getIOCMatchStatistics(testOrgAId);

      assert.strictEqual(iocStats.total_ioc_matches, 3);
      assert.strictEqual(iocStats.unique_indicators_matched, 2); // IP and Domain
      assert.strictEqual(iocStats.incidents_enriched, 2);
      assert.strictEqual(iocStats.avg_matches_per_incident, 1.5); // 3 matches / 2 incidents = 1.5
      assert.strictEqual(iocStats.malicious_matches, 3); // 2 critical/high matches
      assert.strictEqual(iocStats.benign_matches, 0);
    });

    console.log('\n--- TEST GROUP 8: CRITERION G — REPUTATION PROVIDER METRICS ---');

    await testAsync('8A: Tracks external provider lookups, hit rates, and latency', async () => {
      const origKey = process.env.ABUSEIPDB_API_KEY;
      const origFetch = reputationService.fetchFn;

      try {
        process.env.ABUSEIPDB_API_KEY = 'test-key';
        reputationService.fetchFn = async () => ({
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              ipAddress: '198.51.100.99',
              abuseConfidenceScore: 90,
              totalReports: 15,
              usageType: 'Data Center',
              lastReportedAt: new Date().toISOString()
            }
          })
        });

        // 1. Initial lookup -> dispatch to AbuseIPDB -> cache miss, writes cache
        await reputationService.lookup('198.51.100.99', 'ip', { bypassCache: true });
        // 2. Second lookup -> cache hit!
        await reputationService.lookup('198.51.100.99', 'ip');

        const metrics = await threatIntelAnalyticsService.getReputationProviderMetrics(testOrgAId);

        assert.strictEqual(typeof metrics.virustotal_queries, 'number');
        assert.strictEqual(typeof metrics.abuseipdb_queries, 'number');
        assert.strictEqual(typeof metrics.safebrowsing_queries, 'number');
        assert.strictEqual(typeof metrics.cache_hits, 'number');
        assert.strictEqual(typeof metrics.cache_misses, 'number');
        assert.strictEqual(typeof metrics.avg_provider_response_time, 'number');

        assert.ok(metrics.cache_hits >= 1);
        assert.ok(metrics.abuseipdb_queries >= 1);
      } finally {
        process.env.ABUSEIPDB_API_KEY = origKey;
        reputationService.fetchFn = origFetch;
      }
    });

    console.log('\n--- TEST GROUP 9: CRITERION H — EXECUTIVE SUMMARY GENERATOR ---');

    await testAsync('9A: Generates executive report with operational metrics and analytics-driven recommendations', async () => {
      const summary = await threatIntelAnalyticsService.getExecutiveSummary(testOrgAId);

      assert.strictEqual(summary.reporting_period, 'last_30_days');
      assert.ok(summary.total_indicators >= 4);
      assert.strictEqual(summary.indicators_blocked, 1);
      assert.strictEqual(summary.malicious_iocs_detected, 3);
      assert.strictEqual(summary.incidents_enriched, 2);
      assert.strictEqual(summary.top_threat_type, 'technical_threat');
      assert.strictEqual(summary.top_feed, 'Org A Verified C2 Feed');

      // Recommendations must be an array of strings derived from metrics
      assert.ok(Array.isArray(summary.recommendations));
      assert.ok(summary.recommendations.length > 0);
      assert.strictEqual(typeof summary.recommendations[0], 'string');

      // Recommendation should flag the failing/circuit-broken feed
      const feedRec = summary.recommendations.find((r) => r.includes('failing or circuit-broken feed'));
      assert.ok(feedRec, 'Expected recommendation alerting about circuit-broken feed');
    });

    await testAsync('9B: Validates generateExecutiveSummary alias works identically', async () => {
      const aliasSummary = await threatIntelAnalyticsService.generateExecutiveSummary(testOrgAId);
      assert.strictEqual(aliasSummary.reporting_period, 'last_30_days');
      assert.ok(aliasSummary.total_indicators >= 4);
      assert.strictEqual(aliasSummary.indicators_blocked, 1);
    });

    console.log('\n--- TEST GROUP 10: CRITERION I — MULTI-TENANT ISOLATION ---');

    await testAsync('10A: Org B cannot view Org A trends, indicators, domains, or matches', async () => {
      const orgBTrends = await threatIntelAnalyticsService.getThreatTrends(testOrgBId);
      assert.strictEqual(orgBTrends.matches_last_24h, 1, 'Org B only has 1 match');
      assert.strictEqual(orgBTrends.incidents_enriched_last_24h, 1, 'Org B only has 1 incident enriched');

      const orgBDomains = await threatIntelAnalyticsService.getTopMaliciousDomains(testOrgBId);
      const leakedDomain = orgBDomains.find((d) => d.domain === 'evil-command-analytics.com');
      assert.strictEqual(leakedDomain, undefined, 'Org A domain must never leak into Org B top domains');

      const orgBTarget = orgBDomains.find((d) => d.domain === 'org-b-isolated-threat.com');
      assert.ok(orgBTarget, 'Org B sees its own domain');

      const orgBIOCStats = await threatIntelAnalyticsService.getIOCMatchStatistics(testOrgBId);
      assert.strictEqual(orgBIOCStats.total_ioc_matches, 1);
      assert.strictEqual(orgBIOCStats.incidents_enriched, 1);
    });

    console.log('\n--- TEST GROUP 11: CRITERION J — CONTROLLER RESPONSES ---');

    await testAsync('11A: Controller getTrends returns 200 and trends payload', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getTrends(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(res.data.indicators_last_24h !== undefined);
      assert.ok(res.data.matches_last_24h !== undefined);
    });

    await testAsync('11B: Controller getTopIndicators returns 200 and indicator types list', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' }, query: { limit: '5' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getTopIndicators(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(Array.isArray(res.data));
    });

    await testAsync('11C: Controller getTopDomains returns 200 and malicious domains', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' }, query: {} };
      const res = createMockRes();
      await threatIntelAnalyticsController.getTopDomains(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(Array.isArray(res.data));
    });

    await testAsync('11D: Controller getTopIPs returns 200 and malicious IPs', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' }, query: {} };
      const res = createMockRes();
      await threatIntelAnalyticsController.getTopIPs(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(Array.isArray(res.data));
    });

    await testAsync('11E: Controller getFeedPerformance returns 200 and feed performance metrics', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getFeedPerformance(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(res.data.total_feeds !== undefined);
      assert.ok(res.data.circuit_broken_feeds !== undefined);
    });

    await testAsync('11F: Controller getIOCStats returns 200 and correlation effectiveness', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getIOCStats(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.data.total_ioc_matches, 3);
    });

    await testAsync('11G: Controller getProviderMetrics returns 200 and external reputation metrics', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getProviderMetrics(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.ok(res.data.virustotal_queries !== undefined);
      assert.ok(res.data.cache_hits !== undefined);
    });

    await testAsync('11H: Controller getExecutiveSummary returns 200 and executive report', async () => {
      const req = { user: { id: null, organization_id: testOrgAId, role: 'analyst' }, query: { period: 'last_30_days' } };
      const res = createMockRes();
      await threatIntelAnalyticsController.getExecutiveSummary(req, res);

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.data.reporting_period, 'last_30_days');
      assert.ok(Array.isArray(res.data.recommendations));
    });

    console.log('\n--- TEST GROUP 12: CRITERION K — ROUTE REGISTRATION ---');

    await testAsync('12A: Registers all 8 endpoints in threatIntelAnalyticsRoutes', async () => {
      const registeredPaths = threatIntelAnalyticsRoutes.stack
        .filter((layer) => layer.route)
        .map((layer) => layer.route.path);

      assert.ok(registeredPaths.includes('/trends'));
      assert.ok(registeredPaths.includes('/top-indicators'));
      assert.ok(registeredPaths.includes('/top-domains'));
      assert.ok(registeredPaths.includes('/top-ips'));
      assert.ok(registeredPaths.includes('/feed-performance'));
      assert.ok(registeredPaths.includes('/ioc-stats'));
      assert.ok(registeredPaths.includes('/provider-metrics'));
      assert.ok(registeredPaths.includes('/executive-summary'));
    });

    await testAsync('12B: Mounts /analytics sub-router in threatIntelRoutes', async () => {
      const routerLayers = threatIntelRoutes.stack.filter((l) => l.name === 'router');
      assert.ok(routerLayers.length > 0, 'threatIntelRoutes must mount analytics router');
    });

    console.log('\n--- TEST GROUP 13: CRITERION L — AUDIT LOG PERSISTENCE ---');

    await testAsync('13A: Records threat_analytics_viewed and threat_executive_report_viewed audit logs', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type
         FROM public.audit_logs
         WHERE action IN ('threat_analytics_viewed', 'threat_executive_report_viewed')
           AND organization_id = $1;`,
        [testOrgAId]
      );

      assert.ok(auditRes.rows.length >= 2, 'Expected at least 2 audit entries for Org A analytics/reporting');
      const actions = auditRes.rows.map((r) => r.action);
      assert.ok(actions.includes('threat_analytics_viewed'), 'Must log threat_analytics_viewed');
      assert.ok(actions.includes('threat_executive_report_viewed'), 'Must log threat_executive_report_viewed');
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    try {
      if (responseActionId) {
        await db.query(`DELETE FROM public.response_actions WHERE id = $1;`, [responseActionId]);
      }
      if (matchIds.length > 0) {
        await db.query(`DELETE FROM public.incident_ioc_matches WHERE id = ANY($1::uuid[]);`, [matchIds]);
      }
      if (incidentA1Id || incidentA2Id || incidentBId) {
        await db.query(`DELETE FROM public.incidents WHERE id IN ($1, $2, $3);`, [incidentA1Id, incidentA2Id, incidentBId]);
      }
      if (indIpId || indDomainId || indUrlId || indShaId || indOrgBId) {
        await db.query(
          `DELETE FROM public.threat_indicators WHERE id IN ($1, $2, $3, $4, $5);`,
          [indIpId, indDomainId, indUrlId, indShaId, indOrgBId]
        );
      }
      if (feedA1Id || feedA2Id || feedBId) {
        await db.query(`DELETE FROM public.threat_feeds WHERE id IN ($1, $2, $3);`, [feedA1Id, feedA2Id, feedBId]);
      }
      if (testOrgAId || testOrgBId) {
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id IN ($1, $2);`, [testOrgAId, testOrgBId]);
        await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgAId, testOrgBId]);
      }
      console.log('  [✅] Test fixtures cleaned up successfully');
    } catch (cleanupErr) {
      console.error('  [⚠️] Fixture cleanup warning:', cleanupErr.message);
    }
  }

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
