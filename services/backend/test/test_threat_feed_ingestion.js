const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const db = require('../src/config/db');
const redis = require('../src/config/redis');
const threatFeedService = require('../src/services/threatFeedService');
const threatIntelService = require('../src/services/threatIntelService');
const schedulerService = require('../src/services/schedulerService');

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Threat Feed Ingestion & Scheduler Integration Test Suite');
  console.log('========================================================================\n');

  redis.enableMockRedis();

  let passed = 0;
  let failed = 0;

  async function testAsync(description, fn) {
    try {
      await fn();
      console.log(`  [✅] ${description}`);
      passed++;
    } catch (err) {
      console.error(`  [❌] ${description}:`, err.message);
      failed++;
    }
  }

  // Setup temporary directory for test feed files
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cyberguard-ti-test-'));

  let testOrgAId;
  let testOrgBId;
  let jsonFeedId;
  let csvFeedId;
  let textFeedId;
  let tenantFeedId;

  console.log('--- TEST GROUP 1: FEED SETUP & PARSING ---');

  await testAsync('1A: Prepares test tenant organizations', async () => {
    const orgARes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Feed Test Org A') RETURNING id;`
    );
    testOrgAId = orgARes.rows[0].id;

    const orgBRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Feed Test Org B') RETURNING id;`
    );
    testOrgBId = orgBRes.rows[0].id;

    assert.ok(testOrgAId);
    assert.ok(testOrgBId);
  });

  const jsonFeedPath = path.join(tempDir, 'sample_feed.json');
  const csvFeedPath = path.join(tempDir, 'sample_feed.csv');
  const textFeedPath = path.join(tempDir, 'sample_feed.txt');

  await testAsync('1B: Creates mock feed files on disk', async () => {
    // 1. JSON Feed
    const jsonData = {
      data: [
        { ipAddress: '198.51.100.10', abuseConfidenceScore: 92 },
        { ipAddress: '198.51.100.11', abuseConfidenceScore: 65 },
        { ipAddress: '198.51.100.10', abuseConfidenceScore: 95 } // Duplicate in same batch
      ]
    };
    fs.writeFileSync(jsonFeedPath, JSON.stringify(jsonData, null, 2), 'utf8');

    // 2. CSV Feed
    const csvData = [
      '# Threat Intel CSV Export',
      'indicator,type,severity,confidence,actor',
      '203.0.113.88,ip,high,85,APT41',
      'c2-beacon.sample.org,domain,critical,98,FIN7',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,sha256,critical,100,Lazarus',
      '203.0.113.88,ip,high,80,APT41' // Duplicate in same batch
    ].join('\n');
    fs.writeFileSync(csvFeedPath, csvData, 'utf8');

    // 3. Plain Text Feed
    const textData = [
      '# C2 IP Blocklist',
      '192.0.2.10',
      '192.0.2.11',
      'hxxps://defanged-lure[.]example[.]com/download',
      '192.0.2.10' // Duplicate in same batch
    ].join('\n');
    fs.writeFileSync(textFeedPath, textData, 'utf8');

    assert.ok(fs.existsSync(jsonFeedPath));
    assert.ok(fs.existsSync(csvFeedPath));
    assert.ok(fs.existsSync(textFeedPath));
  });

  await testAsync('1C: Registers global and tenant threat feeds in database', async () => {
    // Global JSON feed
    const jsonRes = await db.query(
      `INSERT INTO threat_feeds (
        feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, confidence_weight
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;`,
      ['Global AbuseIPDB Mock', 'abuseipdb-mock', 'abuseipdb', jsonFeedPath, 60, 1.0]
    );
    jsonFeedId = jsonRes.rows[0].id;

    // Global CSV feed
    const csvRes = await db.query(
      `INSERT INTO threat_feeds (
        feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, confidence_weight
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;`,
      ['Global Malicious CSV Mock', 'csv-mock', 'csv', csvFeedPath, 120, 0.9]
    );
    csvFeedId = csvRes.rows[0].id;

    // Global Text feed
    const textRes = await db.query(
      `INSERT INTO threat_feeds (
        feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, confidence_weight
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;`,
      ['Global Raw IP List', 'text-mock', 'text', textFeedPath, 30, 0.8]
    );
    textFeedId = textRes.rows[0].id;

    // Tenant-isolated feed for Org A
    const tenantRes = await db.query(
      `INSERT INTO threat_feeds (
        organization_id, feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, confidence_weight
      ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id;`,
      [testOrgAId, 'Org A Private MISP Feed', 'org-a-misp', 'text', textFeedPath, 60, 1.0]
    );
    tenantFeedId = tenantRes.rows[0].id;

    assert.ok(jsonFeedId);
    assert.ok(csvFeedId);
    assert.ok(textFeedId);
    assert.ok(tenantFeedId);
  });

  console.log('\n--- TEST GROUP 2: FEED INGESTION & DEDUPLICATION ---');

  await testAsync('2A: Ingests JSON feed and deduplicates indicators', async () => {
    const result = await threatFeedService.syncFeed(jsonFeedId);
    assert.strictEqual(result.success, true);
    // 3 raw entries in JSON with 1 duplicate -> exactly 2 unique indicators ingested
    assert.strictEqual(result.indicator_count, 2);

    const ind1 = await threatIntelService.lookupIOC('ip', '198.51.100.10');
    assert.ok(ind1);
    assert.strictEqual(ind1.indicator_value, '198.51.100.10');
    // Kept highest confidence (95) from duplicate entry
    assert.strictEqual(ind1.confidence_score, 95);
  });

  await testAsync('2B: Ingests CSV feed, parses headers and hash types', async () => {
    const result = await threatFeedService.syncFeed(csvFeedId);
    assert.strictEqual(result.success, true);
    // 4 rows in CSV with 1 duplicate -> exactly 3 unique indicators
    assert.strictEqual(result.indicator_count, 3);

    const hashInd = await threatIntelService.lookupIOC('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.ok(hashInd);
    assert.strictEqual(hashInd.threat_actor, 'Lazarus');

    const domainInd = await threatIntelService.lookupIOC('domain', 'c2-beacon.sample.org');
    assert.ok(domainInd);
    assert.strictEqual(domainInd.threat_actor, 'FIN7');
  });

  await testAsync('2C: Ingests plain text feed and refangs defanged URLs', async () => {
    const result = await threatFeedService.syncFeed(textFeedId);
    assert.strictEqual(result.success, true);
    // 2 IPs + 1 URL + 1 extracted domain = 4 unique indicators
    assert.strictEqual(result.indicator_count, 4);

    const urlInd = await threatIntelService.lookupIOC('url', 'https://defanged-lure.example.com/download');
    assert.ok(urlInd);
  });

  console.log('\n--- TEST GROUP 3: MULTI-TENANT INDICATOR ISOLATION ---');

  await testAsync('3A: Ingests tenant-specific feed into isolated namespace', async () => {
    const result = await threatFeedService.syncFeed(tenantFeedId);
    assert.strictEqual(result.success, true);

    // Indicator recorded under Org A
    const lookupA = await threatIntelService.lookupIOC('ip', '192.0.2.10', {
      organizationId: testOrgAId,
      bypassCache: true
    });
    assert.ok(lookupA);

    // Org B queries indicators
    const lookupB = await threatIntelService.lookupIOC('ip', '192.0.2.10', {
      organizationId: testOrgBId,
      bypassCache: true
    });
    // Org B sees the global text feed indicator if present, but never Org A's private copy
    if (lookupB) {
      assert.notStrictEqual(lookupB.organization_id, testOrgAId);
    }
  });

  console.log('\n--- TEST GROUP 4: FEED HEALTH, TIMESTAMPS & FAILURE HANDLING ---');

  await testAsync('4A: Successfully synced feed updates health timestamps', async () => {
    const feedRes = await db.query('SELECT * FROM threat_feeds WHERE id = $1', [jsonFeedId]);
    const feed = feedRes.rows[0];

    assert.strictEqual(feed.sync_status, 'success');
    assert.strictEqual(feed.consecutive_failures, 0);
    assert.strictEqual(feed.last_error, null);
    assert.ok(feed.last_sync_at);
    assert.ok(feed.next_sync_due_at);
    assert.ok(new Date(feed.next_sync_due_at) > new Date(feed.last_sync_at));
  });

  await testAsync('4B: Failed feed records error, backoff, and trips circuit breaker on 5 failures', async () => {
    // Create broken feed pointing to nonexistent file
    const brokenRes = await db.query(
      `INSERT INTO threat_feeds (
        feed_name, feed_slug, feed_type, feed_url, polling_frequency_minutes, consecutive_failures
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;`,
      ['Broken Feed', 'broken-feed', 'json_custom', '/path/to/nonexistent/feed.json', 60, 4]
    );
    const brokenFeedId = brokenRes.rows[0].id;

    // Syncing broken feed triggers 5th consecutive failure
    const syncRes = await threatFeedService.syncFeed(brokenFeedId);
    assert.strictEqual(syncRes.success, false);

    const checkedRes = await db.query('SELECT * FROM threat_feeds WHERE id = $1', [brokenFeedId]);
    const checked = checkedRes.rows[0];

    assert.strictEqual(checked.consecutive_failures, 5);
    assert.strictEqual(checked.sync_status, 'circuit_broken');
    assert.ok(checked.last_error);

    // Clean up broken feed
    await db.query('DELETE FROM threat_feeds WHERE id = $1', [brokenFeedId]);
  });

  console.log('\n--- TEST GROUP 5: SCHEDULER & ADVISORY LOCK INTEGRATION ---');

  await testAsync('5A: syncDueFeeds synchronizes feeds scheduled in the past', async () => {
    // Set text feed due date to the past
    await db.query(
      `UPDATE threat_feeds SET next_sync_due_at = NOW() - INTERVAL '5 minutes' WHERE id = $1`,
      [textFeedId]
    );

    const dueSyncResults = await threatFeedService.syncDueFeeds();
    assert.ok(Array.isArray(dueSyncResults));
    const syncedText = dueSyncResults.find((r) => r.feed_id === textFeedId);
    assert.ok(syncedText);
    assert.strictEqual(syncedText.success, true);
  });

  await testAsync('5B: processDueThreatFeeds acquires lock and processes due feeds', async () => {
    // Schedule JSON feed to be due
    await db.query(
      `UPDATE threat_feeds SET next_sync_due_at = NOW() - INTERVAL '1 minute' WHERE id = $1`,
      [jsonFeedId]
    );

    const results = await schedulerService.processDueThreatFeeds();
    assert.ok(Array.isArray(results));
  });

  await testAsync('5C: Advisory lock prevents concurrent scheduler execution', async () => {
    // Hold advisory lock on a separate connection
    const lockClient = await db.pool.connect();
    try {
      const lockRes = await lockClient.query(
        'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired;',
        [schedulerService.THREAT_FEED_LOCK_KEY]
      );
      assert.strictEqual(lockRes.rows[0].acquired, true);

      // Now processDueThreatFeeds should gracefully skip execution
      const skippedResults = await schedulerService.processDueThreatFeeds();
      assert.deepStrictEqual(skippedResults, []);
    } finally {
      await lockClient.query(
        'SELECT pg_advisory_unlock(hashtext($1));',
        [schedulerService.THREAT_FEED_LOCK_KEY]
      );
      lockClient.release();
    }
  });

  console.log('\n--- TEST GROUP 6: AUDIT LOGS & HEALTH REPORTING APIS ---');

  await testAsync('6A: Generates feed_sync_started and feed_sync_completed audit logs', async () => {
    const auditRes = await db.query(
      `SELECT action, resource_type, details
       FROM public.audit_logs
       WHERE action IN ('feed_sync_started', 'feed_sync_completed')
       ORDER BY created_at DESC
       LIMIT 5;`
    );

    assert.ok(auditRes.rows.length >= 2);
    const actions = auditRes.rows.map((r) => r.action);
    assert.strictEqual(actions.includes('feed_sync_started'), true);
    assert.strictEqual(actions.includes('feed_sync_completed'), true);
  });

  await testAsync('6B: getFeedHealth returns structured breakdown', async () => {
    const health = await threatFeedService.getFeedHealth();
    assert.ok(health.total_feeds >= 3);
    assert.ok(health.active_feeds >= 3);
    assert.ok(Array.isArray(health.feeds));
  });

  await testAsync('6C: getFeedStatistics computes correct indicator totals and success rate', async () => {
    const stats = await threatFeedService.getFeedStatistics();
    assert.ok(stats.active_feeds >= 3);
    assert.ok(stats.indicators_ingested > 0);
    assert.strictEqual(typeof stats.sync_success_rate, 'number');
    assert.ok(stats.sync_success_rate >= 0 && stats.sync_success_rate <= 100);
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test resources', async () => {
    // Delete test feeds & test orgs
    await db.query(
      `DELETE FROM threat_feeds WHERE id IN ($1, $2, $3, $4)`,
      [jsonFeedId, csvFeedId, textFeedId, tenantFeedId]
    );
    await db.query(
      `DELETE FROM threat_indicators WHERE feed_id IN ($1, $2, $3, $4) OR organization_id IN ($5, $6)`,
      [jsonFeedId, csvFeedId, textFeedId, tenantFeedId, testOrgAId, testOrgBId]
    );
    await db.query(
      `DELETE FROM organizations WHERE id IN ($1, $2)`,
      [testOrgAId, testOrgBId]
    );

    // Remove temporary directory
    fs.rmSync(tempDir, { recursive: true, force: true });
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
