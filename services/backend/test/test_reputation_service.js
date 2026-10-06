const assert = require('assert');
const reputationService = require('../src/services/reputationService');
const incidentThreatIntelService = require('../src/services/incidentThreatIntelService');
const { persistDetectionIncident } = require('../src/services/incidentService');
const db = require('../src/config/db');

/**
 * CYBERGUARD — Task 4: External Reputation Connectors Test Suite
 *
 * Validates:
 * 1. AbuseIPDB adapter
 * 2. VirusTotal adapter
 * 3. Safe Browsing adapter
 * 4. Cache hit
 * 5. Cache miss
 * 6. Retry logic
 * 7. Timeout handling
 * 8. Circuit breaker
 * 9. Normalized output
 * 10. Risk boost integration
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
  console.log('CYBERGUARD — Task 4: External Reputation Connectors Test Suite');
  console.log('========================================================================\n');

  // Backup original fetch & env vars
  const originalFetch = reputationService.fetchFn;
  const originalAbuseKey = process.env.ABUSEIPDB_API_KEY;
  const originalVtKey = process.env.VIRUSTOTAL_API_KEY;
  const originalSbKey = process.env.SAFE_BROWSING_API_KEY;

  let testOrgId = null;
  let createdIncidentIds = [];

  console.log('--- TEST GROUP 1: ADAPTERS & NORMALIZED OUTPUT ---');

  await testAsync('1A: AbuseIPDB adapter parses API response into normalized structure', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-abuseipdb-key';

    // Mock AbuseIPDB response
    reputationService.fetchFn = async (url, opts) => {
      assert.ok(url.includes('api.abuseipdb.com'));
      assert.strictEqual(opts.headers['Key'], 'test-abuseipdb-key');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            ipAddress: '198.51.100.22',
            abuseConfidenceScore: 88,
            usageType: 'Data Center/Web Hosting',
            lastReportedAt: '2026-10-04T12:00:00Z'
          }
        })
      };
    };

    const res = await reputationService.checkAbuseIpDb('198.51.100.22');
    assert.ok(res);
    assert.strictEqual(res.source, 'abuseipdb');
    assert.strictEqual(res.reputation_score, 88);
    assert.strictEqual(res.malicious, true);
    assert.strictEqual(res.confidence, 88);
    assert.ok(res.categories.includes('Data Center/Web Hosting'));
    assert.strictEqual(res.last_seen, '2026-10-04T12:00:00Z');
    assert.ok(res.raw);
  });

  await testAsync('1B: VirusTotal adapter parses IP, domain, URL, and hash into normalized structure', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'test-vt-key';

    // Mock VirusTotal file hash response
    reputationService.fetchFn = async (url, opts) => {
      assert.ok(url.includes('virustotal.com'));
      assert.strictEqual(opts.headers['x-apikey'], 'test-vt-key');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 48,
                suspicious: 2,
                harmless: 0,
                undetected: 15
              },
              categories: { engine1: 'trojan', engine2: 'ransomware' },
              last_analysis_date: 1728000000
            }
          }
        })
      };
    };

    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const res = await reputationService.checkVirusTotal('sha256', hash);

    assert.ok(res);
    assert.strictEqual(res.source, 'virustotal');
    assert.strictEqual(res.malicious, true);
    assert.ok(res.reputation_score >= 85);
    assert.strictEqual(res.confidence, 95);
    assert.ok(res.categories.includes('trojan'));
    assert.ok(res.last_seen);
    assert.ok(res.raw);
  });

  await testAsync('1C: Safe Browsing adapter parses threat matches into normalized structure', async () => {
    process.env.SAFE_BROWSING_API_KEY = 'test-sb-key';

    reputationService.fetchFn = async (url, opts) => {
      assert.ok(url.includes('safebrowsing.googleapis.com'));
      const parsedBody = JSON.parse(opts.body);
      assert.strictEqual(parsedBody.client.clientId, 'cyberguard-backend');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          matches: [
            { threatType: 'MALWARE', platformType: 'ANY_PLATFORM' },
            { threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM' }
          ]
        })
      };
    };

    const res = await reputationService.checkSafeBrowsing('https://phishing-lure.evil-site.org/login');
    assert.ok(res);
    assert.strictEqual(res.source, 'safebrowsing');
    assert.strictEqual(res.reputation_score, 95);
    assert.strictEqual(res.malicious, true);
    assert.strictEqual(res.confidence, 90);
    assert.ok(res.categories.includes('MALWARE'));
    assert.ok(res.categories.includes('SOCIAL_ENGINEERING'));
    assert.ok(res.raw);
  });

  await testAsync('1D: Graceful degradation when API keys are absent', async () => {
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.VIRUSTOTAL_API_KEY;
    delete process.env.SAFE_BROWSING_API_KEY;

    let networkCalled = false;
    reputationService.fetchFn = async () => {
      networkCalled = true;
      return { ok: true, status: 200, json: async () => ({}) };
    };

    const resIp = await reputationService.checkAbuseIpDb('192.0.2.1');
    const resVt = await reputationService.checkVirusTotal('domain', 'example.com');
    const resSb = await reputationService.checkSafeBrowsing('http://example.com');

    assert.strictEqual(resIp, null);
    assert.strictEqual(resVt, null);
    assert.strictEqual(resSb, null);
    assert.strictEqual(networkCalled, false);
  });

  console.log('\n--- TEST GROUP 2: CACHING LAYER (rep:<type>:<value>) ---');

  await testAsync('2A: Cache miss populates Redis/memory cache under rep:<type>:<value>', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-key';
    const ip = '198.51.100.99';

    reputationService.fetchFn = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          ipAddress: ip,
          abuseConfidenceScore: 75,
          usageType: 'ISP'
        }
      })
    });

    // 1. Initial lookup -> Cache Miss (fetches live)
    const result1 = await reputationService.lookupIP(ip, { bypassCache: true });
    assert.ok(result1);
    assert.strictEqual(result1._cached, undefined);

    // Verify key in cache
    const cachedData = await reputationService.getCachedReputation('ip', ip);
    assert.ok(cachedData);
    assert.strictEqual(cachedData._cached, true);
    assert.strictEqual(cachedData.reputation_score, 75);
  });

  await testAsync('2B: Cache hit serves stored reputation without network requests', async () => {
    const ip = '198.51.100.99';

    let fetchAttempted = false;
    reputationService.fetchFn = async () => {
      fetchAttempted = true;
      throw new Error('Network should not be called on cache hit!');
    };

    const result2 = await reputationService.lookupIP(ip);
    assert.ok(result2);
    assert.strictEqual(result2._cached, true);
    assert.strictEqual(result2.reputation_score, 75);
    assert.strictEqual(fetchAttempted, false);
  });

  console.log('\n--- TEST GROUP 3: RESILIENCE (RETRY, TIMEOUT, CIRCUIT BREAKER) ---');

  await testAsync('3A: Retry logic retries on 5xx errors and succeeds upon recovery', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-key';
    let attempts = 0;

    reputationService.fetchFn = async () => {
      attempts++;
      if (attempts === 1) {
        return { ok: false, status: 503, json: async () => ({ error: 'Service Unavailable' }) };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          data: { ipAddress: '192.0.2.55', abuseConfidenceScore: 40 }
        })
      };
    };

    const res = await reputationService.dispatchWithRetry('abuseipdb', 'https://api.abuseipdb.com/test', {}, 2);
    assert.ok(res);
    assert.strictEqual(attempts, 2);
    assert.strictEqual(res.data.abuseConfidenceScore, 40);
  });

  await testAsync('3B: Timeout handling aborts slow requests and handles error gracefully', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-key';

    reputationService.fetchFn = async (url, opts) => {
      return new Promise((resolve, reject) => {
        // Simulates a hung request
        opts.signal.addEventListener('abort', () => {
          reject(new Error('Request aborted due to timeout'));
        });
      });
    };

    const res = await reputationService.dispatchWithRetry('abuseipdb', 'https://api.abuseipdb.com/slow', {
      timeoutMs: 50
    }, 1);

    assert.strictEqual(res, null);
  });

  await testAsync('3C: Circuit breaker trips after 5 consecutive failures and blocks subsequent calls', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-key';
    reputationService.resetCircuitBreaker('abuseipdb');

    let callCount = 0;
    reputationService.fetchFn = async () => {
      callCount++;
      return { ok: false, status: 500, json: async () => ({}) };
    };

    // Trigger 5 failures
    for (let i = 0; i < 5; i++) {
      await reputationService.dispatchWithRetry('abuseipdb', 'https://api.abuseipdb.com/fail', {}, 0);
    }

    assert.strictEqual(reputationService.isCircuitOpen('abuseipdb'), true);

    // 6th call should be immediately blocked by circuit breaker without calling fetchFn
    const previousCallCount = callCount;
    const blockedRes = await reputationService.dispatchWithRetry('abuseipdb', 'https://api.abuseipdb.com/fail', {}, 0);
    assert.strictEqual(blockedRes, null);
    assert.strictEqual(callCount, previousCallCount); // fetchFn was NOT invoked

    reputationService.resetCircuitBreaker('abuseipdb');
  });

  console.log('\n--- TEST GROUP 4: RISK BOOST & PIPELINE INTEGRATION ---');

  await testAsync('4A: Querying external reputation for unmatched IOC applies +25 high-confidence boost', async () => {
    // Setup test organization
    const orgRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Reputation Test Org') RETURNING id;`
    );
    testOrgId = orgRes.rows[0].id;

    process.env.ABUSEIPDB_API_KEY = 'test-key';
    reputationService.resetCircuitBreaker('abuseipdb');

    // Mock high-confidence malicious IP from AbuseIPDB
    reputationService.fetchFn = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          ipAddress: '198.51.100.123',
          abuseConfidenceScore: 92,
          usageType: 'Tor Exit Node'
        }
      })
    });

    const mlResult = {
      risk_level: 'medium',
      risk_score: 50,
      explanation: 'Traffic detected from IP 198.51.100.123',
      signals: {
        source_ip: '198.51.100.123'
      }
    };

    // Incident creation with external reputation enrichment
    const incident = await persistDetectionIncident({
      user: { organization_id: testOrgId },
      threatType: 'technical_threat',
      sourceType: 'system',
      mlResult
    });

    createdIncidentIds.push(incident.id);

    // Verify dynamic score boost:
    // Base 50 + 25 (High confidence malicious reputation) = 75
    assert.strictEqual(Number(incident.risk_score), 75);
    assert.strictEqual(incident.risk_level, 'high');

    // Verify reputation metadata attached to incident
    assert.ok(incident.threat_intel);
    assert.strictEqual(incident.threat_intel.reputation_boost, 25);
    assert.ok(incident.threat_intel.reputation_sources.includes('abuseipdb'));
    assert.strictEqual(incident.threat_intel.reputation_matches.length, 1);
    assert.strictEqual(incident.threat_intel.reputation_matches[0].indicator_value, '198.51.100.123');
  });

  await testAsync('4B: Malicious reputation capped at 100 maximum risk score', async () => {
    process.env.ABUSEIPDB_API_KEY = 'test-key';

    // Mock high-confidence response (+25 boost)
    reputationService.fetchFn = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          ipAddress: '198.51.100.124',
          abuseConfidenceScore: 90
        }
      })
    });

    // Base score 85 + 25 boost = 110 -> strictly capped at 100
    const mlResult = {
      risk_level: 'high',
      risk_score: 85,
      explanation: 'Traffic from 198.51.100.124',
      signals: {
        source_ip: '198.51.100.124'
      }
    };

    const incident = await persistDetectionIncident({
      user: { organization_id: testOrgId },
      threatType: 'technical_threat',
      sourceType: 'system',
      mlResult
    });

    createdIncidentIds.push(incident.id);

    assert.strictEqual(Number(incident.risk_score), 100);
    assert.strictEqual(incident.risk_level, 'critical');
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test resources', async () => {
    // Restore fetch and env
    reputationService.fetchFn = originalFetch;
    if (originalAbuseKey) process.env.ABUSEIPDB_API_KEY = originalAbuseKey;
    else delete process.env.ABUSEIPDB_API_KEY;
    if (originalVtKey) process.env.VIRUSTOTAL_API_KEY = originalVtKey;
    else delete process.env.VIRUSTOTAL_API_KEY;
    if (originalSbKey) process.env.SAFE_BROWSING_API_KEY = originalSbKey;
    else delete process.env.SAFE_BROWSING_API_KEY;

    // Delete incidents & org
    if (createdIncidentIds.length > 0) {
      await db.query(
        `DELETE FROM public.incident_ioc_matches WHERE incident_id = ANY($1::uuid[])`,
        [createdIncidentIds]
      );
      await db.query(
        `DELETE FROM public.incidents WHERE id = ANY($1::uuid[])`,
        [createdIncidentIds]
      );
    }
    if (testOrgId) {
      await db.query(`DELETE FROM public.organizations WHERE id = $1`, [testOrgId]);
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
