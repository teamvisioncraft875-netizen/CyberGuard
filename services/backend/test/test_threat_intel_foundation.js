const assert = require('assert');
const threatIntelService = require('../src/services/threatIntelService');
const { extractIOCs, normalizeIOC, refang } = require('../src/utils/iocExtractor');
const db = require('../src/config/db');
const redis = require('../src/config/redis');

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Threat Intelligence Foundation Test Suite');
  console.log('========================================================================\n');

  // Initialize mock Redis so test suite operates deterministically in environments without active Redis service
  redis.enableMockRedis();

  let passed = 0;
  let failed = 0;

  function test(description, fn) {
    try {
      fn();
      console.log(`  [✅] ${description}`);
      passed++;
    } catch (err) {
      console.error(`  [❌] ${description}:`, err.message);
      failed++;
    }
  }

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

  console.log('--- TEST GROUP 1: IOC EXTRACTION ---');

  test('1A: Extracts IPv4 addresses accurately from prose', () => {
    const text = 'Suspicious connection detected from 198.51.100.24 and 203.0.113.5 on port 443';
    const iocs = extractIOCs(text);
    const ips = iocs.filter((i) => i.type === 'ip').map((i) => i.value);
    assert.strictEqual(ips.includes('198.51.100.24'), true);
    assert.strictEqual(ips.includes('203.0.113.5'), true);
  });

  test('1B: Extracts IPv6 addresses accurately', () => {
    const text = 'Attack originated from 2001:db8:85a3::8a2e:370:7334 via edge gateway';
    const iocs = extractIOCs(text);
    const ipv6 = iocs.find((i) => i.type === 'ipv6');
    assert.ok(ipv6);
    assert.strictEqual(ipv6.value, '2001:db8:85a3::8a2e:370:7334');
  });

  test('1C: Extracts standalone FQDN domains', () => {
    const text = 'Host queried c2-beacon.darkthreat.org and beacon.evil-apt.com repeatedly';
    const iocs = extractIOCs(text);
    const domains = iocs.filter((i) => i.type === 'domain').map((i) => i.value);
    assert.strictEqual(domains.includes('c2-beacon.darkthreat.org'), true);
    assert.strictEqual(domains.includes('beacon.evil-apt.com'), true);
  });

  test('1D: Extracts full URLs with paths and query parameters', () => {
    const text = 'Phishing lure sent at https://secure-login.attacker.net/verify?token=xyz123#fragment';
    const iocs = extractIOCs(text);
    const url = iocs.find((i) => i.type === 'url');
    assert.ok(url);
    assert.strictEqual(url.value, 'https://secure-login.attacker.net/verify?token=xyz123');
  });

  test('1E: Extracts SHA256 hashes without triggering false SHA1 or MD5 substrings', () => {
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const text = `Dropped malicious executable with sha256: ${sha256}`;
    const iocs = extractIOCs(text);
    const hashes = iocs.filter((i) => i.type === 'sha256');
    assert.strictEqual(hashes.length, 1);
    assert.strictEqual(hashes[0].value, sha256);
    // Boundary protection: should not extract false MD5 or SHA1 from inside the 64-char hex
    const md5s = iocs.filter((i) => i.type === 'md5');
    const sha1s = iocs.filter((i) => i.type === 'sha1');
    assert.strictEqual(md5s.length, 0);
    assert.strictEqual(sha1s.length, 0);
  });

  test('1F: Extracts SHA1 and MD5 hashes independently', () => {
    const sha1 = '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12';
    const md5 = '5d41402abc4b2a76b9719d911017c592';
    const text = `File signatures: sha1=${sha1} md5=${md5}`;
    const iocs = extractIOCs(text);
    const foundSha1 = iocs.find((i) => i.type === 'sha1');
    const foundMd5 = iocs.find((i) => i.type === 'md5');
    assert.ok(foundSha1);
    assert.strictEqual(foundSha1.value, sha1);
    assert.ok(foundMd5);
    assert.strictEqual(foundMd5.value, md5);
  });

  test('1G: Successfully handles security-defanged indicators', () => {
    const text = 'Observed hxxps://malicious[.]example[.]com/payload and IP 192[.]0[.]2[.]100';
    const iocs = extractIOCs(text);
    const ip = iocs.find((i) => i.type === 'ip');
    const domain = iocs.find((i) => i.type === 'domain');
    const url = iocs.find((i) => i.type === 'url');
    assert.ok(ip);
    assert.strictEqual(ip.value, '192.0.2.100');
    assert.ok(domain);
    assert.strictEqual(domain.value, 'malicious.example.com');
    assert.ok(url);
    assert.strictEqual(url.value, 'https://malicious.example.com/payload');
  });

  console.log('\n--- TEST GROUP 2: IOC NORMALIZATION ---');

  test('2A: Normalizes IPv4 address format', () => {
    const norm = normalizeIOC('ip', '  198.51.100.1  ');
    assert.deepStrictEqual(norm, { type: 'ip', value: '198.51.100.1' });
    const invalid = normalizeIOC('ip', '999.999.999.999');
    assert.strictEqual(invalid, null);
  });

  test('2B: Normalizes domain to lowercase and strips schemes/ports', () => {
    const norm = normalizeIOC('domain', 'HTTP://Evil-Site.Com:8080/path');
    assert.deepStrictEqual(norm, { type: 'domain', value: 'evil-site.com' });
  });

  test('2C: Normalizes URL and removes hash fragments', () => {
    const norm = normalizeIOC('url', 'HTTPS://PHISH.COM/login?user=admin#section');
    assert.deepStrictEqual(norm, { type: 'url', value: 'https://phish.com/login?user=admin' });
  });

  test('2D: Normalizes hashes to lowercase hex', () => {
    const norm = normalizeIOC('sha256', 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855');
    assert.deepStrictEqual(norm, {
      type: 'sha256',
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    });
  });

  console.log('\n--- TEST GROUP 3: IOC DEDUPLICATION ---');

  test('3A: Deduplicates repeated occurrences in raw text', () => {
    const text = `
      Malicious IP: 198.51.100.77
      Same IP again: 198.51.100.77
      Third mention: 198.51.100.77
      Domain: evil.com
      Same domain: evil.com
      Hash: 5d41402abc4b2a76b9719d911017c592
      Same hash: 5d41402abc4b2a76b9719d911017c592
    `;
    const iocs = extractIOCs(text);
    assert.strictEqual(iocs.length, 3);
    const counts = {};
    for (const ioc of iocs) {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    }
    assert.strictEqual(counts.ip, 1);
    assert.strictEqual(counts.domain, 1);
    assert.strictEqual(counts.md5, 1);
  });

  console.log('\n--- TEST GROUP 4: CACHE HIT / MISS BEHAVIOR ---');

  await testAsync('4A: Returns null on cache miss for unrecorded IOC', async () => {
    const cached = await threatIntelService.getCachedIOC('ip', '203.0.113.250');
    assert.strictEqual(cached, null);
  });

  await testAsync('4B: Stores and retrieves cached IOC correctly (Cache Hit)', async () => {
    const mockIndicator = {
      indicator_type: 'ip',
      indicator_value: '203.0.113.250',
      severity: 'critical',
      confidence_score: 95,
      threat_actor: 'APT29'
    };

    const saved = await threatIntelService.cacheIOC('ip', '203.0.113.250', mockIndicator, 60);
    assert.strictEqual(saved, true);

    const hit = await threatIntelService.getCachedIOC('ip', '203.0.113.250');
    assert.ok(hit);
    assert.strictEqual(hit.indicator_value, '203.0.113.250');
    assert.strictEqual(hit.confidence_score, 95);
    assert.strictEqual(hit.threat_actor, 'APT29');
  });

  console.log('\n--- TEST GROUP 5: DATABASE & MULTI-TENANT ISOLATION ---');

  let testOrgAId;
  let testOrgBId;

  await testAsync('5A: Sets up test organizations in database', async () => {
    const orgARes = await db.query(
      `INSERT INTO organizations (name) VALUES ('ThreatIntel Test Org A') RETURNING id;`
    );
    testOrgAId = orgARes.rows[0].id;

    const orgBRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('ThreatIntel Test Org B') RETURNING id;`
    );
    testOrgBId = orgBRes.rows[0].id;

    assert.ok(testOrgAId);
    assert.ok(testOrgBId);
  });

  await testAsync('5B: Records a global indicator and retrieves it', async () => {
    const recorded = await threatIntelService.recordIndicator({
      type: 'ip',
      value: '198.51.100.99',
      organization_id: null, // Global
      severity: 'high',
      confidence_score: 85,
      threat_actor: 'Lazarus Group',
      tags: ['c2', 'botnet']
    });

    assert.ok(recorded.id);
    assert.strictEqual(recorded.indicator_value, '198.51.100.99');
    assert.strictEqual(recorded.confidence_score, 85);

    // Lookup as Org A (should see global indicator)
    const lookupOrgA = await threatIntelService.lookupIOC('ip', '198.51.100.99', {
      organizationId: testOrgAId
    });
    assert.ok(lookupOrgA);
    assert.strictEqual(lookupOrgA.indicator_value, '198.51.100.99');
    assert.strictEqual(lookupOrgA.threat_actor, 'Lazarus Group');
  });

  await testAsync('5C: Enforces tenant isolation on private indicators', async () => {
    // Org A registers a proprietary IOC
    await threatIntelService.recordIndicator({
      type: 'domain',
      value: 'proprietary-threat-org-a.com',
      organization_id: testOrgAId,
      severity: 'critical',
      confidence_score: 99,
      threat_actor: 'Targeted Campaign'
    });

    // Org A can find it
    const lookupA = await threatIntelService.lookupIOC('domain', 'proprietary-threat-org-a.com', {
      organizationId: testOrgAId,
      bypassCache: true
    });
    assert.ok(lookupA);
    assert.strictEqual(lookupA.organization_id, testOrgAId);

    // Org B CANNOT find it (tenant isolation)
    const lookupB = await threatIntelService.lookupIOC('domain', 'proprietary-threat-org-a.com', {
      organizationId: testOrgBId,
      bypassCache: true
    });
    assert.strictEqual(lookupB, null);
  });

  await testAsync('5D: lookupIOC populates cache on initial miss and hits cache subsequently', async () => {
    // Lookup with bypassCache to test cold path
    const coldResult = await threatIntelService.lookupIOC('ip', '198.51.100.99', {
      organizationId: testOrgAId,
      bypassCache: true
    });
    assert.ok(coldResult);
    assert.strictEqual(coldResult._cached, undefined);

    // Warm path lookup (should return from Redis)
    const warmResult = await threatIntelService.lookupIOC('ip', '198.51.100.99', {
      organizationId: testOrgAId
    });
    assert.ok(warmResult);
    assert.strictEqual(warmResult._cached, true);
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test records', async () => {
    if (testOrgAId && testOrgBId) {
      await db.query(`DELETE FROM threat_indicators WHERE organization_id IN ($1, $2) OR indicator_value = '198.51.100.99'`, [testOrgAId, testOrgBId]);
      await db.query(`DELETE FROM organizations WHERE id IN ($1, $2)`, [testOrgAId, testOrgBId]);
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
