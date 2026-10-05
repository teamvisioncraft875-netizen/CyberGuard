const assert = require('assert');
const path = require('path');
const db = require('../src/config/db');
const redis = require('../src/config/redis');
const threatIntelService = require('../src/services/threatIntelService');
const incidentThreatIntelService = require('../src/services/incidentThreatIntelService');
const { persistDetectionIncident } = require('../src/services/incidentService');

/**
 * CYBERGUARD — Task 3: IOC Correlation & Incident Enrichment Test Suite
 *
 * Validates:
 * 1. IOC extraction from incident payload
 * 2. Indicator match detection
 * 3. Multi-tenant isolation
 * 4. incident_ioc_matches creation
 * 5. Risk score boost calculation
 * 6. Score cap at 100
 * 7. No duplicate IOC matches
 * 8. Multiple IOC matches in one incident
 * 9. Cache hit behavior
 * 10. Cache miss fallback to DB
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
  console.log('CYBERGUARD — Task 3: IOC Correlation & Incident Enrichment Test Suite');
  console.log('========================================================================\n');

  let testOrgAId = null;
  let testOrgBId = null;
  let globalIndicatorId1 = null;
  let globalIndicatorId2 = null;
  let tenantAIndicatorId = null;
  let createdIncidentIds = [];

  console.log('--- TEST GROUP 1: IOC EXTRACTION FROM INCIDENT PAYLOAD ---');

  await testAsync('1A: Extracts IOCs from signals, URLs, messages, telemetry, and explanations', async () => {
    const mockPayload = {
      threatType: 'phishing',
      sourceType: 'email',
      text: 'Suspicious email with defanged link hxxps://phish-login[.]security-update[.]com/verify',
      url: 'https://cdn-malware.example.org/payload.exe',
      explanation: 'Analysis detected network beaconing to C2 node 198.51.100.42 and domain c2-hub.darknet.org',
      signals: {
        source_ip: '203.0.113.19',
        destination_ip: '198.51.100.42',
        process_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      },
      details: {
        listening_port_ip: '192.0.2.1'
      }
    };

    const extracted = incidentThreatIntelService.extractIncidentIOCs(mockPayload);
    assert.ok(Array.isArray(extracted));
    assert.ok(extracted.length >= 6);

    const values = extracted.map((e) => e.value);
    const contexts = extracted.map((e) => e.match_context);

    // Verify refanged URL domain
    assert.ok(values.includes('phish-login.security-update.com'));
    // Verify explicit URL
    assert.ok(values.includes('https://cdn-malware.example.org/payload.exe'));
    // Verify explanation IP
    assert.ok(values.includes('198.51.100.42'));
    // Verify signal source IP
    assert.ok(values.includes('203.0.113.19'));
    // Verify signal destination IP
    assert.ok(values.includes('198.51.100.42'));
    // Verify SHA256 hash
    assert.ok(values.includes('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));

    // Verify contexts
    assert.ok(contexts.includes('source_ip'));
    assert.ok(contexts.includes('destination_ip'));
    assert.ok(contexts.includes('payload_hash'));
    assert.ok(contexts.includes('url_domain'));
  });

  console.log('\n--- TEST GROUP 2: DATABASE & FIXTURE SETUP ---');

  await testAsync('2A: Prepares test tenant organizations and seed indicators', async () => {
    // 1. Orgs
    const orgARes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Intel Tenant A') RETURNING id;`
    );
    testOrgAId = orgARes.rows[0].id;

    const orgBRes = await db.query(
      `INSERT INTO organizations (name) VALUES ('Threat Intel Tenant B') RETURNING id;`
    );
    testOrgBId = orgBRes.rows[0].id;

    // 2. Global Threat Indicator 1: IP (Confidence 95, Critical)
    const ind1 = await threatIntelService.recordIndicator({
      type: 'ip',
      value: '198.51.100.77',
      severity: 'critical',
      confidence_score: 95,
      threat_actor: 'APT29',
      malware_family: 'CozyBear',
      tags: ['c2', 'state-sponsored'],
      organization_id: null
    });
    globalIndicatorId1 = ind1.id;

    // 3. Global Threat Indicator 2: Hash (Confidence 65, Medium)
    const ind2 = await threatIntelService.recordIndicator({
      type: 'sha256',
      value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
      severity: 'medium',
      confidence_score: 65,
      threat_actor: 'Emotet Gang',
      malware_family: 'Emotet',
      tags: ['dropper'],
      organization_id: null
    });
    globalIndicatorId2 = ind2.id;

    // 4. Tenant A Private Threat Indicator: Domain (Confidence 85, High)
    const indTenantA = await threatIntelService.recordIndicator({
      type: 'domain',
      value: 'tenant-a-internal-c2.malicious.net',
      severity: 'high',
      confidence_score: 85,
      threat_actor: 'FIN7',
      tags: ['targeted', 'internal'],
      organization_id: testOrgAId
    });
    tenantAIndicatorId = indTenantA.id;

    assert.ok(globalIndicatorId1);
    assert.ok(globalIndicatorId2);
    assert.ok(tenantAIndicatorId);
  });

  console.log('\n--- TEST GROUP 3: MATCH DETECTION, CORRELATION & CACHING ---');

  await testAsync('3A: Indicator match detection returns enriched metadata', async () => {
    const extracted = [
      { type: 'ip', value: '198.51.100.77', match_context: 'source_ip' }
    ];

    const matches = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgAId
    });

    assert.strictEqual(matches.length, 1);
    const m = matches[0];
    assert.strictEqual(m.indicator_id, globalIndicatorId1);
    assert.strictEqual(m.matched_value, '198.51.100.77');
    assert.strictEqual(m.reputation_score, 95);
    assert.strictEqual(m.severity, 'critical');
    assert.strictEqual(m.threat_actor, 'APT29');
    assert.strictEqual(m.malware_family, 'CozyBear');
    assert.ok(m.tags.includes('c2'));
  });

  await testAsync('3B: Cache hit behavior verifies subsequent lookups use cache', async () => {
    const extracted = [
      { type: 'ip', value: '198.51.100.77', match_context: 'source_ip' }
    ];

    // Second correlation should hit Redis/fallback cache
    const matches = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgAId
    });

    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0]._cached, true);
  });

  await testAsync('3C: Cache miss fallback to DB populates cache', async () => {
    const extracted = [
      { type: 'sha256', value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', match_context: 'payload_hash' }
    ];

    // Force bypassCache to emulate cold cache miss
    const matches = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgAId,
      bypassCache: true
    });

    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].indicator_id, globalIndicatorId2);
    assert.strictEqual(matches[0]._cached, false);

    // Now query again without bypassCache; should be cached
    const cachedMatches = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgAId
    });
    assert.strictEqual(cachedMatches[0]._cached, true);
  });

  console.log('\n--- TEST GROUP 4: MULTI-TENANT ISOLATION ---');

  await testAsync('4A: Org A matches private indicator; Org B is strictly isolated', async () => {
    const extracted = [
      { type: 'domain', value: 'tenant-a-internal-c2.malicious.net', match_context: 'url_domain' }
    ];

    // Org A query should match private indicator
    const matchesA = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgAId,
      bypassCache: true
    });
    assert.strictEqual(matchesA.length, 1);
    assert.strictEqual(matchesA[0].indicator_id, tenantAIndicatorId);

    // Org B query MUST NOT match Org A's private indicator
    const matchesB = await incidentThreatIntelService.correlateIncidentIOCs(extracted, {
      organizationId: testOrgBId,
      bypassCache: true
    });
    assert.strictEqual(matchesB.length, 0);
  });

  console.log('\n--- TEST GROUP 5: RISK SCORE BOOST & CAPPING LOGIC ---');

  await testAsync('5A: Confidence 50-69 yields +10 risk boost', async () => {
    const matches = [{ reputation_score: 55, severity: 'medium' }];
    const res = incidentThreatIntelService.calculateThreatIntelBoost(matches, 50);
    assert.strictEqual(res.boost, 10);
    assert.strictEqual(res.finalScore, 60);
    assert.strictEqual(res.enrichedRiskLevel, 'high');
  });

  await testAsync('5B: Confidence 70-89 yields +20 risk boost', async () => {
    const matches = [{ reputation_score: 75, severity: 'high' }];
    const res = incidentThreatIntelService.calculateThreatIntelBoost(matches, 50);
    assert.strictEqual(res.boost, 20);
    assert.strictEqual(res.finalScore, 70);
    assert.strictEqual(res.enrichedRiskLevel, 'high');
  });

  await testAsync('5C: Confidence 90-100 yields +35 risk boost', async () => {
    const matches = [{ reputation_score: 95, severity: 'critical' }];
    const res = incidentThreatIntelService.calculateThreatIntelBoost(matches, 55);
    assert.strictEqual(res.boost, 35);
    assert.strictEqual(res.finalScore, 90);
    assert.strictEqual(res.enrichedRiskLevel, 'critical');
  });

  await testAsync('5D: Final risk score is strictly capped at 100', async () => {
    const matches = [{ reputation_score: 95, severity: 'critical' }];
    // Base score 85 + boost 35 = 120 -> capped at 100
    const res = incidentThreatIntelService.calculateThreatIntelBoost(matches, 85);
    assert.strictEqual(res.boost, 35);
    assert.strictEqual(res.finalScore, 100);
    assert.strictEqual(res.enrichedRiskLevel, 'critical');
  });

  console.log('\n--- TEST GROUP 6: DEDUPLICATION & MULTIPLE MATCHES ---');

  await testAsync('6A: Multiple IOC matches in one incident select highest confidence boost', async () => {
    const matches = [
      { reputation_score: 60, severity: 'medium', matched_value: 'val1', match_context: 'source_ip' },
      { reputation_score: 95, severity: 'critical', matched_value: 'val2', match_context: 'payload_hash' }
    ];
    const res = incidentThreatIntelService.calculateThreatIntelBoost(matches, 50);
    // Highest is 95 -> +35 boost
    assert.strictEqual(res.boost, 35);
    assert.strictEqual(res.finalScore, 85);
    assert.strictEqual(res.highestConfidence, 95);
  });

  await testAsync('6B: Deduplication ensures no duplicate IOC matches in correlation', async () => {
    // Extracted list has redundant occurrences of the same indicator in the same match_context
    const extractedWithDupes = [
      { type: 'ip', value: '198.51.100.77', match_context: 'source_ip' },
      { type: 'ip', value: '198.51.100.77', match_context: 'source_ip' },
      { type: 'ip', value: '198.51.100.77', match_context: 'source_ip' }
    ];

    const matches = await incidentThreatIntelService.correlateIncidentIOCs(extractedWithDupes, {
      organizationId: testOrgAId
    });

    // Exactly 1 match record
    assert.strictEqual(matches.length, 1);
  });

  console.log('\n--- TEST GROUP 7: END-TO-END PIPELINE & INCIDENT_IOC_MATCHES PERSISTENCE ---');

  await testAsync('7A: persistDetectionIncident enriches risk score and writes to incident_ioc_matches', async () => {
    const mlResult = {
      risk_level: 'medium',
      risk_score: 55, // Base score 55
      explanation: 'Detected connection to malicious command & control host 198.51.100.77',
      signals: {
        source_ip: '198.51.100.77' // Matches ind1 with confidence 95 (+35 boost)
      }
    };

    const incident = await persistDetectionIncident({
      user: { organization_id: testOrgAId },
      threatType: 'technical_threat',
      sourceType: 'system',
      mlResult
    });

    createdIncidentIds.push(incident.id);

    // Verify incident attributes
    assert.ok(incident.id);
    // Enriched score: 55 + 35 = 90
    assert.strictEqual(Number(incident.risk_score), 90);
    assert.strictEqual(incident.risk_level, 'critical');

    // Verify threat_intel enrichment attached
    assert.ok(incident.threat_intel);
    assert.strictEqual(incident.threat_intel.matched_ioc_count, 1);
    assert.strictEqual(incident.threat_intel.threat_intel_boost, 35);
    assert.strictEqual(incident.threat_intel.highest_confidence_indicator.value, '198.51.100.77');

    // Verify persistent records in public.incident_ioc_matches table
    const matchRes = await db.query(
      `SELECT * FROM public.incident_ioc_matches WHERE incident_id = $1`,
      [incident.id]
    );

    assert.strictEqual(matchRes.rows.length, 1);
    const row = matchRes.rows[0];
    assert.strictEqual(row.organization_id, testOrgAId);
    assert.strictEqual(row.indicator_id, globalIndicatorId1);
    assert.strictEqual(row.matched_value, '198.51.100.77');
    assert.strictEqual(row.reputation_score, 95);
    assert.strictEqual(row.severity, 'critical');
  });

  await testAsync('7B: Incidents without IOC matches preserve original score and leave junction empty', async () => {
    const mlResult = {
      risk_level: 'low',
      risk_score: 25,
      explanation: 'Clean login event from internal subnet',
      signals: {
        source_ip: '10.0.0.1' // Non-threat IP
      }
    };

    const incident = await persistDetectionIncident({
      user: { organization_id: testOrgAId },
      threatType: 'account_takeover',
      sourceType: 'login',
      mlResult
    });

    createdIncidentIds.push(incident.id);

    // Score remains original 25
    assert.strictEqual(Number(incident.risk_score), 25);
    assert.strictEqual(incident.risk_level, 'low');

    // 0 IOC matches in database
    const matchRes = await db.query(
      `SELECT * FROM public.incident_ioc_matches WHERE incident_id = $1`,
      [incident.id]
    );
    assert.strictEqual(matchRes.rows.length, 0);
  });

  console.log('\n--- CLEANUP ---');
  await testAsync('Clean up test resources', async () => {
    // Delete matches
    if (createdIncidentIds.length > 0) {
      await db.query(
        `DELETE FROM public.incident_ioc_matches WHERE incident_id = ANY($1::uuid[])`,
        [createdIncidentIds]
      );
      // Delete incidents
      await db.query(
        `DELETE FROM public.incidents WHERE id = ANY($1::uuid[])`,
        [createdIncidentIds]
      );
    }

    // Delete test indicators
    await db.query(
      `DELETE FROM public.threat_indicators WHERE id IN ($1, $2, $3)`,
      [globalIndicatorId1, globalIndicatorId2, tenantAIndicatorId]
    );

    // Delete test orgs
    await db.query(
      `DELETE FROM public.organizations WHERE id IN ($1, $2)`,
      [testOrgAId, testOrgBId]
    );
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
