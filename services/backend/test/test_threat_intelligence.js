process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const ThreatIOC = require('../src/models/ThreatIOC');
const SiemAlert = require('../src/models/SiemAlert');
const threatIntelService = require('../src/services/siem/threatIntelService');
const streamingService = require('../src/services/siem/streamingService');
const EventPipelineService = require('../src/services/siem/eventPipelineService');
const { createOrganizationFixture, createUserFixture, cleanupFixtures } = require('./fixtures');

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

function createToken(user, roleOverride = null, orgOverride = undefined) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: roleOverride || user.jwt_role || user.role,
      organization_id: orgOverride !== undefined ? orgOverride : (user.organization_id || null)
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runThreatIntelligenceSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — SIEM Phase 5: Threat Intelligence & IOC Platform Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;

  let orgA;
  let orgB;
  let adminA;
  let analystA;
  let employeeA;
  let adminB;

  let tokenAdminA;
  let tokenAnalystA;
  let tokenEmployeeA;
  let tokenAdminB;

  try {
    // 1. Start Server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // 2. Setup Multi-Tenant Fixtures
    orgA = await createOrganizationFixture({ name: 'Threat Intel SOC Org A' });
    orgB = await createOrganizationFixture({ name: 'Threat Intel SOC Org B' });

    adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });
    adminB = await createUserFixture({ organization_id: orgB.id, role: 'admin' });

    tokenAdminA = createToken(adminA);
    tokenAnalystA = createToken(analystA);
    tokenEmployeeA = createToken(employeeA);
    tokenAdminB = createToken(adminB);

    let createdIocId = null;

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 1: IOC CRUD & VALIDATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP 1: IOC CRUD & VALIDATION ---');

    await testAsync('1.1: Rejects IOC creation with missing ioc_value (400)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenAnalystA}` },
        body: JSON.stringify({ ioc_type: 'ip' })
      });
      assert.strictEqual(res.status, 400);
    });

    await testAsync('1.2: Rejects IOC creation with invalid ioc_type (400)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenAnalystA}` },
        body: JSON.stringify({ ioc_type: 'unknown_type', ioc_value: '1.2.3.4' })
      });
      assert.strictEqual(res.status, 400);
    });

    await testAsync('1.3: Successfully creates IP IOC with dynamic risk score (201)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenAnalystA}` },
        body: JSON.stringify({
          ioc_type: 'ip',
          ioc_value: '198.51.100.42',
          confidence: 85,
          threat_actor: 'APT29',
          malware_family: 'Cobalt Strike',
          campaign_name: 'Operation Ghost',
          tags: ['c2', 'critical_infra']
        })
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.ok(json.data.id);
      assert.strictEqual(json.data.ioc_type, 'ip');
      assert.strictEqual(json.data.ioc_value, '198.51.100.42');
      assert.ok(json.data.risk_score >= 85);
      createdIocId = json.data.id;
    });

    await testAsync('1.4: Upserts on duplicate IOC within same tenant', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenAnalystA}` },
        body: JSON.stringify({
          ioc_type: 'ip',
          ioc_value: '198.51.100.42',
          confidence: 95
        })
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.strictEqual(json.data.id, createdIocId);
      assert.strictEqual(json.data.confidence, 95);
    });

    await testAsync('1.5: Retrieves single IOC by ID (200)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs/${createdIocId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.id, createdIocId);
      assert.strictEqual(json.data.threat_actor, 'APT29');
    });

    await testAsync('1.6: Updates IOC properties and timestamps (200)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs/${createdIocId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenAnalystA}` },
        body: JSON.stringify({
          risk_score: 98,
          malware_family: 'Cobalt Strike Beacon'
        })
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.risk_score, 98);
      assert.strictEqual(json.data.malware_family, 'Cobalt Strike Beacon');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 2: IOC SEARCH & FILTERING
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 2: IOC SEARCH & FILTERING ---');

    // Create additional diverse IOC fixtures
    let domainIoc, urlIoc, hashIoc, expiredIoc;
    beforeIOCs: {
      domainIoc = await ThreatIOC.createIOC({
        organization_id: orgA.id,
        ioc_type: 'domain',
        ioc_value: 'malicious-c2.evil.com',
        confidence: 90,
        risk_score: 85,
        threat_actor: 'Lazarus Group',
        malware_family: 'AppleJeus'
      });

      urlIoc = await ThreatIOC.createIOC({
        organization_id: orgA.id,
        ioc_type: 'url',
        ioc_value: 'http://evil.com/payload.exe',
        confidence: 70,
        risk_score: 75,
        threat_actor: 'FIN7'
      });

      hashIoc = await ThreatIOC.createIOC({
        organization_id: orgA.id,
        ioc_type: 'sha256',
        ioc_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        confidence: 95,
        risk_score: 95,
        malware_family: 'Ransomware.LockBit'
      });

      expiredIoc = await ThreatIOC.createIOC({
        organization_id: orgA.id,
        ioc_type: 'ip',
        ioc_value: '203.0.113.99',
        confidence: 50,
        risk_score: 40,
        expiration_date: new Date(Date.now() - 3600000) // 1 hour ago
      });
    }

    await testAsync('2.1: Searches IOCs by type filter', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs?ioc_type=domain`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.length >= 1);
      assert.ok(json.data.every(i => i.ioc_type === 'domain'));
    });

    await testAsync('2.2: Searches IOCs by text keyword (actor/malware/value)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs?q=LockBit`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.length, 1);
      assert.strictEqual(json.data[0].malware_family, 'Ransomware.LockBit');
    });

    await testAsync('2.3: Filters IOCs by minimum risk threshold', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs?min_risk=80`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.length >= 2);
      assert.ok(json.data.every(i => i.risk_score >= 80));
    });

    await testAsync('2.4: Excludes expired IOCs by default', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs?q=203.0.113.99`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.length, 0);
    });

    await testAsync('2.5: Includes expired IOCs when include_expired=true', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs?q=203.0.113.99&include_expired=true`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.length, 1);
      assert.strictEqual(json.data[0].ioc_value, '203.0.113.99');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 3: IOC OBSERVABLE EXTRACTION & MATCHING
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 3: IOC OBSERVABLE EXTRACTION & MATCHING ---');

    await testAsync('3.1: Extracts observables (IP, domain, URL, hash, email) from event', () => {
      const dummyEvent = {
        normalized_event: {
          source_ip: '10.0.0.5',
          destination_ip: '198.51.100.42',
          domain: 'malicious-c2.evil.com',
          url: 'http://evil.com/payload.exe',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          user: 'phished.victim@target.com'
        }
      };

      const observables = threatIntelService.extractObservables(dummyEvent);
      assert.strictEqual(observables.length, 6);
      const values = observables.map(o => o.value);
      assert.ok(values.includes('198.51.100.42'));
      assert.ok(values.includes('malicious-c2.evil.com'));
      assert.ok(values.includes('http://evil.com/payload.exe'));
    });

    await testAsync('3.2: Matches destination IP observable against active IOCs', async () => {
      const event = {
        normalized_event: { destination_ip: '198.51.100.42' }
      };
      const matches = await threatIntelService.matchEvent(event, orgA.id);
      assert.strictEqual(matches.length, 1);
      assert.strictEqual(matches[0].ioc_value, '198.51.100.42');
      assert.strictEqual(matches[0].ioc_type, 'ip');
    });

    await testAsync('3.3: Matches domain observable against active IOCs', async () => {
      const event = {
        normalized_event: { domain: 'malicious-c2.evil.com' }
      };
      const matches = await threatIntelService.matchEvent(event, orgA.id);
      assert.strictEqual(matches.length, 1);
      assert.strictEqual(matches[0].threat_actor, 'Lazarus Group');
    });

    await testAsync('3.4: Matches file hash (sha256) observable', async () => {
      const event = {
        normalized_event: { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
      };
      const matches = await threatIntelService.matchEvent(event, orgA.id);
      assert.strictEqual(matches.length, 1);
      assert.strictEqual(matches[0].malware_family, 'Ransomware.LockBit');
    });

    await testAsync('3.5: Does NOT match expired IOCs during event lookup', async () => {
      const event = {
        normalized_event: { destination_ip: '203.0.113.99' }
      };
      const matches = await threatIntelService.matchEvent(event, orgA.id);
      assert.strictEqual(matches.length, 0);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 4: RISK SCORING ALGORITHM
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 4: RISK SCORING ALGORITHM ---');

    await testAsync('4.1: Computes base confidence score without extras', () => {
      const score = threatIntelService.calculateRiskScore({ confidence: 45 });
      assert.strictEqual(score, 45);
    });

    await testAsync('4.2: Adds sightings count weight (up to +20)', () => {
      const score = threatIntelService.calculateRiskScore({ confidence: 50, sightingsCount: 5 });
      assert.strictEqual(score, 60); // 50 + 10
    });

    await testAsync('4.3: Adds recent activity weight (+15 for last 24h)', () => {
      const recent = new Date(Date.now() - 3600000); // 1h ago
      const score = threatIntelService.calculateRiskScore({ confidence: 50, lastSeen: recent });
      assert.strictEqual(score, 65); // 50 + 15
    });

    await testAsync('4.4: Adds campaign and threat actor severity weights (+20 total)', () => {
      const score = threatIntelService.calculateRiskScore({
        confidence: 60,
        campaignName: 'Operation Solar',
        threatActor: 'APT29'
      });
      assert.strictEqual(score, 80); // 60 + 10 + 10
    });

    await testAsync('4.5: Clamps dynamic risk score to max 100', () => {
      const score = threatIntelService.calculateRiskScore({
        confidence: 95,
        sightingsCount: 50,
        lastSeen: new Date(),
        campaignName: 'Super Campaign',
        threatActor: 'Mega Threat'
      });
      assert.strictEqual(score, 100);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 5: PIPELINE INTEGRATION, SIGHTINGS & ALERT GENERATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 5: PIPELINE INTEGRATION, SIGHTINGS & ALERT GENERATION ---');

    let capturedSSEEvents = [];
    let unsubSSE;

    beforeSSE: {
      const sub = streamingService.subscribe({
        organizationId: orgA.id,
        callback: (payload) => {
          capturedSSEEvents.push(payload);
        }
      });
      unsubSSE = sub.unsubscribe;
    }

    await testAsync('5.1: Pipeline ingestion matches Critical IOC (risk > 80) and creates Critical alert', async () => {
      capturedSSEEvents = [];

      const rawEvent = {
        source_type: 'windows',
        event_id: 3,
        source_ip: '10.10.10.20',
        destination_ip: '198.51.100.42', // Matched Critical IOC (risk 98)
        user: 'victim_user'
      };

      const result = await EventPipelineService.processEvents({
        organizationId: orgA.id,
        events: [rawEvent]
      });

      assert.ok(
        result.successful_events >= 1,
        `Expected at least 1 successful event, got: ${JSON.stringify(result)}`
      );

      // Verify SIEM Alert created
      const alertsRes = await db.query(
        `SELECT * FROM public.siem_alerts WHERE organization_id = $1 AND rule_code = 'THREAT-INTEL-IOC' ORDER BY created_at DESC LIMIT 1;`,
        [orgA.id]
      );
      assert.strictEqual(alertsRes.rows.length, 1);
      const alert = alertsRes.rows[0];
      assert.strictEqual(alert.severity, 'critical');
      assert.ok(alert.title.includes('198.51.100.42'));
    });

    await testAsync('5.2: Records Sighting with matched event telemetry and metadata', async () => {
      const sightings = await ThreatIOC.getSightings({ organization_id: orgA.id, ioc_id: createdIocId });
      assert.ok(sightings.data.length >= 1);
      const s = sightings.data[0];
      assert.strictEqual(s.destination_ip, '198.51.100.42');
      assert.strictEqual(s.user_name, 'victim_user');
      assert.strictEqual(s.malware_family, 'Cobalt Strike Beacon');
    });

    await testAsync('5.3: Dispatches real-time SSE ioc_match and new_sighting stream events', () => {
      const matchEvents = capturedSSEEvents.filter(e => e.type === 'ioc_match');
      const sightingEvents = capturedSSEEvents.filter(e => e.type === 'new_sighting');

      assert.ok(matchEvents.length >= 1, 'Expected at least 1 ioc_match SSE message');
      assert.ok(sightingEvents.length >= 1, 'Expected at least 1 new_sighting SSE message');
      assert.strictEqual(matchEvents[0].ioc_match.ioc_value, '198.51.100.42');
    });

    await testAsync('5.4: GET /api/v1/threat-intel/sightings returns paginated sightings', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/sightings?ioc_id=${createdIocId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.length >= 1);
      assert.strictEqual(json.data[0].ioc_value, '198.51.100.42');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 6: THREAT INTELLIGENCE DASHBOARD STATS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 6: THREAT INTELLIGENCE DASHBOARD STATS ---');

    await testAsync('6.1: GET /api/v1/threat-intel/dashboard returns metrics and rankings', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/dashboard`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.total_iocs >= 4);
      assert.ok(json.active_iocs >= 3);
      assert.ok(json.expired_iocs >= 1);
      assert.ok(json.high_risk_iocs >= 2);
      assert.ok(json.sightings_today >= 1);
      assert.ok(Array.isArray(json.top_threat_actors));
      assert.ok(Array.isArray(json.top_malware_families));
      assert.ok(Array.isArray(json.top_campaigns));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // TEST GROUP 7: MULTI-TENANT ISOLATION & RBAC SECURITY
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 7: MULTI-TENANT ISOLATION & RBAC SECURITY ---');

    await testAsync('7.1: Rejects unauthenticated request with 401', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`);
      assert.strictEqual(res.status, 401);
    });

    await testAsync('7.2: Rejects employee role with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('7.3: Rejects request with missing organization_id with 403', async () => {
      const nullOrgToken = createToken(analystA, 'analyst', null);
      const res = await fetch(`${baseUrl}/threat-intel/iocs`, {
        headers: { Authorization: `Bearer ${nullOrgToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('7.4: Cross-tenant isolation: Org B cannot view Org A IOCs (404)', async () => {
      const res = await fetch(`${baseUrl}/threat-intel/iocs/${createdIocId}`, {
        headers: { Authorization: `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(res.status, 404);
    });

    await testAsync('7.5: Cross-tenant isolation: Org B event does NOT match Org A IOC', async () => {
      const event = {
        normalized_event: { destination_ip: '198.51.100.42' }
      };
      const matches = await threatIntelService.matchEvent(event, orgB.id);
      assert.strictEqual(matches.length, 0);
    });

    await testAsync('7.6: Deletes IOC and confirms deletion (200 & 404)', async () => {
      const delRes = await fetch(`${baseUrl}/threat-intel/iocs/${createdIocId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });
      assert.strictEqual(delRes.status, 200);

      const checkRes = await fetch(`${baseUrl}/threat-intel/iocs/${createdIocId}`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });
      assert.strictEqual(checkRes.status, 404);
    });

    if (unsubSSE) unsubSSE();

  } finally {
    console.log('\n--- CLEANUP THREAT INTEL FIXTURES ---');
    if (server) server.close();
    if (orgA || orgB) {
      await cleanupFixtures({ orgIds: [orgA?.id, orgB?.id].filter(Boolean) });
      console.log('  [✅] Test fixtures cleaned up successfully');
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

if (require.main === module) {
  runThreatIntelligenceSuite();
}

module.exports = { runThreatIntelligenceSuite };
