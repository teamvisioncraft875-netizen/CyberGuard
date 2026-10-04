const assert = require('assert');
const db = require('./src/config/db');
const ddosDetectionService = require('./src/services/ddosDetectionService');
const DDoSAlert = require('./src/models/DDoSAlert');
const Incident = require('./src/models/Incident');
const IncidentEvidence = require('./src/models/IncidentEvidence');
const AuditLog = require('./src/models/AuditLog');
const LoginEvent = require('./src/models/LoginEvent');
const Organization = require('./src/models/Organization');

async function runTests() {
  console.log('--- Starting DDoS Detection Service Verification ---');

  // 1. Setup test organization
  const org = await Organization.create({
    name: 'DDoS Test Org ' + Math.random().toString(36).substring(7)
  });
  const orgId = org.id;
  console.log('✅ Test Organization created:', orgId);

  // 1b. Create a test user for login events
  const userRes = await db.query(`
    INSERT INTO public.users (email, password_hash, role, organization_id)
    VALUES ('ddos_user_' || substr(gen_random_uuid()::text, 1, 8) || '@example.com', 'hash', 'employee', $1)
    RETURNING id;
  `, [orgId]);
  const userId = userRes.rows[0].id;

  try {
    // =========================================================================
    // Test 1: detectRequestSpike
    // =========================================================================
    console.log('\nTesting detectRequestSpike...');
    process.env.DDOS_REQUEST_SPIKE_THRESHOLD = '50'; // Temporarily lower threshold for fast testing

    const normalIp = '198.51.100.1';
    const spikeIp = '198.51.100.99';

    // Record 20 requests for normalIp (below threshold)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'request_spike',
      source_ip: normalIp,
      count: 20
    });

    // Record 60 requests for spikeIp (above threshold 50)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'request_spike',
      source_ip: spikeIp,
      count: 60
    });

    const spikeResults = await ddosDetectionService.detectRequestSpike(orgId, 5);
    console.log('Request Spike Results:', spikeResults);

    const normalResult = spikeResults.find(r => r.source_ip === normalIp);
    const spikeResult = spikeResults.find(r => r.source_ip === spikeIp);

    assert.ok(normalResult, 'normalIp should be present in results');
    assert.strictEqual(normalResult.threshold_exceeded, false, 'normalIp threshold_exceeded should be false');
    assert.ok(spikeResult, 'spikeIp should be present in results');
    assert.strictEqual(spikeResult.threshold_exceeded, true, 'spikeIp threshold_exceeded should be true');
    console.log('✅ Test 1 (detectRequestSpike) PASSED');

    // =========================================================================
    // Test 2: detectPostFlood
    // =========================================================================
    console.log('\nTesting detectPostFlood...');
    process.env.DDOS_POST_FLOOD_THRESHOLD = '30';

    const floodIp = '203.0.113.88';
    const targetEndpoint = '/api/v1/auth/login';

    // Record 45 post requests to targetEndpoint
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'post_flood',
      source_ip: floodIp,
      endpoint: targetEndpoint,
      count: 45
    });

    // Test with specific endpoint
    const postFloodResults = await ddosDetectionService.detectPostFlood(orgId, targetEndpoint, 5);
    console.log('POST Flood Results:', postFloodResults);

    assert.ok(postFloodResults.length > 0, 'Should find at least 1 post flood');
    const floodMatch = postFloodResults.find(r => r.source_ip === floodIp);
    assert.ok(floodMatch, 'floodIp should be detected');
    assert.strictEqual(floodMatch.endpoint, targetEndpoint, 'Endpoint should match');
    assert.ok(floodMatch.count > 30, 'Count should exceed threshold');
    console.log('✅ Test 2 (detectPostFlood) PASSED');

    // =========================================================================
    // Test 3: detectLoginAbuse
    // =========================================================================
    console.log('\nTesting detectLoginAbuse...');
    process.env.DDOS_LOGIN_ABUSE_THRESHOLD = '5';

    const bruteForceIp = '192.0.2.77';

    // Insert 8 failed login events for this user and IP
    for (let i = 0; i < 8; i++) {
      await LoginEvent.create({
        user_id: userId,
        ip_address: bruteForceIp,
        success: false,
        failed_attempt_count: 1
      });
    }

    const loginAbuseResults = await ddosDetectionService.detectLoginAbuse(orgId, 15);
    console.log('Login Abuse Results:', loginAbuseResults);

    const abuseMatch = loginAbuseResults.find(r => r.source_ip === bruteForceIp);
    assert.ok(abuseMatch, 'bruteForceIp should be flagged for login abuse');
    assert.ok(abuseMatch.failed_attempts >= 8, 'Failed attempts should be >= 8');
    console.log('✅ Test 3 (detectLoginAbuse) PASSED');

    // =========================================================================
    // Test 4: detectIPFlooding
    // =========================================================================
    console.log('\nTesting detectIPFlooding...');
    process.env.DDOS_IP_FLOOD_THRESHOLD = '15';

    const floodingIp = '192.0.2.199';

    // Record flood metric with count 25 across multiple endpoints
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'ip_flooding',
      source_ip: floodingIp,
      endpoint: '/api/v1/users',
      count: 15
    });
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'ip_flooding',
      source_ip: floodingIp,
      endpoint: '/api/v1/devices',
      count: 15
    });

    const floodResults = await ddosDetectionService.detectIPFlooding(orgId, 5);
    console.log('IP Flooding Results:', floodResults);

    const floodMatched = floodResults.find(r => r.source_ip === floodingIp);
    assert.ok(floodMatched, 'floodingIp should be detected');
    assert.ok(floodMatched.request_count > 15, 'Request count should exceed threshold');
    console.log('✅ Test 4 (detectIPFlooding) PASSED');

    // =========================================================================
    // Test 5: createDDoSIncident
    // =========================================================================
    console.log('\nTesting createDDoSIncident...');

    const attackerIp = '198.51.100.222';
    const incidentRes = await ddosDetectionService.createDDoSIncident(
      'request_spike',
      attackerIp,
      {
        organization_id: orgId,
        count: 1200,
        endpoint: '/api/v1/search',
        window_minutes: 5
      }
    );
    const incidentId = incidentRes.id || incidentRes;

    console.log('Created Incident ID:', incidentId);
    assert.ok(incidentId, 'incidentId must be returned');

    // Verify incident row in database
    const incidentRow = await Incident.findById(incidentId);
    assert.ok(incidentRow, 'Incident row must exist in database');
    assert.strictEqual(incidentRow.threat_type, 'ddos', 'threat_type must be ddos');
    assert.strictEqual(incidentRow.risk_level, 'critical', 'risk_level must be critical');
    assert.strictEqual(Number(incidentRow.risk_score), 95, 'risk_score must be 95');
    assert.strictEqual(incidentRow.organization_id, orgId, 'organization_id must match');

    // Verify incident evidence row
    const evidenceRows = await IncidentEvidence.findByIncidentId(incidentId);
    assert.ok(evidenceRows.length > 0, 'Incident evidence must be stored');
    assert.strictEqual(evidenceRows[0].evidence_type, 'ddos_metrics', 'evidence_type must be ddos_metrics');

    const rawPayload = typeof evidenceRows[0].raw_payload === 'string'
      ? JSON.parse(evidenceRows[0].raw_payload)
      : evidenceRows[0].raw_payload;

    assert.strictEqual(rawPayload.source_ip, attackerIp, 'evidence raw_payload source_ip must match');
    assert.strictEqual(rawPayload.metric_type, 'request_spike', 'evidence raw_payload metric_type must match');
    assert.strictEqual(rawPayload.count, 1200, 'evidence raw_payload count must match');

    // Verify ddos_metrics entry created for audit + trending
    const metricsForOrg = await DDoSAlert.findByOrg(orgId, { metric_type: 'request_spike' });
    assert.ok(metricsForOrg.length > 0, 'DDoS metric must be stored in ddos_metrics table');
    console.log('✅ Test 5 (createDDoSIncident) PASSED');

    // =========================================================================
    // Test 6: SQL Injection Safety
    // =========================================================================
    console.log('\nTesting SQL Injection Safety...');
    const maliciousInput = "'; DROP TABLE ddos_metrics; --";
    const safeResults = await ddosDetectionService.detectPostFlood(maliciousInput, maliciousInput, 5);
    assert.ok(Array.isArray(safeResults), 'Should handle malicious inputs safely');
    console.log('✅ Test 6 (SQL Injection Safety) PASSED');

    console.log('\n🎉 ALL 6 DDOS DETECTION TESTS PASSED SUCCESSFULLY! 🎉');
  } finally {
    // Cleanup test data
    console.log('\nCleaning up test organization...');
    await db.query('DELETE FROM public.organizations WHERE id = $1', [orgId]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
  }
}

runTests().catch(err => {
  console.error('❌ Test failed with error:', err);
  process.exit(1);
});
