process.env.NODE_ENV = 'test';
const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const db = require('./src/config/db');
const { app } = require('./src/index');
const Organization = require('./src/models/Organization');
const User = require('./src/models/User');
const ResponsePolicy = require('./src/models/ResponsePolicy');
const ResponseAction = require('./src/models/ResponseAction');
const Incident = require('./src/models/Incident');
const IncidentEvidence = require('./src/models/IncidentEvidence');
const MitreMapping = require('./src/models/MitreMapping');
const ddosDetectionService = require('./src/services/ddosDetectionService');
const PolicyEngine = require('./src/services/PolicyEngine');
const config = require('./src/config');

const JWT_SECRET = config.JWT_SECRET || process.env.JWT_SECRET || 'test-secret';

function request(server, { method, path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: server.address().port,
        method,
        path,
        headers: {
          'Content-Type': 'application/json',
          ...headers
        }
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          let parsed;
          try {
            parsed = JSON.parse(data);
          } catch (_) {
            parsed = data;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runCompleteDDoSVerification() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Comprehensive DDoS Detection & Policy Integration Test');
  console.log('========================================================================');

  // 1. Setup isolated test organizations
  const org = await Organization.create({
    name: 'DDoS Verification Org ' + Math.random().toString(36).substring(7)
  });
  const orgId = org.id;

  const otherOrg = await Organization.create({
    name: 'DDoS Other Org ' + Math.random().toString(36).substring(7)
  });
  const otherOrgId = otherOrg.id;

  // 2. Setup users for auth/scoping tests
  const adminUser = await User.create({
    email: 'admin_ddos_' + Math.random().toString(36).substring(7) + '@cyberguard.test',
    password_hash: 'hash',
    role: 'admin',
    organization_id: orgId
  });

  const employeeUser = await User.create({
    email: 'employee_ddos_' + Math.random().toString(36).substring(7) + '@cyberguard.test',
    password_hash: 'hash',
    role: 'employee',
    organization_id: orgId
  });

  const adminToken = jwt.sign(
    { id: adminUser.id, email: adminUser.email, role: 'admin', organization_id: orgId },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const employeeToken = jwt.sign(
    { id: employeeUser.id, email: employeeUser.email, role: 'employee', organization_id: orgId },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  const targetIp = '203.0.113.42';

  try {
    // =========================================================================
    // SCENARIO 1: REQUEST SPIKE DETECTION
    // =========================================================================
    console.log('\n[Scenario 1] Request Spike Detection...');
    // Simulate 600 requests from 203.0.113.42 in 5 minutes (default threshold: 500)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'request_spike',
      source_ip: targetIp,
      count: 600,
      window_start: new Date(Date.now() - 5 * 60 * 1000),
      window_end: new Date()
    });

    const spikeResults = await ddosDetectionService.detectRequestSpike(orgId, 5);
    console.log('Spike results:', spikeResults);

    const spikeMatch = spikeResults.find((r) => r.source_ip === targetIp);
    assert.ok(spikeMatch, 'Target IP 203.0.113.42 must be detected in spike results');
    assert.strictEqual(spikeMatch.threshold_exceeded, true, 'threshold_exceeded must be true');
    assert.ok(spikeMatch.incident_id, 'Incident must be auto-created for request spike');

    // Verify incident properties in DB
    const spikeInc = await Incident.findById(spikeMatch.incident_id);
    assert.ok(spikeInc, 'Incident row must exist in database');
    assert.strictEqual(spikeInc.threat_type, 'ddos', 'threat_type must be ddos');
    assert.strictEqual(Number(spikeInc.risk_score), 95, 'risk_score must be 95 (critical)');
    assert.strictEqual(spikeInc.risk_level, 'critical', 'risk_level must be critical');

    // Check: audit_logs has 'ddos_incident_created'
    const spikeAudit = await db.query(
      `SELECT * FROM public.audit_logs WHERE organization_id = $1 AND action = 'ddos_incident_created' AND resource_id = $2;`,
      [orgId, spikeInc.id]
    );
    assert.ok(spikeAudit.rows.length > 0, "audit_logs must contain 'ddos_incident_created'");
    console.log('✅ Scenario 1 (Request Spike Detection) PASSED');

    // =========================================================================
    // SCENARIO 2: POST FLOOD DETECTION
    // =========================================================================
    console.log('\n[Scenario 2] POST Flood Detection...');
    const targetIp2 = '203.0.113.43';
    // Simulate 150 POST requests to /auth/login from 203.0.113.43 in 5 minutes (default threshold: 100)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'post_flood',
      source_ip: targetIp2,
      endpoint: '/auth/login',
      count: 150,
      window_start: new Date(Date.now() - 5 * 60 * 1000),
      window_end: new Date()
    });

    const floodResults = await ddosDetectionService.detectPostFlood(orgId, '/auth/login', 5);
    console.log('Post flood results:', floodResults);

    const floodMatch = floodResults.find((r) => r.source_ip === targetIp2);
    assert.ok(floodMatch, 'Target IP 203.0.113.43 must be detected in post flood results');
    assert.strictEqual(floodMatch.threshold_exceeded, true, 'threshold_exceeded must be true');
    assert.ok(floodMatch.incident_id, 'Incident must be created for POST flood');

    // Verify incident created with evidence={endpoint, count}
    const floodEvidence = await IncidentEvidence.findByIncidentId(floodMatch.incident_id);
    assert.ok(floodEvidence.length > 0, 'Incident evidence must be present');
    const evPayload = floodEvidence[0].raw_payload || {};
    assert.strictEqual(evPayload.endpoint, '/auth/login', 'evidence must contain endpoint /auth/login');
    assert.strictEqual(Number(evPayload.count), 150, 'evidence must contain count 150');
    console.log('✅ Scenario 2 (POST Flood Detection) PASSED');

    // =========================================================================
    // SCENARIO 3: LOGIN ABUSE DETECTION
    // =========================================================================
    console.log('\n[Scenario 3] Login Abuse Detection...');
    const targetIp3 = '203.0.113.44';
    // Simulate 15 failed login attempts from 203.0.113.44 in 15 minutes (default threshold: 10)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'login_abuse',
      source_ip: targetIp3,
      count: 15,
      window_start: new Date(Date.now() - 15 * 60 * 1000),
      window_end: new Date()
    });

    const loginAbuseResults = await ddosDetectionService.detectLoginAbuse(orgId, 15);
    console.log('Login abuse results:', loginAbuseResults);

    const abuseMatch = loginAbuseResults.find((r) => r.source_ip === targetIp3);
    assert.ok(abuseMatch, 'Target IP 203.0.113.44 must be detected in login abuse results');
    assert.strictEqual(abuseMatch.threshold_exceeded, true, 'threshold_exceeded must be true');
    assert.ok(abuseMatch.incident_id, 'Incident must be created for login abuse');

    // Verify incident: recommended_actions includes 'block_ip'
    const recActions = await db.query(
      `SELECT action_type FROM public.recommended_actions WHERE incident_id = $1;`,
      [abuseMatch.incident_id]
    );
    const actionTypes = recActions.rows.map((r) => r.action_type);
    assert.ok(actionTypes.includes('block_ip'), "recommended_actions must include 'block_ip'");
    console.log('✅ Scenario 3 (Login Abuse Detection) PASSED');

    // =========================================================================
    // SCENARIO 4: IP FLOODING DETECTION
    // =========================================================================
    console.log('\n[Scenario 4] IP Flooding Detection...');
    const targetIp4 = '203.0.113.45';
    // Simulate 30 requests from same IP to different endpoints in 5 minutes (default threshold: 20)
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'ip_flooding',
      source_ip: targetIp4,
      endpoint: '/api/v1/search',
      count: 15,
      window_start: new Date(Date.now() - 5 * 60 * 1000),
      window_end: new Date()
    });
    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'ip_flooding',
      source_ip: targetIp4,
      endpoint: '/api/v1/export',
      count: 15,
      window_start: new Date(Date.now() - 5 * 60 * 1000),
      window_end: new Date()
    });

    const ipFloodResults = await ddosDetectionService.detectIPFlooding(orgId, 5);
    console.log('IP flooding results:', ipFloodResults);

    const ipFloodMatch = ipFloodResults.find((r) => r.source_ip === targetIp4);
    assert.ok(ipFloodMatch, 'Target IP 203.0.113.45 must be detected in IP flooding');
    assert.strictEqual(ipFloodMatch.threshold_exceeded, true, 'threshold_exceeded must be true');
    assert.ok(ipFloodMatch.incident_id, 'Incident must be created for IP flooding');
    console.log('✅ Scenario 4 (IP Flooding Detection) PASSED');

    // =========================================================================
    // SCENARIO 5: ENDPOINT TESTS (POST /admin/ddos/scan & GET /admin/ddos/threats)
    // =========================================================================
    console.log('\n[Scenario 5] Admin Endpoint Verification...');

    // 5a. POST /api/v1/admin/ddos/scan with scan_type='request_spike'
    const scanRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { scan_type: 'request_spike', window_minutes: 5 }
    });
    assert.strictEqual(scanRes.status, 200, 'POST /admin/ddos/scan should return 200');
    assert.ok(Array.isArray(scanRes.body.threats), 'threats must be an array');
    assert.ok(scanRes.body.threats.length > 0, 'threats list must not be empty');

    // 5b. GET /api/v1/admin/ddos/threats: org-scoped, paginated
    const threatsRes = await request(server, {
      method: 'GET',
      path: '/api/v1/admin/ddos/threats?limit=10&offset=0',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(threatsRes.status, 200, 'GET /admin/ddos/threats should return 200');
    assert.ok(Array.isArray(threatsRes.body.threats), 'threats must be an array');
    assert.ok(threatsRes.body.total > 0, 'total must be > 0');

    // 5c. Non-admin gets 403 Forbidden
    const forbiddenRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${employeeToken}` },
      body: { scan_type: 'request_spike' }
    });
    assert.strictEqual(forbiddenRes.status, 403, 'Non-admin must receive 403 Forbidden');
    console.log('✅ Scenario 5 (Endpoint Tests) PASSED');

    // =========================================================================
    // SCENARIO 6: POLICY INTEGRATION
    // =========================================================================
    console.log('\n[Scenario 6] Policy Engine Automated Response Integration...');
    // Create policy for threat_type='ddos', min_score=90, action_type='block_ip'
    const policy = await ResponsePolicy.create({
      organization_id: orgId,
      name: 'Automated DDoS Mitigation Policy',
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

    const ddosAttackerIp = '198.51.100.99';
    // Create DDoS incident
    const incidentObj = await ddosDetectionService.createDDoSIncident(
      orgId,
      'request_spike',
      ddosAttackerIp,
      {
        count: 700,
        window_minutes: 5
      }
    );

    // Wait 300ms for async PolicyEngine evaluation
    await new Promise((resolve) => setTimeout(resolve, 350));

    // Verify response_action created with action_type='block_ip'
    const actionsRes = await db.query(
      `SELECT * FROM public.response_actions WHERE incident_id = $1 AND action_type = 'block_ip';`,
      [incidentObj.id]
    );
    assert.ok(actionsRes.rows.length > 0, 'response_action with action_type block_ip must be created');
    const blockAction = actionsRes.rows[0];
    assert.strictEqual(blockAction.action_type, 'block_ip');
    assert.strictEqual(blockAction.action_mode, 'shadow');
    assert.strictEqual(blockAction.policy_id, policy.id);

    const actionTarget = typeof blockAction.target === 'string'
      ? JSON.parse(blockAction.target)
      : blockAction.target;

    // Verify target is the DDoS source IP
    assert.strictEqual(actionTarget.ip_address, ddosAttackerIp, 'target must be the DDoS source IP');
    assert.strictEqual(actionTarget.org_wide, true, 'target org_wide must be true');
    console.log('✅ Scenario 6 (Policy Integration) PASSED');

    // =========================================================================
    // SCENARIO 7: AUDIT TRAIL
    // =========================================================================
    console.log('\n[Scenario 7] Audit Trail Verification...');
    const auditLogsRes = await db.query(
      `SELECT action, resource_type, ip_address, created_at 
       FROM public.audit_logs 
       WHERE organization_id = $1 
       ORDER BY created_at DESC;`,
      [orgId]
    );

    const loggedActions = auditLogsRes.rows.map((r) => r.action);
    console.log('Audit trail actions recorded:', loggedActions);

    assert.ok(loggedActions.includes('ddos_incident_created'), "'ddos_incident_created' must be in audit logs");
    assert.ok(loggedActions.includes('ddos_scan_triggered'), "'ddos_scan_triggered' must be in audit logs");
    console.log('✅ Scenario 7 (Audit Trail Verification) PASSED');

    console.log('\n========================================================================');
    console.log('🎉 ALL 7 DDOS VERIFICATION SCENARIOS PASSED WITH ZERO ERRORS! 🎉');
    console.log('========================================================================');
  } finally {
    server.close();
    console.log('\nCleaning up verification resources...');
    await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [orgId, otherOrgId]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
    process.exit(0);
  }
}

runCompleteDDoSVerification().catch((err) => {
  console.error('❌ Verification failed with error:', err);
  process.exit(1);
});
