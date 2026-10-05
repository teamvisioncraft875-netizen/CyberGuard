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
const DetectionSignal = require('./src/models/DetectionSignal');
const RecommendedAction = require('./src/models/RecommendedAction');
const ddosDetectionService = require('./src/services/ddosDetectionService');
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

async function runPolicyIntegrationTest() {
  console.log('--- Starting DDoS Incident Pipeline & Policy Engine Integration Test ---');

  // 1. Setup test organization
  const org = await Organization.create({
    name: 'DDoS Policy Org ' + Math.random().toString(36).substring(7)
  });
  const orgId = org.id;
  console.log('✅ Created test organization:', orgId);

  // 2. Setup admin user
  const admin = await User.create({
    email: 'admin_ddos_' + Math.random().toString(36).substring(7) + '@test.com',
    password_hash: 'hash',
    role: 'admin',
    organization_id: orgId
  });
  const adminToken = jwt.sign(
    { id: admin.id, email: admin.email, role: 'admin', organization_id: orgId },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  // 3. Create response policy for DDoS threats
  // Admin creates policy: match threat_type='*' (or 'ddos'), min_score=90, action_type='block_ip'
  const policy = await ResponsePolicy.create({
    organization_id: orgId,
    name: 'DDoS Automated Response Policy',
    rules: [
      {
        threat_type: '*',
        min_score: 90,
        action_type: 'block_ip',
        action_mode: 'shadow',
        auto_execute_after_mins: 5,
        target_filter: { user_roles: ['*'] }
      }
    ],
    is_enabled: true
  });
  console.log('✅ Created response policy:', policy.id);

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    // 4. Seed traffic metrics to trigger detection
    process.env.DDOS_REQUEST_SPIKE_THRESHOLD = '100';
    const attackerIp = '198.51.100.205';

    await ddosDetectionService.recordMetric({
      organization_id: orgId,
      metric_type: 'request_spike',
      source_ip: attackerIp,
      count: 250,
      threshold_exceeded: false
    });

    // 5. Trigger manual scan via API: POST /api/v1/admin/ddos/scan
    console.log('\nTriggering DDoS scan via admin endpoint...');
    const scanRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { scan_type: 'request_spike', window_minutes: 5 }
    });

    console.log('Scan response:', scanRes.body);
    assert.strictEqual(scanRes.status, 200, 'Scan endpoint should return 200 OK');
    assert.strictEqual(scanRes.body.incidents_created, 1, 'Should create 1 incident for threat');
    assert.ok(scanRes.body.threats.some(t => t.source_ip === attackerIp), 'Attacker IP should be detected');

    // Wait 250ms for fire-and-forget policy evaluation to persist proposed action
    await new Promise((resolve) => setTimeout(resolve, 350));

    // 6. Verify Incident created in database
    const incidentsRes = await db.query(
      `SELECT * FROM public.incidents WHERE organization_id = $1 AND threat_type = 'ddos' ORDER BY created_at DESC LIMIT 1;`,
      [orgId]
    );
    assert.ok(incidentsRes.rows.length > 0, 'Incident must exist with threat_type ddos');
    const incident = incidentsRes.rows[0];
    console.log('\nVerified Incident in DB:', {
      id: incident.id,
      threat_type: incident.threat_type,
      source_type: incident.source_type,
      risk_level: incident.risk_level,
      risk_score: incident.risk_score
    });

    assert.strictEqual(incident.threat_type, 'ddos', 'threat_type must be ddos');
    assert.strictEqual(incident.source_type, 'ddos_detection', 'source_type must be ddos_detection');
    assert.strictEqual(incident.risk_level, 'critical', 'risk_level must be critical');
    assert.strictEqual(Number(incident.risk_score), 95, 'risk_score must be 95');

    // 7. Verify MITRE mapping created (T1498 Network Denial of Service)
    const mitreRows = await MitreMapping.findByIncidentId(incident.id);
    assert.ok(mitreRows.length > 0, 'MITRE mapping must be created');
    assert.strictEqual(mitreRows[0].technique_id, 'T1498', 'MITRE technique should be T1498');
    assert.strictEqual(mitreRows[0].technique_name, 'Network Denial of Service');
    console.log('✅ MITRE Mapping Verified: T1498 Network Denial of Service');

    // 8. Verify detection signals created
    const signalRows = await db.query(
      `SELECT * FROM public.detection_signals WHERE incident_id = $1;`,
      [incident.id]
    );
    assert.ok(signalRows.rows.length > 0, 'Detection signals must be recorded');
    const spikeSignal = signalRows.rows.find(s => s.signal_name === 'request_spike');
    assert.ok(spikeSignal, 'request_spike signal must be present');
    assert.strictEqual(spikeSignal.signal_value, '250', 'signal_value should match request count');
    assert.strictEqual(Number(spikeSignal.weight), 0.9, 'weight should be 0.9');
    console.log('✅ Detection Signal Verified:', spikeSignal.signal_name, 'value:', spikeSignal.signal_value);

    // 9. Verify recommended actions created
    const recActions = await db.query(
      `SELECT * FROM public.recommended_actions WHERE incident_id = $1;`,
      [incident.id]
    );
    assert.ok(recActions.rows.length >= 2, 'Must have at least 2 recommended actions');
    const actionTypes = recActions.rows.map(r => r.action_type);
    assert.ok(actionTypes.includes('block_ip'), 'block_ip must be recommended');
    assert.ok(actionTypes.includes('notify_admin'), 'notify_admin must be recommended');
    console.log('✅ Recommended Actions Verified:', actionTypes);

    // 10. Verify Policy Engine proposed response action
    const responseActions = await db.query(
      `SELECT * FROM public.response_actions WHERE incident_id = $1;`,
      [incident.id]
    );
    console.log('\nResponse Actions Created by Policy Engine:', responseActions.rows);
    assert.ok(responseActions.rows.length > 0, 'Policy engine must create at least 1 response_action');
    
    const blockIpAction = responseActions.rows.find(a => a.action_type === 'block_ip');
    assert.ok(blockIpAction, 'block_ip response action must be created');
    assert.strictEqual(blockIpAction.action_mode, 'shadow', 'action_mode must be shadow');
    assert.strictEqual(blockIpAction.status, 'proposed', 'status must be proposed');
    assert.strictEqual(blockIpAction.policy_id, policy.id, 'policy_id must match our created policy');

    const target = typeof blockIpAction.target === 'string'
      ? JSON.parse(blockIpAction.target)
      : blockIpAction.target;

    assert.strictEqual(target.ip_address, attackerIp, 'target ip_address must match attacker source IP');
    assert.strictEqual(target.org_wide, true, 'target org_wide flag must be true');
    console.log('✅ Response Action Verified:', {
      id: blockIpAction.id,
      action_type: blockIpAction.action_type,
      action_mode: blockIpAction.action_mode,
      status: blockIpAction.status,
      target
    });

    console.log('\n🎉 ALL DDOS POLICY ENGINE INTEGRATION CHECKS PASSED! 🎉');
  } finally {
    server.close();
    console.log('\nCleaning up test organization and artifacts...');
    await db.query('DELETE FROM public.organizations WHERE id = $1;', [orgId]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
    process.exit(0);
  }
}

runPolicyIntegrationTest().catch((err) => {
  console.error('❌ Policy Integration Test failed:', err);
  process.exit(1);
});
