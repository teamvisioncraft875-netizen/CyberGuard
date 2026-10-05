process.env.NODE_ENV = 'test';
const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const db = require('./src/config/db');
const { app } = require('./src/index');
const Organization = require('./src/models/Organization');
const User = require('./src/models/User');
const DDoSAlert = require('./src/models/DDoSAlert');
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

async function runApiTests() {
  console.log('--- Starting DDoS API Integration Tests ---');

  // 1. Create test organizations (Org A and Org B for tenant scoping test)
  const orgA = await Organization.create({ name: 'DDoS API Org A ' + Math.random().toString(36).substring(7) });
  const orgB = await Organization.create({ name: 'DDoS API Org B ' + Math.random().toString(36).substring(7) });

  // 2. Create users: Admin A, Employee A, Admin B
  const adminA = await User.create({
    email: 'admin_a_' + Math.random().toString(36).substring(7) + '@test.com',
    password_hash: 'hash',
    role: 'admin',
    organization_id: orgA.id
  });

  const employeeA = await User.create({
    email: 'emp_a_' + Math.random().toString(36).substring(7) + '@test.com',
    password_hash: 'hash',
    role: 'employee',
    organization_id: orgA.id
  });

  const adminB = await User.create({
    email: 'admin_b_' + Math.random().toString(36).substring(7) + '@test.com',
    password_hash: 'hash',
    role: 'admin',
    organization_id: orgB.id
  });

  const tokenAdminA = jwt.sign(
    { id: adminA.id, email: adminA.email, role: 'admin', organization_id: orgA.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const tokenEmployeeA = jwt.sign(
    { id: employeeA.id, email: employeeA.email, role: 'employee', organization_id: orgA.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const tokenAdminB = jwt.sign(
    { id: adminB.id, email: adminB.email, role: 'admin', organization_id: orgB.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    // =========================================================================
    // Test 1: Authentication & Authorization on POST /api/v1/admin/ddos/scan
    // =========================================================================
    console.log('\n[Test 1] Auth & RBAC on POST /api/v1/admin/ddos/scan...');
    
    // 1a. Missing token -> 401
    const noAuthRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      body: { scan_type: 'request_spike' }
    });
    assert.strictEqual(noAuthRes.status, 401, 'Should return 401 without auth token');

    // 1b. Employee token -> 403 Forbidden
    const forbiddenRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${tokenEmployeeA}` },
      body: { scan_type: 'request_spike' }
    });
    assert.strictEqual(forbiddenRes.status, 403, 'Should return 403 for non-admin user');
    console.log('✅ Test 1 (Auth & RBAC) PASSED');

    // =========================================================================
    // Test 2: Input Validation on POST /api/v1/admin/ddos/scan
    // =========================================================================
    console.log('\n[Test 2] Input validation on POST /api/v1/admin/ddos/scan...');
    const invalidScanRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${tokenAdminA}` },
      body: { scan_type: 'unknown_attack_type' }
    });
    assert.strictEqual(invalidScanRes.status, 400, 'Should return 400 for invalid scan_type');
    assert.strictEqual(invalidScanRes.body.error, 'INVALID_SCAN_TYPE');
    console.log('✅ Test 2 (Input Validation) PASSED');

    // =========================================================================
    // Test 3: Successful Scan Execution & Incident Creation
    // =========================================================================
    console.log('\n[Test 3] Trigger scan with detected threat & incident creation...');
    process.env.DDOS_REQUEST_SPIKE_THRESHOLD = '25';

    // Seed a metric for Org A that exceeds the threshold
    const attackerIp = '198.51.100.111';
    await DDoSAlert.create({
      organization_id: orgA.id,
      metric_type: 'request_spike',
      source_ip: attackerIp,
      count: 75,
      threshold_exceeded: false
    });

    const scanRes = await request(server, {
      method: 'POST',
      path: '/api/v1/admin/ddos/scan',
      headers: { Authorization: `Bearer ${tokenAdminA}` },
      body: { scan_type: 'request_spike', window_minutes: 5 }
    });

    console.log('Scan Response:', scanRes.body);
    assert.strictEqual(scanRes.status, 200, 'Should return 200 OK');
    assert.strictEqual(scanRes.body.metric_type, 'request_spike');
    assert.ok(Array.isArray(scanRes.body.threats), 'threats must be an array');
    assert.ok(scanRes.body.threats.length > 0, 'Should identify at least 1 threat');
    assert.ok(scanRes.body.incidents_created >= 1, 'Should create at least 1 incident');

    // Verify audit log entry
    const auditRes = await db.query(
      `SELECT * FROM public.audit_logs 
       WHERE organization_id = $1 AND action = 'ddos_scan_triggered' 
       ORDER BY created_at DESC LIMIT 1;`,
      [orgA.id]
    );
    assert.ok(auditRes.rows.length > 0, 'Audit log entry must be created with action ddos_scan_triggered');
    console.log('✅ Test 3 (Scan Execution & Audit Log) PASSED');

    // =========================================================================
    // Test 4: View Active Threats & Org Scoping on GET /api/v1/admin/ddos/threats
    // =========================================================================
    console.log('\n[Test 4] GET /api/v1/admin/ddos/threats & Org Scoping...');

    // 4a. Admin A retrieves threats
    const threatsResA = await request(server, {
      method: 'GET',
      path: '/api/v1/admin/ddos/threats?scan_type=request_spike',
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });

    assert.strictEqual(threatsResA.status, 200, 'Should return 200 OK');
    assert.ok(Array.isArray(threatsResA.body.threats), 'threats must be an array');
    assert.ok(threatsResA.body.total >= 1, 'Org A should have at least 1 threat');
    const orgAThreat = threatsResA.body.threats.find(t => t.source_ip === attackerIp);
    assert.ok(orgAThreat, 'Org A should see attacker IP');

    // 4b. Admin B retrieves threats (Org B should NOT see Org A threats)
    const threatsResB = await request(server, {
      method: 'GET',
      path: '/api/v1/admin/ddos/threats',
      headers: { Authorization: `Bearer ${tokenAdminB}` }
    });

    assert.strictEqual(threatsResB.status, 200, 'Should return 200 OK');
    const leakMatch = threatsResB.body.threats.find(t => t.source_ip === attackerIp);
    assert.strictEqual(leakMatch, undefined, 'Org B must NOT see Org A threats (Strict Tenant Isolation)');
    console.log('✅ Test 4 (View Threats & Tenant Isolation) PASSED');

    console.log('\n🎉 ALL DDOS API INTEGRATION TESTS PASSED SUCCESSFULLY! 🎉');
  } finally {
    server.close();
    console.log('\nCleaning up test organizations...');
    await db.query('DELETE FROM public.organizations WHERE id IN ($1, $2)', [orgA.id, orgB.id]);
    if (db.pool && db.pool.end) {
      await db.pool.end();
    }
    process.exit(0);
  }
}

runApiTests().catch((err) => {
  console.error('❌ DDoS API tests failed:', err);
  process.exit(1);
});
