process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
const { app, server: gatewayServer } = require('./src');
const jwt = require('jsonwebtoken');
const db = require('./src/config/db');
const User = require('./src/models/User');
const Organization = require('./src/models/Organization');

async function runRealAuthTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — REAL AUTHENTICATION VERIFICATION SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdUserIds = [];
  const createdOrgIds = [];

  const timestamp = Date.now();
  const individualEmail = `real_ind_${timestamp}@cyberguard.internal`;
  const adminEmail = `real_emp1_${timestamp}@cyberguard.internal`;
  const employeeEmail = `real_emp2_${timestamp}@cyberguard.internal`;
  const orgName = `Test Corp ${timestamp}`;
  const validPassword = 'SecurePassword123!';
  const wrongPassword = 'IncorrectPassword999!';

  try {
    // 1. Start ephemeral HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}`);
        resolve();
      });
    });

    let indToken, adminToken, empToken;

    // ──────────────────────────────────────────────────────────────────────────
    // Test 1: Signup Individual User
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Test 1: Signup Individual User ---');
    const res1 = await fetch(`${baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: individualEmail,
        password: validPassword,
        role: 'individual'
      })
    });

    const data1 = await res1.json();
    if (res1.status !== 201) {
      throw new Error(`Test 1 Failed: Expected status 201, got ${res1.status}: ${JSON.stringify(data1)}`);
    }
    if (!data1.token || !data1.user || data1.user.role !== 'individual' || data1.user.organization_id !== null) {
      throw new Error(`Test 1 Failed: Invalid payload returned: ${JSON.stringify(data1)}`);
    }

    // Verify JWT signature and claims
    const decoded1 = jwt.verify(data1.token, process.env.JWT_SECRET);
    if (decoded1.id !== data1.user.id || decoded1.role !== 'individual' || decoded1.organization_id !== null) {
      throw new Error(`Test 1 Failed: JWT claims mismatch: ${JSON.stringify(decoded1)}`);
    }
    indToken = data1.token;
    createdUserIds.push(data1.user.id);
    console.log(`✔ [PASS] Test 1: Created individual user ${data1.user.id}, JWT verified valid (24h expiry)`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 2: Signup Employee with a New Organization (Should become Admin)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 2: Signup Employee with New Organization (Becomes Admin) ---');
    const res2 = await fetch(`${baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: adminEmail,
        password: validPassword,
        role: 'employee',
        organization_name: orgName
      })
    });

    const data2 = await res2.json();
    if (res2.status !== 201) {
      throw new Error(`Test 2 Failed: Expected status 201, got ${res2.status}: ${JSON.stringify(data2)}`);
    }
    if (data2.user.role !== 'admin' || !data2.user.organization_id) {
      throw new Error(`Test 2 Failed: Expected role 'admin' for new org creator, got: ${JSON.stringify(data2.user)}`);
    }

    const decoded2 = jwt.verify(data2.token, process.env.JWT_SECRET);
    if (decoded2.role !== 'admin' || decoded2.organization_id !== data2.user.organization_id) {
      throw new Error(`Test 2 Failed: JWT claims mismatch: ${JSON.stringify(decoded2)}`);
    }
    adminToken = data2.token;
    createdUserIds.push(data2.user.id);
    createdOrgIds.push(data2.user.organization_id);
    console.log(`✔ [PASS] Test 2: New organization '${orgName}' created, user promoted to admin (${data2.user.id})`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 3: Signup Second Employee in Same Organization (Should remain Employee)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 3: Signup Second Employee in Same Organization (Remains Employee) ---');
    const res3 = await fetch(`${baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: employeeEmail,
        password: validPassword,
        role: 'employee',
        organization_name: orgName
      })
    });

    const data3 = await res3.json();
    if (res3.status !== 201) {
      throw new Error(`Test 3 Failed: Expected status 201, got ${res3.status}: ${JSON.stringify(data3)}`);
    }
    if (data3.user.role !== 'employee' || data3.user.organization_id !== data2.user.organization_id) {
      throw new Error(`Test 3 Failed: Expected role 'employee' joining existing org, got: ${JSON.stringify(data3.user)}`);
    }

    const decoded3 = jwt.verify(data3.token, process.env.JWT_SECRET);
    if (decoded3.role !== 'employee' || decoded3.organization_id !== data2.user.organization_id) {
      throw new Error(`Test 3 Failed: JWT claims mismatch: ${JSON.stringify(decoded3)}`);
    }
    empToken = data3.token;
    createdUserIds.push(data3.user.id);
    console.log(`✔ [PASS] Test 3: Second user joined existing organization as employee (${data3.user.id}, not admin)`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 4: Login with Correct Password
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 4: Login with Correct Password ---');
    const res4 = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: individualEmail,
        password: validPassword
      })
    });

    const data4 = await res4.json();
    if (res4.status !== 200) {
      throw new Error(`Test 4 Failed: Expected status 200, got ${res4.status}: ${JSON.stringify(data4)}`);
    }
    if (!data4.token || data4.user.email !== individualEmail || data4.user.password_hash !== undefined) {
      throw new Error(`Test 4 Failed: Invalid login response or password_hash leaked: ${JSON.stringify(data4)}`);
    }
    const decoded4 = jwt.verify(data4.token, process.env.JWT_SECRET);
    if (decoded4.email !== individualEmail) {
      throw new Error(`Test 4 Failed: JWT email mismatch: ${JSON.stringify(decoded4)}`);
    }
    console.log(`✔ [PASS] Test 4: Login succeeded with correct password, JWT verified valid`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 5: Login with Wrong Password
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 5: Login with Wrong Password ---');
    const res5 = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: individualEmail,
        password: wrongPassword
      })
    });

    const data5 = await res5.json();
    if (res5.status !== 401 || data5.error !== 'INVALID_CREDENTIALS') {
      throw new Error(`Test 5 Failed: Expected 401 INVALID_CREDENTIALS, got ${res5.status}: ${JSON.stringify(data5)}`);
    }
    console.log(`✔ [PASS] Test 5: Login with wrong password rejected with 401 INVALID_CREDENTIALS`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 6: Login with Nonexistent Email
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 6: Login with Nonexistent Email ---');
    const res6 = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `ghost_${timestamp}@cyberguard.internal`,
        password: validPassword
      })
    });

    const data6 = await res6.json();
    if (res6.status !== 401 || data6.error !== 'INVALID_CREDENTIALS') {
      throw new Error(`Test 6 Failed: Expected 401 INVALID_CREDENTIALS, got ${res6.status}: ${JSON.stringify(data6)}`);
    }
    console.log(`✔ [PASS] Test 6: Login with nonexistent email rejected with 401 INVALID_CREDENTIALS`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 7: GET /auth/me with Valid Token
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 7: GET /auth/me with Valid Token ---');
    const res7 = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    const data7 = await res7.json();
    if (res7.status !== 200) {
      throw new Error(`Test 7 Failed: Expected 200, got ${res7.status}: ${JSON.stringify(data7)}`);
    }
    if (data7.email !== adminEmail || data7.role !== 'admin' || data7.password_hash !== undefined) {
      throw new Error(`Test 7 Failed: Returned mock or invalid database record: ${JSON.stringify(data7)}`);
    }
    console.log(`✔ [PASS] Test 7: GET /me returned real DB profile for ${data7.email} (password_hash stripped)`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test 8: GET /auth/me with Invalid / Expired Token
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Test 8: GET /auth/me with Invalid & Expired Tokens ---');
    // 8a. Tampered token
    const tamperedToken = adminToken.slice(0, -6) + 'abcdef';
    const res8a = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tamperedToken}` }
    });
    if (res8a.status !== 401) {
      throw new Error(`Test 8a Failed: Expected 401 for tampered token, got ${res8a.status}`);
    }

    // 8b. Expired token
    const expiredToken = jwt.sign(
      { id: data2.user.id, email: adminEmail, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '-10s' }
    );
    const res8b = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${expiredToken}` }
    });
    if (res8b.status !== 401) {
      throw new Error(`Test 8b Failed: Expected 401 for expired token, got ${res8b.status}`);
    }

    // 8c. Missing header
    const res8c = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET'
    });
    if (res8c.status !== 401) {
      throw new Error(`Test 8c Failed: Expected 401 for missing header, got ${res8c.status}`);
    }
    console.log(`✔ [PASS] Test 8: Tampered, expired, and missing tokens strictly rejected with 401`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 8 REAL AUTHENTICATION TESTS PASSED 100%!');
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } finally {
    // Teardown test server and cleanup test database records
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }

    console.log('[CLEANUP] Cleaning up test users and organizations...');
    for (const uid of createdUserIds) {
      try {
        await db.query('DELETE FROM users WHERE id = $1', [uid]);
      } catch (_) {}
    }
    for (const oid of createdOrgIds) {
      try {
        await db.query('DELETE FROM organizations WHERE id = $1', [oid]);
      } catch (_) {}
    }
    console.log('[CLEANUP] Complete.');
    await db.pool.end();
  }
}

runRealAuthTests().catch((err) => {
  console.error('\n❌ TEST SUITE FAILED:', err);
  process.exit(1);
});
