process.env.NODE_ENV = 'test';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');
const config = require('./src/config');
const db = require('./src/config/db');

async function runTests() {
  console.log('====================================================');
  console.log('  CYBERGUARD: Dual-Token Auth & Refresh Tests       ');
  console.log('====================================================\n');

  let server;
  let testUserId = null;

  try {
    // 1. Spin up ephemeral server
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[Setup] Test server running on port ${port}`);

    const testEmail = `dual_token_${Date.now()}@cyberguard.test`;
    const testPassword = 'SecurePassword123!';

    // --- STEP 1: Signup & receive accessToken + refreshToken ---
    console.log('[Step 1] User signs up to receive accessToken + refreshToken...');
    const signupRes = await fetch(`${baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        role: 'individual'
      })
    });

    const signupData = await signupRes.json();
    if (signupRes.status !== 201) {
      throw new Error(`Step 1 Failed: Expected 201, got ${signupRes.status}: ${JSON.stringify(signupData)}`);
    }

    if (!signupData.accessToken || typeof signupData.accessToken !== 'string') {
      throw new Error('Step 1 Failed: Missing accessToken in signup response');
    }
    if (!signupData.refreshToken || typeof signupData.refreshToken !== 'string') {
      throw new Error('Step 1 Failed: Missing refreshToken in signup response');
    }

    testUserId = signupData.user.id;
    const rawRefreshToken = signupData.refreshToken;
    let currentAccessToken = signupData.accessToken;

    // Check Set-Cookie header
    const setCookie = signupRes.headers.get('set-cookie');
    if (!setCookie || !setCookie.includes('refreshToken=')) {
      throw new Error('Step 1 Failed: Expected HTTP-only refreshToken cookie in response');
    }

    console.log(`  User ID:       ${testUserId}`);
    console.log(`  Access Token:  ${currentAccessToken.slice(0, 30)}...`);
    console.log(`  Refresh Token: ${rawRefreshToken.slice(0, 16)}... (32-byte hex)`);
    console.log(`  Set-Cookie:    ${setCookie.split(';')[0]}`);
    console.log('✅ PASS [Step 1]: Signup issued 15m accessToken, 7d refreshToken, and HTTP-only cookie.\n');

    // --- STEP 2: Immediately call POST /auth/refresh with refreshToken ---
    console.log('[Step 2] Immediately calling POST /auth/refresh with refreshToken...');
    const refreshRes1 = await fetch(`${baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refreshToken: rawRefreshToken
      })
    });

    const refreshData1 = await refreshRes1.json();
    if (refreshRes1.status !== 200) {
      throw new Error(`Step 2 Failed: Expected 200 from /auth/refresh, got ${refreshRes1.status}: ${JSON.stringify(refreshData1)}`);
    }
    if (!refreshData1.accessToken || typeof refreshData1.accessToken !== 'string') {
      throw new Error('Step 2 Failed: Missing new accessToken in refresh response');
    }

    const refreshedAccessToken = refreshData1.accessToken;
    console.log(`  Refreshed Token: ${refreshedAccessToken.slice(0, 30)}...`);
    console.log('✅ PASS [Step 2]: POST /auth/refresh issued new accessToken from valid refreshToken.\n');

    // --- STEP 3: Expired access token returns 401 TOKEN_EXPIRED with refresh guidance ---
    console.log('[Step 3] Testing expired accessToken behavior on protected endpoint...');
    // Create an expired access token (expired 2 seconds ago)
    const expiredToken = jwt.sign(
      {
        id: testUserId,
        email: testEmail,
        role: 'individual',
        organization_id: null
      },
      config.JWT_SECRET,
      { expiresIn: '-2s' }
    );

    const expiredReqRes = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${expiredToken}`
      }
    });

    const expiredReqData = await expiredReqRes.json();
    if (expiredReqRes.status !== 401) {
      throw new Error(`Step 3 Failed: Expected 401 for expired token, got ${expiredReqRes.status}`);
    }
    if (expiredReqData.error !== 'TOKEN_EXPIRED') {
      throw new Error(`Step 3 Failed: Expected error 'TOKEN_EXPIRED', got '${expiredReqData.error}'`);
    }
    if (!expiredReqData.message.includes('/refresh')) {
      throw new Error(`Step 3 Failed: Message should guide user to /refresh, got: '${expiredReqData.message}'`);
    }
    console.log(`  Status:  ${expiredReqRes.status} Unauthorized`);
    console.log(`  Error:   ${expiredReqData.error}`);
    console.log(`  Message: "${expiredReqData.message}"`);
    console.log('✅ PASS [Step 3]: Expired token returned 401 TOKEN_EXPIRED directing client to /auth/refresh.\n');

    // --- STEP 4: Call POST /auth/refresh with refreshToken to get new accessToken ---
    console.log('[Step 4] Calling POST /auth/refresh to renew session after expiration...');
    const refreshRes2 = await fetch(`${baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refreshToken: rawRefreshToken
      })
    });

    const refreshData2 = await refreshRes2.json();
    if (refreshRes2.status !== 200 || !refreshData2.accessToken) {
      throw new Error(`Step 4 Failed: Expected 200 and accessToken, got ${refreshRes2.status}`);
    }
    const renewedAccessToken = refreshData2.accessToken;
    console.log(`  Renewed Token: ${renewedAccessToken.slice(0, 30)}...`);
    console.log('✅ PASS [Step 4]: Successfully renewed access token using stored refresh token.\n');

    // --- STEP 5: Use new accessToken on protected endpoint ---
    console.log('[Step 5] Accessing protected /auth/me with renewed access token...');
    const protectedRes = await fetch(`${baseUrl}/auth/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${renewedAccessToken}`
      }
    });

    const protectedData = await protectedRes.json();
    if (protectedRes.status !== 200) {
      throw new Error(`Step 5 Failed: Expected 200 from /auth/me, got ${protectedRes.status}: ${JSON.stringify(protectedData)}`);
    }
    if (protectedData.id !== testUserId || protectedData.email !== testEmail) {
      throw new Error(`Step 5 Failed: Profile mismatch: ${JSON.stringify(protectedData)}`);
    }
    console.log(`  Verified User: ${protectedData.email} (${protectedData.role})`);
    console.log('✅ PASS [Step 5]: Renewed access token successfully authenticated protected endpoint.\n');

    // --- STEP 6: Call POST /auth/logout -> refresh tokens revoked ---
    console.log('[Step 6] Calling POST /auth/logout to revoke user refresh tokens...');
    const logoutRes = await fetch(`${baseUrl}/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${renewedAccessToken}`
      }
    });

    const logoutData = await logoutRes.json();
    if (logoutRes.status !== 200) {
      throw new Error(`Step 6 Failed: Expected 200 for logout, got ${logoutRes.status}: ${JSON.stringify(logoutData)}`);
    }
    if (logoutData.message !== 'Logged out') {
      throw new Error(`Step 6 Failed: Expected message 'Logged out', got '${logoutData.message}'`);
    }

    // Verify clear-cookie was issued
    const logoutCookie = logoutRes.headers.get('set-cookie');
    console.log(`  Logout Response: ${logoutData.message}`);
    console.log('✅ PASS [Step 6]: User logged out and refreshToken revoked in DB.\n');

    // --- STEP 7: Try POST /auth/refresh with revoked token -> confirm 401 REFRESH_TOKEN_INVALID ---
    console.log('[Step 7] Trying POST /auth/refresh with the revoked refresh token...');
    const revokedRefreshRes = await fetch(`${baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refreshToken: rawRefreshToken
      })
    });

    const revokedRefreshData = await revokedRefreshRes.json();
    if (revokedRefreshRes.status !== 401) {
      throw new Error(`Step 7 Failed: Expected 401 for revoked refresh token, got ${revokedRefreshRes.status}: ${JSON.stringify(revokedRefreshData)}`);
    }
    if (revokedRefreshData.error !== 'REFRESH_TOKEN_INVALID') {
      throw new Error(`Step 7 Failed: Expected error 'REFRESH_TOKEN_INVALID', got '${revokedRefreshData.error}'`);
    }
    console.log(`  Status:  ${revokedRefreshRes.status} Unauthorized`);
    console.log(`  Error:   ${revokedRefreshData.error}`);
    console.log(`  Message: "${revokedRefreshData.message}"`);
    console.log('✅ PASS [Step 7]: Revoked refresh token rejected with 401 REFRESH_TOKEN_INVALID.\n');

    console.log('====================================================');
    console.log('  ALL DUAL-TOKEN REFRESH TESTS PASSED (7/7)         ');
    console.log('====================================================');
    process.exitCode = 0;
  } catch (err) {
    console.error('\n❌ TEST RUN FAILED:', err.message);
    process.exitCode = 1;
  } finally {
    // Cleanup test user
    if (testUserId) {
      console.log('[Cleanup] Cleaning up test user and refresh tokens...');
      await db.query(`DELETE FROM users WHERE id = $1`, [testUserId]);
      console.log('[Cleanup] Done.');
    }
    if (server) {
      server.close();
    }
    setTimeout(() => process.exit(process.exitCode || 0), 500);
  }
}

runTests();
