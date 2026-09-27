process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const http = require('http');
const { app } = require('./src/index');
const { pool } = require('./src/config/db');

async function sendRequest(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    if (body) {
      reqOptions.headers['Content-Type'] = 'application/json';
      reqOptions.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch {
          json = data;
        }
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: json
        });
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

async function runRateLimitingTests() {
  let server;
  const results = [];

  function recordResult(name, passed, details = '') {
    results.push({ name, passed, details });
    const tag = passed ? '✔ PASS' : '✖ FAIL';
    console.log(`[${tag}] ${name}`);
    if (details) {
      console.log(`       ${details}`);
    }
  }

  try {
    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  CYBERGUARD — EXPRESS RATE LIMITING VERIFICATION SUITE');
    console.log('════════════════════════════════════════════════════════════════════════\n');

    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });

    const port = server.address().port;
    const baseApiUrl = `http://127.0.0.1:${port}/api/v1`;
    const baseRootUrl = `http://127.0.0.1:${port}`;
    console.log(`[INIT] Ephemeral test server active on port ${port}\n`);

    // ──────────────────────────────────────────────────────────────────────────
    // Test Group 1: Auth Limiter (5 requests / 15 min per IP on /auth/login)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Group 1: Strict Auth Rate Limiter (POST /auth/login) ---');
    const loginPayload = JSON.stringify({
      email: 'test_bruteforce@example.com',
      password: 'wrong_password_attempt'
    });

    // Make 5 requests - all should pass rate limiting (status 400 or 401, not 429)
    let firstFivePassed = true;
    for (let i = 1; i <= 5; i++) {
      const res = await sendRequest(`${baseApiUrl}/auth/login`, { method: 'POST' }, loginPayload);
      if (res.status === 429) {
        firstFivePassed = false;
        recordResult(`Login attempt ${i}/5 allowed through rate limiter`, false, `Unexpected 429 on attempt ${i}`);
      }
    }

    if (firstFivePassed) {
      recordResult('First 5 login attempts processed without rate limit error (HTTP 401/400)', true, 'All 5 attempts reached auth handler');
    }

    // 6th request: must be blocked by express-rate-limit with HTTP 429
    const sixthRes = await sendRequest(`${baseApiUrl}/auth/login`, { method: 'POST' }, loginPayload);

    const is429 = sixthRes.status === 429;
    recordResult('6th login attempt within window returns HTTP 429 Too Many Requests', is429, `Status: ${sixthRes.status}`);

    const hasExpectedBody =
      sixthRes.data &&
      sixthRes.data.error === 'RATE_LIMIT_EXCEEDED' &&
      sixthRes.data.message === 'Too many requests, please try again later.';

    recordResult(
      '429 response matches required JSON error structure',
      hasExpectedBody,
      `Payload: ${JSON.stringify(sixthRes.data)}`
    );

    const hasStandardHeaders =
      sixthRes.headers['ratelimit-limit'] !== undefined ||
      sixthRes.headers['retry-after'] !== undefined;

    recordResult(
      'RateLimit headers present in 429 response (standardHeaders: true)',
      hasStandardHeaders,
      `ratelimit-limit: ${sixthRes.headers['ratelimit-limit']}, retry-after: ${sixthRes.headers['retry-after']}`
    );

    // ──────────────────────────────────────────────────────────────────────────
    // Test Group 2: Monitoring Endpoints (/health, /health/readiness) Unthrottled
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Group 2: Monitoring & Health Endpoints (/health, /health/readiness) ---');

    let allHealthOk = true;
    const healthRounds = 30;

    for (let i = 1; i <= healthRounds; i++) {
      const endpoint = i % 2 === 0 ? '/health' : '/health/readiness';
      const res = await sendRequest(`${baseRootUrl}${endpoint}`);
      if (res.status !== 200 || res.data?.status !== 'ok') {
        allHealthOk = false;
        recordResult(`Health check request #${i} to ${endpoint}`, false, `Status: ${res.status}, body: ${JSON.stringify(res.data)}`);
        break;
      }
    }

    if (allHealthOk) {
      recordResult(
        `High volume of health checks (${healthRounds} requests) is NEVER throttled`,
        true,
        `All requests to /health and /health/readiness returned 200 OK`
      );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Summary
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n════════════════════════════════════════════════════════════════════════');
    const totalTests = results.length;
    const passedTests = results.filter((r) => r.passed).length;
    const failedTests = totalTests - passedTests;

    console.log(`  RATE LIMITING TEST SUMMARY: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
    console.log('════════════════════════════════════════════════════════════════════════\n');

    if (failedTests > 0) {
      process.exitCode = 1;
    }
  } catch (err) {
    console.error('[TEST ERROR] Unhandled test exception:', err);
    process.exitCode = 1;
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (pool) {
      await pool.end();
    }
  }
}

runRateLimitingTests();
