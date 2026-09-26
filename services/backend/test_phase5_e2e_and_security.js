/**
 * CYBERGUARD — Phase 5 Unified E2E, Security & Resilience Test Suite
 *
 * Verifies:
 * - STEP 5.7: Security boundaries (missing JWT, invalid JWT, expired JWT, malformed JSON)
 * - STEP 5.9: Full End-to-End flows (URL, Network, Login, Security)
 * - STEP 5.10: Failure & recovery testing (service down -> 502, never false Safe; malformed payloads handled safely)
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-test-jwt-secret-key-32chars!';
const REAL_ML_PORT = process.env.ML_PORT || '8000';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');

const DIVIDER = '═'.repeat(72);
function logSection(title) {
  console.log(`\n${DIVIDER}\n  ${title}\n${DIVIDER}`);
}

async function runPhase5TestSuite() {
  logSection('CYBERGUARD PHASE 5 — FULL SYSTEM INTEGRATION & SECURITY TEST SUITE');

  let server;
  let baseUrl;
  let validToken;
  let expiredToken;
  let forgedToken;

  try {
    // 1. Start Express on ephemeral port
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        console.log(`[Express Gateway] Listening on ephemeral port ${port}`);
        resolve();
      });
    });

    // 2. Generate tokens
    const testUser = { id: 'usr_phase5_tester', role: 'individual', email: 'tester@cyberguard.internal' };
    validToken = jwt.sign(testUser, process.env.JWT_SECRET, { expiresIn: '1h' });
    expiredToken = jwt.sign(testUser, process.env.JWT_SECRET, { expiresIn: '-10s' });
    forgedToken = jwt.sign(testUser, 'wrong_secret_key_hack_attempt', { expiresIn: '1h' });

    // =========================================================================
    // SECTION 1: Security Boundaries (Step 5.7)
    // =========================================================================
    logSection('1. Security Boundary Enforcement Tests');

    // 1a. Missing JWT
    console.log('[Sec 1a] Testing missing JWT...');
    const noAuthRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://cyberguard.io' })
    });
    if (noAuthRes.status !== 401) throw new Error(`Expected 401 for missing JWT, got ${noAuthRes.status}`);
    console.log('✅ PASS: Missing JWT rejected with 401');

    // 1b. Expired JWT
    console.log('[Sec 1b] Testing expired JWT...');
    const expRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${expiredToken}`
      },
      body: JSON.stringify({ url: 'https://cyberguard.io' })
    });
    if (expRes.status !== 401) throw new Error(`Expected 401 for expired JWT, got ${expRes.status}`);
    console.log('✅ PASS: Expired JWT rejected with 401');

    // 1c. Forged JWT signature
    console.log('[Sec 1c] Testing forged JWT signature...');
    const forgeRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${forgedToken}`
      },
      body: JSON.stringify({ url: 'https://cyberguard.io' })
    });
    if (forgeRes.status !== 401) throw new Error(`Expected 401 for forged JWT, got ${forgeRes.status}`);
    console.log('✅ PASS: Forged JWT signature rejected with 401');

    // 1d. Malformed JSON body
    console.log('[Sec 1d] Testing malformed JSON body...');
    const malformedJsonRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: '{"url": "http://test.com", bad_json'
    });
    if (malformedJsonRes.status !== 400) throw new Error(`Expected 400 for malformed JSON, got ${malformedJsonRes.status}`);
    console.log('✅ PASS: Malformed JSON syntax handled safely with 400');

    // =========================================================================
    // SECTION 2: End-to-End Pipeline Verification (Step 5.9)
    // =========================================================================
    logSection('2. End-to-End Integration Verification');

    // Configure ML Service URL to live or active port
    process.env.ML_SERVICE_URL = `http://127.0.0.1:${REAL_ML_PORT}`;

    // 2a. E2E Phishing URL Check
    console.log('[E2E 2a] Testing phishing URL detection...');
    const phishRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({ url: 'http://sl83684.pro/loading.php?user=amazon_account_update' })
    });
    if (phishRes.status !== 200) throw new Error(`Expected 200 for URL check, got ${phishRes.status}`);
    const phishData = await phishRes.json();
    if (phishData.risk_level !== 'Critical') throw new Error(`Expected Critical, got ${phishData.risk_level}`);
    console.log(`✅ PASS: E2E URL detection returned Critical (brand: ${phishData.signals?.target_brand})`);

    // 2b. E2E Network Telemetry
    console.log('[E2E 2b] Testing network surge telemetry...');
    const netRes = await fetch(`${baseUrl}/api/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:00:00Z',
        event_type: 'network_spike',
        details: {
          duration: 0.05,
          packet_count: 500,
          total_bytes: 600000,
          source_bytes: 580000,
          protocol: 'tcp',
          destination_port: 8088
        }
      })
    });
    if (netRes.status !== 201) throw new Error(`Expected 201 for telemetry, got ${netRes.status}`);
    const netData = await netRes.json();
    if (!netData.anomaly_detected || (netData.risk_level !== 'High' && netData.risk_level !== 'Critical')) {
      throw new Error(`Expected anomaly High/Critical, got ${netData.risk_level}`);
    }
    console.log(`✅ PASS: E2E Network telemetry returned ${netData.risk_level} anomaly`);

    // 2c. E2E Login Anomaly
    console.log('[E2E 2c] Testing login anomaly telemetry...');
    const loginRes = await fetch(`${baseUrl}/api/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:00:00Z',
        device_id: 'new-unrecognized-device',
        location: 'Unknown',
        failed_attempts: 5
      })
    });
    if (loginRes.status !== 201) throw new Error(`Expected 201 for login event, got ${loginRes.status}`);
    const loginData = await loginRes.json();
    if (!loginData.anomaly_detected) throw new Error('Expected anomaly_detected: true');
    console.log(`✅ PASS: E2E Login anomaly returned ${loginData.risk_level}`);

    // =========================================================================
    // SECTION 3: Failure & Recovery Testing (Step 5.10)
    // =========================================================================
    logSection('3. Failure & Recovery Resilience');

    // 3a. ML service unavailable simulation
    console.log('[Fail 3a] Testing ML microservice down behavior...');
    // Point gateway to an unreachable port
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:59999';
    const deadMlRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({ url: 'http://example.com' })
    });

    if (deadMlRes.status !== 502) {
      throw new Error(`Expected 502 DETECTION_ENGINE_UNAVAILABLE when ML service is down, got ${deadMlRes.status}`);
    }
    const deadMlData = await deadMlRes.json();
    if (deadMlData.error !== 'DETECTION_ENGINE_UNAVAILABLE') {
      throw new Error(`Expected error code DETECTION_ENGINE_UNAVAILABLE, got: ${JSON.stringify(deadMlData)}`);
    }
    console.log('✅ PASS: Down ML service strictly returns 502 (NEVER silently converted to false Safe)');

    // Restore ML service URL
    process.env.ML_SERVICE_URL = `http://127.0.0.1:${REAL_ML_PORT}`;

    // 3b. Missing required body fields
    console.log('[Fail 3b] Testing missing required fields in /api/check/url...');
    const emptyBodyRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({})
    });
    if (emptyBodyRes.status !== 400) throw new Error(`Expected 400, got ${emptyBodyRes.status}`);
    console.log('✅ PASS: Missing payload fields rejected with 400');

    logSection('ALL PHASE 5 E2E & RESILIENCE TESTS PASSED (10/10)');
  } finally {
    if (server) {
      server.close();
      console.log('[Server] Gateway stopped.');
    }
  }
}

if (require.main === module) {
  runPhase5TestSuite()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ TEST RUN FAILED:', err.message);
      process.exit(1);
    });
}

module.exports = { runPhase5TestSuite };
