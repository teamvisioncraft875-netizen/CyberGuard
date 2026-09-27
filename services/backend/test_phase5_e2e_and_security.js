/**
 * CYBERGUARD — Phase D / Phase 5 Unified E2E, Security & Resilience Test Suite
 *
 * Verifies:
 * - SECTION 1: Security boundaries (missing JWT, invalid JWT, expired JWT, malformed JSON)
 * - SECTION 2: Existing E2E verification (URL, Network)
 * - SECTION 3: Phase D Login Anomaly Detection Engine End-to-End & Security Tests:
 *     - Test 1: Valid login telemetry returns 201 with full UnifiedAnalysis schema
 *     - Test 2: Anomalous login produces elevated anomaly score and High/Critical risk
 *     - Test 3: Normal/low-anomaly login returns operational classification
 *     - Test 4: Malformed request payloads return HTTP 400 (missing fields, invalid types)
 *     - Test 5: Unauthorized requests return HTTP 401 (missing, expired, forged JWT)
 *     - Test 6: ML service unavailable returns HTTP 502 (Never false Safe)
 *     - Test 7: ML service timeout returns HTTP 502 (bounded timeout)
 *     - Test 8: Malformed ML response returns HTTP 502
 *     - Test 9: No credential leakage in response body or error payloads
 *     - Test 10: Existing URL and Network telemetry endpoints remain operational
 * - SECTION 4: End-to-end Backend -> ML -> Backend Performance Benchmark
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-test-jwt-secret-key-32chars!';
const REAL_ML_PORT = process.env.ML_PORT || '8000';
const LIVE_ML_URL = `http://127.0.0.1:${REAL_ML_PORT}`;

const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const jwt = require('jsonwebtoken');
const { app } = require('./src/index');

const DIVIDER = '═'.repeat(72);
function logSection(title) {
  console.log(`\n${DIVIDER}\n  ${title}\n${DIVIDER}`);
}

async function isMlRunning(url) {
  try {
    const res = await fetch(`${url}/health`, { signal: AbortSignal.timeout(1500) });
    return res.ok;
  } catch {
    return false;
  }
}

async function ensureMlService() {
  if (await isMlRunning(LIVE_ML_URL)) {
    console.log(`[ML Service] Active instance verified healthy at ${LIVE_ML_URL}`);
    return null;
  }

  console.log(`[ML Service] Not answering on port ${REAL_ML_PORT}. Spawning Python FastAPI engine...`);
  const mlDir = path.resolve(__dirname, '../ml-service');
  const mlProc = spawn('python', ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', REAL_ML_PORT], {
    cwd: mlDir,
    stdio: 'ignore'
  });

  const startTime = Date.now();
  while (Date.now() - startTime < 25000) {
    await new Promise((r) => setTimeout(r, 600));
    if (await isMlRunning(LIVE_ML_URL)) {
      console.log(`[ML Service] Process spawned successfully and responding at ${LIVE_ML_URL}`);
      return mlProc;
    }
  }

  mlProc.kill();
  throw new Error(`Failed to start ML Service on port ${REAL_ML_PORT} within 25 seconds`);
}

async function runPhase5TestSuite() {
  logSection('CYBERGUARD PHASE D — E2E GATEWAY INTEGRATION & SECURITY TEST SUITE');

  let server;
  let baseUrl;
  let validToken;
  let expiredToken;
  let forgedToken;
  let spawnedMlProcess = null;

  try {
    // 0. Ensure Python ML Microservice is running
    spawnedMlProcess = await ensureMlService();
    process.env.ML_SERVICE_URL = LIVE_ML_URL;

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
    // SECTION 1: Gateway Security Boundary Enforcement
    // =========================================================================
    logSection('1. Security Boundary Enforcement Tests');

    // 1a. Missing JWT
    console.log('[Sec 1a] Testing missing JWT on /api/check/url...');
    const noAuthRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://cyberguard.io' })
    });
    if (noAuthRes.status !== 401) throw new Error(`Expected 401 for missing JWT, got ${noAuthRes.status}`);
    console.log('✅ PASS: Missing JWT rejected with 401');

    // 1b. Expired JWT
    console.log('[Sec 1b] Testing expired JWT on /api/check/url...');
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
    // SECTION 2: Existing Detection Engines (URL & Network) Verification
    // =========================================================================
    logSection('2. Existing Detection Engines Verification (URL & Network)');

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

    // =========================================================================
    // SECTION 3: Phase D Login Anomaly Detection E2E & Security Tests
    // =========================================================================
    logSection('3. Phase D Login Anomaly Engine Integration & Security Tests');

    // TEST 1: Valid Login Telemetry
    console.log('[Phase D — Test 1] Testing valid login telemetry ingestion...');
    const validLoginPayload = {
      timestamp: '2026-09-25T12:00:00Z',
      location: 'Tokyo, JP',
      device_id: 'workstation-corp-01',
      failed_attempts: 1
    };
    const t1Res = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });
    if (t1Res.status !== 201) throw new Error(`Expected 201, got ${t1Res.status}`);
    const t1Data = await t1Res.json();
    if (t1Data.status !== 'recorded') throw new Error(`Expected status: recorded, got ${t1Data.status}`);
    if (!['Safe', 'Low', 'Medium', 'High', 'Critical'].includes(t1Data.risk_level)) {
      throw new Error(`Invalid risk_level: ${t1Data.risk_level}`);
    }
    if (typeof t1Data.risk_score !== 'number' || t1Data.risk_score < 0 || t1Data.risk_score > 100) {
      throw new Error(`Invalid risk_score: ${t1Data.risk_score}`);
    }
    if (typeof t1Data.explanation !== 'string' || !t1Data.explanation.length) {
      throw new Error('Explanation missing from login telemetry response');
    }
    if (!Array.isArray(t1Data.recommended_actions)) {
      throw new Error('Recommended actions must be an array');
    }
    if (!t1Data.signals || typeof t1Data.signals !== 'object') {
      throw new Error('Signals object missing from response');
    }
    if (t1Data.signals.supervised_probability !== null) {
      throw new Error('supervised_probability must strictly be null (no fabricated probabilities)');
    }
    if (typeof t1Data.signals.anomaly_score !== 'number' || t1Data.signals.anomaly_score < 0.0 || t1Data.signals.anomaly_score > 1.0) {
      throw new Error(`Invalid anomaly_score: ${t1Data.signals.anomaly_score}`);
    }
    console.log(`✅ PASS: Valid login telemetry recorded (Risk: ${t1Data.risk_level}, Score: ${t1Data.risk_score}, Anomaly: ${t1Data.signals.anomaly_score})`);

    // TEST 2: Anomalous Login (High Failed Attempts / Session Burst)
    console.log('[Phase D — Test 2] Testing anomalous login event (elevated anomaly)...');
    const adversaryUser = { id: 'usr_adversary_burst', role: 'individual' };
    const adversaryToken = jwt.sign(adversaryUser, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Establish session baseline
    await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adversaryToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:00:00Z',
        location: 'Unknown Tor Exit',
        device_id: 'unknown-adversary-device',
        failed_attempts: 1
      })
    });

    // Subsequent high-volume failure event within session window (75s later)
    const t2Res = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adversaryToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:01:15Z',
        location: 'Unknown Tor Exit',
        device_id: 'unknown-adversary-device',
        failed_attempts: 15
      })
    });
    if (t2Res.status !== 201) throw new Error(`Expected 201, got ${t2Res.status}`);
    const t2Data = await t2Res.json();
    if (!t2Data.anomaly_detected) throw new Error('Expected anomaly_detected: true for brute-force pattern');
    if (t2Data.risk_level !== 'High' && t2Data.risk_level !== 'Critical') {
      throw new Error(`Expected High or Critical risk for 15 failed attempts across window, got ${t2Data.risk_level}`);
    }
    if (t2Data.signals.anomaly_score < 0.6) {
      throw new Error(`Expected anomaly_score >= 0.6 for anomalous login, got ${t2Data.signals.anomaly_score}`);
    }
    console.log(`✅ PASS: Anomalous login classified as ${t2Data.risk_level} (anomaly_score: ${t2Data.signals.anomaly_score})`);

    // TEST 3: Normal / Low-Anomaly Login
    console.log('[Phase D — Test 3] Testing baseline / lower-anomaly login...');
    const normalUser = { id: 'usr_benign_normal', role: 'individual' };
    const normalToken = jwt.sign(normalUser, process.env.JWT_SECRET, { expiresIn: '1h' });

    const normalPayload = {
      timestamp: '2026-09-25T12:00:00Z',
      location: 'San Francisco, US',
      device_id: 'trusted-laptop-01',
      failed_attempts: 0
    };
    const t3Res = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${normalToken}`
      },
      body: JSON.stringify(normalPayload)
    });
    if (t3Res.status !== 201) throw new Error(`Expected 201, got ${t3Res.status}`);
    const t3Data = await t3Res.json();
    if (t3Data.signals.anomaly_score >= t2Data.signals.anomaly_score) {
      throw new Error(`Normal login anomaly score (${t3Data.signals.anomaly_score}) should be lower than anomalous score (${t2Data.signals.anomaly_score})`);
    }
    console.log(`✅ PASS: Lower-anomaly login classified as ${t3Data.risk_level} (anomaly_score: ${t3Data.signals.anomaly_score} < ${t2Data.signals.anomaly_score})`);

    // TEST 4: Malformed Request Validation
    console.log('[Phase D — Test 4] Testing request validation rejects malformed payloads (400)...');
    const malformedCases = [
      { name: 'Missing timestamp', body: { device_id: 'dev1', failed_attempts: 0 } },
      { name: 'Missing device_id', body: { timestamp: '2026-09-25T12:00:00Z', failed_attempts: 0 } },
      { name: 'Missing failed_attempts', body: { timestamp: '2026-09-25T12:00:00Z', device_id: 'dev1' } },
      { name: 'Negative failed_attempts', body: { timestamp: '2026-09-25T12:00:00Z', device_id: 'dev1', failed_attempts: -3 } },
      { name: 'Non-numeric failed_attempts', body: { timestamp: '2026-09-25T12:00:00Z', device_id: 'dev1', failed_attempts: 'many' } },
      { name: 'Invalid ISO timestamp', body: { timestamp: 'not-a-timestamp', device_id: 'dev1', failed_attempts: 0 } },
      { name: 'Non-string location', body: { timestamp: '2026-09-25T12:00:00Z', device_id: 'dev1', failed_attempts: 0, location: 9999 } }
    ];

    for (const testCase of malformedCases) {
      const res = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validToken}`
        },
        body: JSON.stringify(testCase.body)
      });
      if (res.status !== 400) {
        throw new Error(`Expected 400 for [${testCase.name}], got ${res.status}`);
      }
      const errData = await res.json();
      if (errData.error !== 'INVALID_PAYLOAD') {
        throw new Error(`Expected error code INVALID_PAYLOAD, got ${errData.error}`);
      }
    }
    console.log(`✅ PASS: All ${malformedCases.length} malformed request payloads rejected with HTTP 400`);

    // TEST 5: Unauthorized Access Control
    console.log('[Phase D — Test 5] Testing authentication enforcement on login telemetry...');
    // 5a. Missing token
    const noTokenRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validLoginPayload)
    });
    if (noTokenRes.status !== 401) throw new Error(`Expected 401 for missing token, got ${noTokenRes.status}`);

    // 5b. Expired token
    const expTokenRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${expiredToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });
    if (expTokenRes.status !== 401) throw new Error(`Expected 401 for expired token, got ${expTokenRes.status}`);

    // 5c. Forged token
    const forgeTokenRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${forgedToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });
    if (forgeTokenRes.status !== 401) throw new Error(`Expected 401 for forged token, got ${forgeTokenRes.status}`);
    console.log('✅ PASS: Unauthorized requests (missing, expired, forged JWT) strictly rejected with 401');

    // TEST 6: ML Service Unavailable Simulation -> HTTP 502 (Fail-Closed)
    console.log('[Phase D — Test 6] Testing ML service unavailable -> HTTP 502 (Never false Safe)...');
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:59997'; // Unbound port
    const downRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });
    if (downRes.status !== 502) {
      throw new Error(`Expected 502 Bad Gateway when ML service is down, got ${downRes.status}`);
    }
    const downData = await downRes.json();
    if (downData.error !== 'DETECTION_ENGINE_UNAVAILABLE') {
      throw new Error(`Expected error code DETECTION_ENGINE_UNAVAILABLE, got ${downData.error}`);
    }
    // Restore URL
    process.env.ML_SERVICE_URL = LIVE_ML_URL;
    console.log('✅ PASS: Down ML service strictly yields HTTP 502 DETECTION_ENGINE_UNAVAILABLE (NEVER 200 or Safe)');

    // TEST 7: ML Service Timeout Simulation -> HTTP 502
    console.log('[Phase D — Test 7] Testing ML service timeout -> HTTP 502...');
    const hangServer = http.createServer((req, res) => {
      // Deliberately delay beyond timeout threshold
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ risk_level: 'Safe', risk_score: 0 }));
        }
      }, 400);
    });
    await new Promise((r) => hangServer.listen(0, '127.0.0.1', r));
    const hangPort = hangServer.address().port;

    process.env.ML_SERVICE_URL = `http://127.0.0.1:${hangPort}`;
    process.env.ML_SERVICE_TIMEOUT_MS = '60'; // 60ms timeout

    const timeoutRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });

    hangServer.close();
    delete process.env.ML_SERVICE_TIMEOUT_MS;
    process.env.ML_SERVICE_URL = LIVE_ML_URL;

    if (timeoutRes.status !== 502) {
      throw new Error(`Expected 502 on ML timeout, got ${timeoutRes.status}`);
    }
    const timeoutData = await timeoutRes.json();
    if (timeoutData.error !== 'DETECTION_ENGINE_UNAVAILABLE') {
      throw new Error(`Expected error DETECTION_ENGINE_UNAVAILABLE on timeout, got ${timeoutData.error}`);
    }
    console.log('✅ PASS: ML request timeout correctly triggers bounded HTTP 502 response');

    // TEST 8: Malformed ML Response -> HTTP 502
    console.log('[Phase D — Test 8] Testing malformed ML response handling -> HTTP 502...');
    const malformedMlServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Return invalid data schema missing required risk structure
      res.end(JSON.stringify({ unexpected_data: true, risk_level: 'InvalidTierLevel' }));
    });
    await new Promise((r) => malformedMlServer.listen(0, '127.0.0.1', r));
    const malformedPort = malformedMlServer.address().port;

    process.env.ML_SERVICE_URL = `http://127.0.0.1:${malformedPort}`;
    const malformedRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify(validLoginPayload)
    });

    malformedMlServer.close();
    process.env.ML_SERVICE_URL = LIVE_ML_URL;

    if (malformedRes.status !== 502) {
      throw new Error(`Expected 502 for malformed ML response, got ${malformedRes.status}`);
    }
    const malformedData = await malformedRes.json();
    if (malformedData.error !== 'DETECTION_ENGINE_UNAVAILABLE') {
      throw new Error(`Expected DETECTION_ENGINE_UNAVAILABLE for malformed ML payload, got ${malformedData.error}`);
    }
    console.log('✅ PASS: Malformed ML response rejected with HTTP 502');

    // TEST 9: Privacy & No Credential Leakage
    console.log('[Phase D — Test 9] Testing privacy preservation and secret/password non-leakage...');
    const sensitivePayload = {
      timestamp: '2026-09-25T12:00:00Z',
      location: 'Internal VPN',
      device_id: 'laptop-work-09',
      failed_attempts: 1,
      password: 'PLAINTEXT_SUPER_SECRET_USER_PASSWORD_4321!',
      auth_token: 'BEARER_AUTH_TOKEN_SECRET_9876',
      credential: 'RAW_SESSION_CREDENTIAL_HEX_5555'
    };
    const sensitiveRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify(sensitivePayload)
    });
    if (sensitiveRes.status !== 201) throw new Error(`Expected 201, got ${sensitiveRes.status}`);
    const rawResponseText = await sensitiveRes.text();
    if (rawResponseText.includes('PLAINTEXT_SUPER_SECRET_USER_PASSWORD_4321!')) {
      throw new Error('SECURITY VIOLATION: Raw password leaked in response text!');
    }
    if (rawResponseText.includes('BEARER_AUTH_TOKEN_SECRET_9876')) {
      throw new Error('SECURITY VIOLATION: Auth token leaked in response text!');
    }
    if (rawResponseText.includes('RAW_SESSION_CREDENTIAL_HEX_5555')) {
      throw new Error('SECURITY VIOLATION: Raw credential leaked in response text!');
    }
    console.log('✅ PASS: Privacy invariant verified: raw passwords/secrets never reflected in response');

    // TEST 10: Existing Endpoints Regression Check
    console.log('[Phase D — Test 10] Testing regression of existing URL and Network endpoints...');
    // URL
    const regUrlRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({ url: 'http://sl83684.pro/loading.php?user=amazon_account_update' })
    });
    if (regUrlRes.status !== 200) throw new Error(`URL endpoint failed with status ${regUrlRes.status}`);

    // Network
    const regNetRes = await fetch(`${baseUrl}/api/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${validToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:00:00Z',
        event_type: 'network_spike',
        details: { duration: 0.05, packet_count: 500, total_bytes: 600000, source_bytes: 580000, protocol: 'tcp', destination_port: 8088 }
      })
    });
    if (regNetRes.status !== 201) throw new Error(`Network endpoint failed with status ${regNetRes.status}`);
    console.log('✅ PASS: Existing URL and Network telemetry endpoints continue functioning without regression');

    // =========================================================================
    // SECTION 4: End-to-End Performance & Latency Benchmark
    // =========================================================================
    logSection('4. End-to-End Backend -> ML -> Backend Latency Benchmark');
    console.log('[Perf] Running 50 iterations of login event analysis through Express Gateway...');
    const latencies = [];
    for (let i = 0; i < 50; i++) {
      const tStart = performance.now();
      const pRes = await fetch(`${baseUrl}/api/v1/telemetry/login-event`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${validToken}`
        },
        body: JSON.stringify({
          timestamp: new Date().toISOString(),
          location: 'HQ-DataCenter',
          device_id: `bench-sensor-${i}`,
          failed_attempts: i % 8
        })
      });
      const tEnd = performance.now();
      if (pRes.status !== 201) throw new Error(`Iteration ${i} failed with status ${pRes.status}`);
      latencies.push(tEnd - tStart);
    }

    latencies.sort((a, b) => a - b);
    const meanLatency = latencies.reduce((sum, val) => sum + val, 0) / latencies.length;
    const p95Latency = latencies[Math.floor(latencies.length * 0.95)];
    const p99Latency = latencies[Math.floor(latencies.length * 0.99)];

    console.log(`⏱ End-to-End Latency Results (50 iterations):`);
    console.log(`   Mean: ${meanLatency.toFixed(2)} ms`);
    console.log(`   P95:  ${p95Latency.toFixed(2)} ms`);
    console.log(`   P99:  ${p99Latency.toFixed(2)} ms`);

    logSection('ALL PHASE D INTEGRATION, SECURITY & REGRESSION TESTS PASSED (10/10)');
  } finally {
    if (server) {
      server.close();
      console.log('[Server] Gateway stopped.');
    }
    if (spawnedMlProcess) {
      console.log('[ML Service] Terminating spawned Python process...');
      spawnedMlProcess.kill();
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
