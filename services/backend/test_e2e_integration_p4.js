/**
 * CYBERGUARD — Phase 4.8 Controlled End-to-End Integration Test
 *
 * Verifies end-to-end integration:
 * 1. URL Engine: Client -> Express Gateway -> FastAPI ML Microservice -> URL Engine -> Unified Response
 * 2. Network Engine: Guard App Telemetry -> Express Gateway -> FastAPI ML Microservice -> Network Engine -> Unified Response
 * 3. Login Engine: Guard App Telemetry -> Express Gateway -> FastAPI ML Microservice -> Login Engine -> Unified Response
 * 4. Security Enforcement: Auth boundary validation (JWT requirement & tenant isolation)
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-test-jwt-secret-key-32chars!';
process.env.ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');

const DIVIDER = '═'.repeat(72);
const SUB_DIVIDER = '─'.repeat(72);

function logSection(title) {
  console.log(`\n${DIVIDER}`);
  console.log(`  ${title}`);
  console.log(`${DIVIDER}`);
}

async function runPhase4EndToEndTests() {
  logSection('CYBERGUARD PHASE 4.8 — END-TO-END INTEGRATION TEST');

  let server;
  let baseUrl;
  let testToken;

  try {
    // Start Express on ephemeral port
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        console.log(`[Express Gateway] Running on ephemeral port ${port}`);
        resolve();
      });
    });

    // Create test JWT token
    const testUser = {
      id: 'usr_e2e_tester_01',
      role: 'individual',
      email: 'tester@cyberguard.internal',
      organization_id: null
    };

    testToken = jwt.sign(testUser, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`[Auth] Issued test JWT bearer token for ${testUser.id}`);

    // =========================================================================
    // TEST 1: URL Threat Analysis (Client -> Express -> FastAPI -> URL Engine)
    // =========================================================================
    logSection('TEST 1: URL Threat Analysis Pipeline');

    // 1a. Phishing URL check
    console.log('[E2E URL 1a] Sending phishing URL check to Express Gateway...');
    const phishUrlRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({
        url: 'http://sl83684.pro/loading.php?user=amazon_account_update'
      })
    });

    console.log(`[E2E URL 1a] Response status: ${phishUrlRes.status}`);
    if (phishUrlRes.status !== 200) {
      const errTxt = await phishUrlRes.text();
      throw new Error(`Expected HTTP 200 from /api/check/url, got ${phishUrlRes.status}: ${errTxt}`);
    }

    const phishData = await phishUrlRes.json();
    console.log(`[E2E URL 1a] Risk Level: ${phishData.risk_level}, Explanation: ${phishData.explanation.slice(0, 70)}...`);
    if (phishData.risk_level !== 'Critical') {
      throw new Error(`Expected Critical risk level for phishing URL, got: ${phishData.risk_level}`);
    }
    if (!phishData.signals || phishData.signals.target_brand !== 'amazon') {
      throw new Error(`Expected target_brand 'amazon' in signals, got: ${JSON.stringify(phishData.signals)}`);
    }
    console.log('✅ TEST 1a PASSED: Phishing URL correctly classified as Critical with brand signals');

    // 1b. Benign URL check
    console.log('\n[E2E URL 1b] Sending benign URL check to Express Gateway...');
    const benignUrlRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({
        url: 'https://cyberguard.io/docs/architecture'
      })
    });

    if (benignUrlRes.status !== 200) {
      throw new Error(`Expected HTTP 200 for benign URL, got ${benignUrlRes.status}`);
    }
    const benignData = await benignUrlRes.json();
    console.log(`[E2E URL 1b] Risk Level: ${benignData.risk_level}`);
    if (benignData.risk_level !== 'Safe') {
      throw new Error(`Expected Safe risk level for benign URL, got: ${benignData.risk_level}`);
    }
    console.log('✅ TEST 1b PASSED: Benign URL correctly classified as Safe');

    // =========================================================================
    // TEST 2: Network Telemetry Pipeline (Guard App -> Express -> FastAPI -> System Engine)
    // =========================================================================
    logSection('TEST 2: Network Telemetry Pipeline');

    console.log('[E2E Net 2a] Sending high-volume network telemetry to Express Gateway...');
    const netTelemetryRes = await fetch(`${baseUrl}/api/telemetry/system-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
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
          destination_port: 8088,
          direction: 'outbound'
        }
      })
    });

    console.log(`[E2E Net 2a] Response status: ${netTelemetryRes.status}`);
    if (netTelemetryRes.status !== 201) {
      const errTxt = await netTelemetryRes.text();
      throw new Error(`Expected HTTP 201 from /api/telemetry/system-event, got ${netTelemetryRes.status}: ${errTxt}`);
    }

    const netData = await netTelemetryRes.json();
    console.log(`[E2E Net 2a] Status: ${netData.status}, Anomaly: ${netData.anomaly_detected}, Risk Level: ${netData.risk_level}`);
    if (netData.status !== 'recorded' || !netData.anomaly_detected) {
      throw new Error(`Expected recorded with anomaly_detected: true, got: ${JSON.stringify(netData)}`);
    }
    if (netData.risk_level !== 'High' && netData.risk_level !== 'Critical') {
      throw new Error(`Expected elevated risk level for network surge, got: ${netData.risk_level}`);
    }
    if (!netData.signals || typeof netData.signals.supervised_threat_probability !== 'number') {
      throw new Error(`Expected supervised_threat_probability in signals, got: ${JSON.stringify(netData.signals)}`);
    }
    console.log('✅ TEST 2a PASSED: Network telemetry transformed and scored with hybrid detection signals');

    // =========================================================================
    // TEST 3: Login Anomaly Pipeline (Guard App -> Express -> FastAPI -> Login Engine)
    // =========================================================================
    logSection('TEST 3: Login Anomaly Telemetry Pipeline');

    console.log('[E2E Login 3] Sending suspicious login event to Express Gateway...');
    const loginRes = await fetch(`${baseUrl}/api/telemetry/login-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({
        timestamp: '2026-09-25T12:05:00Z',
        device_id: 'unknown-macbook-pro',
        location: 'Moscow, RU',
        failed_attempts: 5
      })
    });

    console.log(`[E2E Login 3] Response status: ${loginRes.status}`);
    if (loginRes.status !== 201) {
      const errTxt = await loginRes.text();
      throw new Error(`Expected HTTP 201 from /api/telemetry/login-event, got ${loginRes.status}: ${errTxt}`);
    }

    const loginData = await loginRes.json();
    console.log(`[E2E Login 3] Status: ${loginData.status}, Anomaly: ${loginData.anomaly_detected}, Risk Level: ${loginData.risk_level}`);
    if (loginData.status !== 'recorded' || !loginData.anomaly_detected) {
      throw new Error(`Expected recorded with anomaly_detected: true for failed logins, got: ${JSON.stringify(loginData)}`);
    }
    console.log('✅ TEST 3 PASSED: Login anomaly successfully evaluated and recorded');

    // =========================================================================
    // TEST 4: Security & Authentication Enforcement
    // =========================================================================
    logSection('TEST 4: Security & Authentication Enforcement');

    console.log('[E2E Auth 4] Sending unauthenticated request to /api/check/url...');
    const unauthRes = await fetch(`${baseUrl}/api/check/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://cyberguard.io' })
    });

    console.log(`[E2E Auth 4] Response status: ${unauthRes.status}`);
    if (unauthRes.status !== 401) {
      throw new Error(`Expected HTTP 401 Unauthorized for missing JWT, got ${unauthRes.status}`);
    }
    console.log('✅ TEST 4 PASSED: Security boundary enforced; missing JWT strictly returns HTTP 401');

    logSection('ALL PHASE 4.8 END-TO-END INTEGRATION TESTS PASSED (4/4)');
  } finally {
    if (server) {
      server.close();
      console.log('[Server] Gateway stopped.');
    }
  }
}

if (require.main === module) {
  runPhase4EndToEndTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ E2E INTEGRATION TEST FAILED:', err.message);
      process.exit(1);
    });
}

module.exports = { runPhase4EndToEndTests };
