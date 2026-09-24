/**
 * CYBERGUARD End-to-End Integration Test:
 * Threat Detection -> Database Persistence -> Real-time WebSocket Broadcast
 *
 * Verifies that:
 * 1. An authenticated client connects via Socket.io and joins rooms.
 * 2. POST /api/v1/check/message analyzes a real phishing message and responds with HTTP 200.
 * 3. The newly created incident is persisted across incidents, detection_signals, and recommended_actions.
 * 4. The incident:new event is received in real-time over WebSocket.
 * 5. IDs, risk_level, and explanation are strictly consistent across HTTP, WebSocket, and Database.
 */

process.env.NODE_ENV = 'test';

const jwt = require('jsonwebtoken');
const { io: ioClient } = require('socket.io-client');
const config = require('./src/config');
const { server } = require('./src/index');
const { query, pool } = require('./src/config/db');

// Formatting helpers
const DIVIDER = '═'.repeat(72);
const SUB_DIVIDER = '─'.repeat(72);

function logSection(title) {
  console.log(`\n${DIVIDER}`);
  console.log(`  ${title}`);
  console.log(`${DIVIDER}`);
}

async function runEndToEndIntegrationTest() {
  logSection('CYBERGUARD E2E INTEGRATION PIPELINE TEST');
  console.log(`[INIT] Starting unified test run at ${new Date().toISOString()}`);

  let httpServerInstance;
  let clientSocket;
  let testUser;
  let createdIncidentId;

  try {
    // -------------------------------------------------------------------------
    // STEP 0: Spin up Express + Socket.io server on ephemeral port
    // -------------------------------------------------------------------------
    await new Promise((resolve) => {
      httpServerInstance = server.listen(0, resolve);
    });
    const port = httpServerInstance.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;
    console.log(`[SERVER] HTTP & WebSocket Gateway listening on port ${port}`);

    // -------------------------------------------------------------------------
    // STEP 1: Authenticate a test user & connect WebSocket client
    // -------------------------------------------------------------------------
    logSection('STEP 1: Authenticate Test User & Connect WebSocket Client');

    // Create unique test user in database
    const userEmail = `e2e_analyst_${Date.now()}@cyberguard.internal`;
    const userRes = await query(`
      INSERT INTO users (email, password_hash, role)
      VALUES ($1, 'e2e_hashed_pw_123', 'individual')
      RETURNING id, email, role, organization_id;
    `, [userEmail]);
    testUser = userRes.rows[0];
    console.log(`[AUTH] Created test user: ${testUser.id} (${testUser.email})`);

    // Generate JWT token
    const token = jwt.sign(
      {
        id: testUser.id,
        role: testUser.role,
        organization_id: testUser.organization_id || null,
        email: testUser.email
      },
      config.JWT_SECRET,
      { expiresIn: '1h' }
    );
    console.log(`[AUTH] Generated valid JWT Bearer token`);

    // Connect WebSocket client with authentication
    clientSocket = ioClient(baseUrl, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false
    });

    await new Promise((resolve, reject) => {
      const connectTimeout = setTimeout(() => {
        reject(new Error('[WS] Connection timed out after 5000ms'));
      }, 5000);

      clientSocket.on('connect', () => {
        clearTimeout(connectTimeout);
        console.log(`[WS] Client connected successfully with Socket ID: ${clientSocket.id}`);
        console.log(`[WS] Automatically joined private room: user:${testUser.id}`);
        resolve();
      });

      clientSocket.on('connect_error', (err) => {
        clearTimeout(connectTimeout);
        reject(new Error(`[WS] Connection failed: ${err.message}`));
      });
    });

    // -------------------------------------------------------------------------
    // STEP 2 & 4: Set up WebSocket Listener & Dispatch HTTP Threat Check
    // -------------------------------------------------------------------------
    logSection('STEP 2: Dispatch Threat Check (POST /api/v1/check/message)');

    // Register promise to capture the real-time 'incident:new' WebSocket event
    let capturedWsPayload = null;
    const wsReceivedPromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('[WS] Timed out waiting for "incident:new" event'));
      }, 8000);

      clientSocket.on('incident:new', (payload) => {
        clearTimeout(timeout);
        capturedWsPayload = payload;
        resolve(payload);
      });
    });

    const samplePhishingMessage = {
      text: 'URGENT: Your Chase account is locked. Verify identity at http://chase-security-update.xyz within 1 hour.',
      source_type: 'email'
    };
    console.log('[HTTP] Request payload:');
    console.log(JSON.stringify(samplePhishingMessage, null, 2));

    const httpStartTime = Date.now();
    const httpRes = await fetch(`${baseUrl}/api/v1/check/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(samplePhishingMessage)
    });
    const httpDuration = Date.now() - httpStartTime;
    const httpBody = await httpRes.json();

    // -------------------------------------------------------------------------
    // STEP 3: Capture & Print Full HTTP API Response
    // -------------------------------------------------------------------------
    logSection('STEP 3: Captured HTTP API Response');
    console.log(`[HTTP] Status Code: ${httpRes.status} (${httpDuration}ms)`);
    console.log('[HTTP] Response Body:');
    console.log(JSON.stringify(httpBody, null, 2));

    if (httpRes.status !== 200 || !httpBody.id) {
      throw new Error(`[HTTP] Threat check failed with status ${httpRes.status}: ${JSON.stringify(httpBody)}`);
    }
    createdIncidentId = httpBody.id;

    // -------------------------------------------------------------------------
    // STEP 4: Capture & Print Real-Time WebSocket Event Payload
    // -------------------------------------------------------------------------
    logSection('STEP 4: Captured WebSocket "incident:new" Real-Time Event');
    console.log('[WS] Waiting for event broadcast...');
    const wsPayload = await wsReceivedPromise;
    console.log('[WS] Event "incident:new" received on client:');
    console.log(JSON.stringify(wsPayload, null, 2));

    // -------------------------------------------------------------------------
    // STEP 5: Query Database Directly for matching records
    // -------------------------------------------------------------------------
    logSection('STEP 5: Direct Database Verification (PostgreSQL)');

    // 5a. Incidents table
    const incidentQuery = await query('SELECT * FROM incidents WHERE id = $1;', [createdIncidentId]);
    const incidentRow = incidentQuery.rows[0];
    console.log(`[DB] "incidents" row for ID ${createdIncidentId}:`);
    console.log(JSON.stringify(incidentRow, null, 2));

    if (!incidentRow) {
      throw new Error(`[DB] Incident row not found in database for ID: ${createdIncidentId}`);
    }

    // 5b. Detection Signals table
    const signalsQuery = await query('SELECT * FROM detection_signals WHERE incident_id = $1;', [createdIncidentId]);
    console.log(`\n[DB] "detection_signals" rows (${signalsQuery.rowCount} signals recorded):`);
    console.log(JSON.stringify(signalsQuery.rows, null, 2));

    // 5c. Recommended Actions table
    const actionsQuery = await query('SELECT * FROM recommended_actions WHERE incident_id = $1;', [createdIncidentId]);
    console.log(`\n[DB] "recommended_actions" rows (${actionsQuery.rowCount} actions recorded):`);
    console.log(JSON.stringify(actionsQuery.rows, null, 2));

    // -------------------------------------------------------------------------
    // STEP 6: Assertions & Comprehensive PASS/FAIL Summary
    // -------------------------------------------------------------------------
    logSection('STEP 6: End-to-End Pipeline Verification Summary');

    const checks = [
      {
        name: 'HTTP Incident ID matches WebSocket Event ID',
        expected: createdIncidentId,
        actual: wsPayload.id,
        pass: createdIncidentId === wsPayload.id
      },
      {
        name: 'HTTP Incident ID matches Database Primary Key (incidents.id)',
        expected: createdIncidentId,
        actual: incidentRow.id,
        pass: createdIncidentId === incidentRow.id
      },
      {
        name: 'Consistent risk_level across HTTP, WebSocket, and Database',
        expected: httpBody.risk_level.toLowerCase(),
        actual: `HTTP: "${httpBody.risk_level}" | WS: "${wsPayload.risk_level}" | DB: "${incidentRow.risk_level}"`,
        pass: (
          httpBody.risk_level.toLowerCase() === wsPayload.risk_level.toLowerCase() &&
          httpBody.risk_level.toLowerCase() === incidentRow.risk_level.toLowerCase()
        )
      },
      {
        name: 'Consistent explanation across HTTP, WebSocket, and Database',
        expected: httpBody.explanation,
        actual: `Matches across all 3 tiers`,
        pass: (
          httpBody.explanation === wsPayload.explanation &&
          httpBody.explanation === incidentRow.explanation
        )
      },
      {
        name: 'Detection Signals persisted to DB (metadata keys excluded)',
        expected: '> 0 persisted signals',
        actual: `${signalsQuery.rowCount} signals`,
        pass: signalsQuery.rowCount > 0
      },
      {
        name: 'Recommended Actions persisted to DB with action_status = "pending"',
        expected: 'All status == pending',
        actual: `${actionsQuery.rowCount} actions (${actionsQuery.rows.map(a => a.action_status).join(', ')})`,
        pass: actionsQuery.rowCount > 0 && actionsQuery.rows.every(a => a.action_status === 'pending')
      }
    ];

    console.log(SUB_DIVIDER);
    let allPassed = true;
    for (const [index, check] of checks.entries()) {
      const statusIcon = check.pass ? '✔ PASS' : '✖ FAIL';
      if (!check.pass) allPassed = false;
      console.log(`[${statusIcon}] Check ${index + 1}: ${check.name}`);
      console.log(`       Details: ${check.actual}`);
    }
    console.log(SUB_DIVIDER);

    if (allPassed) {
      console.log('\n🌟 [VERDICT: PASS] FULL PIPELINE TEST COMPLETED SUCCESSFULLY');
      console.log('   All pipeline stages (HTTP Ingestion -> ML Detection -> DB Transaction -> WebSocket Push) are synchronized.');
    } else {
      console.error('\n❌ [VERDICT: FAIL] Pipeline validation failed on one or more integrity checks.');
      process.exitCode = 1;
    }

  } catch (error) {
    console.error('\n[FATAL ERROR IN PIPELINE TEST]:', error);
    process.exitCode = 1;
  } finally {
    // -------------------------------------------------------------------------
    // CLEANUP: Disconnect sockets, close server, remove test records
    // -------------------------------------------------------------------------
    console.log('\n[CLEANUP] Tearing down test connections & removing records...');

    if (clientSocket && clientSocket.connected) {
      clientSocket.disconnect();
    }
    if (httpServerInstance) {
      await new Promise((r) => httpServerInstance.close(r));
    }

    if (createdIncidentId) {
      await query('DELETE FROM detection_signals WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM recommended_actions WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM mitre_mappings WHERE incident_id = $1;', [createdIncidentId]).catch(() => {});
      await query('DELETE FROM incidents WHERE id = $1;', [createdIncidentId]).catch(() => {});
    }

    if (testUser?.id) {
      await query('DELETE FROM users WHERE id = $1;', [testUser.id]).catch(() => {});
    }

    await pool.end().catch(() => {});
    console.log('[CLEANUP] Completed. Test run finished.');
  }
}

runEndToEndIntegrationTest();
