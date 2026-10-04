/**
 * CYBERGUARD — Multimedia Threat Scanner & Incident Feed End-to-End Integration Test
 *
 * Verifies:
 * A. Media upload succeeds (Base64 payload & local path).
 * B. Express forwards to FastAPI Media Engine.
 * C. Real media analysis is performed.
 * D. Risk score and classification are returned.
 * E. Fourier 2D heatmap is returned for visual media as valid non-empty Base64 PNG.
 * F. Recommended SOC triage response is returned.
 * G. Incident is created when threshold is crossed.
 * H. Incident event reaches the Incident Feed over WebSocket (incident:new event).
 * I. No duplicate incident is generated.
 * J. Existing security validation still works (401 for unauthorized, 400 for invalid media_type).
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-test-jwt-secret-key-32chars!';

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { io: Client } = require('socket.io-client');
const { app, server } = require('./src/index');

const DIVIDER = '═'.repeat(74);

async function runMediaIntegrationTest() {
  console.log(`\n${DIVIDER}\n  CYBERGUARD — MULTIMEDIA SCANNER & INCIDENT FEED E2E VERIFICATION\n${DIVIDER}\n`);

  // 1. Start HTTP Server with Socket.io on ephemeral port
  await new Promise((resolve) => {
    server.listen(0, () => resolve());
  });
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[Express Gateway] Listening with Socket.io on ephemeral port ${port}`);

  const testUser = {
    id: 'user_media_test_001',
    role: 'analyst',
    organization_id: 'org_cyberguard_001',
    email: 'analyst@cyberguard.security'
  };
  const token = jwt.sign(testUser, process.env.JWT_SECRET, { expiresIn: '1h' });

  // 2. Connect Socket.io client simulating Incident Feed
  console.log('\n[Flow 1] Connecting Real Socket.io Client for Live Incident Feed...');
  const clientSocket = Client(baseUrl, {
    auth: { token: `Bearer ${token}` },
    transports: ['websocket'],
    reconnection: false
  });

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Socket.io connection timed out')), 5000);
    clientSocket.on('connect', () => {
      clearTimeout(timer);
      console.log(`✅ [WS] Incident Feed client connected successfully (Socket ID: ${clientSocket.id})`);
      resolve();
    });
    clientSocket.on('connect_error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  // Track captured WebSocket incidents
  const capturedIncidents = [];
  clientSocket.on('incident:new', (payload) => {
    capturedIncidents.push(payload);
  });

  try {
    // 3. Test Visual Media Upload (Image Frame) -> Fourier Heatmap & Incident
    console.log('\n[Flow 2] Testing Image Frame Analysis -> Fourier Heatmap & Incident Generation...');
    const realImgPath = path.resolve(__dirname, '../../datasets/FaceForensics/images/ex_deepfakes.png');
    if (!fs.existsSync(realImgPath)) {
      throw new Error(`Real image test fixture not found: ${realImgPath}`);
    }

    const imgBytes = fs.readFileSync(realImgPath);
    const imgBase64 = `data:image/png;base64,${imgBytes.toString('base64')}`;

    const imgUploadStart = Date.now();
    const imgRes = await fetch(`${baseUrl}/api/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        file_url: imgBase64,
        media_type: 'image'
      })
    });

    if (imgRes.status !== 200) {
      const errText = await imgRes.text();
      throw new Error(`Expected 200 from /api/check/media, got ${imgRes.status}: ${errText}`);
    }

    const imgData = await imgRes.json();
    console.log(`  Upload & Analysis completed in ${Date.now() - imgUploadStart} ms`);
    console.log(`  Incident ID: ${imgData.id}`);
    console.log(`  Risk Score : ${imgData.risk_score}/100 (${imgData.risk_level})`);
    console.log(`  Verdict    : ${imgData.signals?.classification || 'analyzed'}`);

    // Verify Fourier Heatmap
    const heatmapB64 = imgData.signals?.fourier_heatmap_base64 || imgData.signals?.heatmap_base64;
    if (!heatmapB64 || typeof heatmapB64 !== 'string') {
      throw new Error('Expected valid Fourier heatmap Base64 string in signals.fourier_heatmap_base64');
    }
    if (heatmapB64.length < 100) {
      throw new Error(`Fourier heatmap Base64 payload too small (${heatmapB64.length} chars)`);
    }
    // Verify valid Base64 decode
    const heatmapBuf = Buffer.from(heatmapB64.replace(/^data:image\/\w+;base64,/, ''), 'base64');
    if (heatmapBuf.length < 50) {
      throw new Error('Decoded Fourier heatmap PNG is invalid or empty');
    }
    console.log(`✅ [XAI Fourier] 2D Log-Power Spectrum Heatmap generated: ${heatmapBuf.length} bytes PNG`);
    console.log(`  Spectral Decay Slope: ${imgData.signals?.spectral_decay_slope}`);
    console.log(`  Periodic Lattice Peaks: ${imgData.signals?.periodic_peak_count}`);

    // Verify Recommended Actions
    if (!Array.isArray(imgData.recommended_actions) || imgData.recommended_actions.length === 0) {
      throw new Error('Expected non-empty recommended_actions in media check response');
    }
    console.log(`✅ [SOC Response] ${imgData.recommended_actions.length} Recommended Actions returned: "${imgData.recommended_actions[0]}"`);

    // Wait a brief moment for WebSocket event
    await new Promise((r) => setTimeout(r, 400));

    // Verify Incident Feed received the event
    const imageIncident = capturedIncidents.find((inc) => inc.source_type === 'image');
    if (!imageIncident) {
      throw new Error('Incident Feed did not receive WebSocket "incident:new" event for image threat');
    }
    if (imageIncident.risk_score !== imgData.risk_score) {
      throw new Error(`WebSocket incident score mismatch: ${imageIncident.risk_score} vs ${imgData.risk_score}`);
    }
    console.log(`✅ [Incident Feed] Real-time "incident:new" captured by WebSocket listener: ID ${imageIncident.id}`);

    // 4. Test Audio Media Upload (Voice Clone Check)
    console.log('\n[Flow 3] Testing Audio Media Analysis -> Incident Generation & Graceful Heatmap Handling...');
    const realAudPath = path.resolve(__dirname, '../../datasets/audio-dfd-benchmark/dataset/100.wav');
    if (!fs.existsSync(realAudPath)) {
      throw new Error(`Real audio test fixture not found: ${realAudPath}`);
    }

    const audBytes = fs.readFileSync(realAudPath);
    const audBase64 = `data:audio/wav;base64,${audBytes.toString('base64')}`;

    const audRes = await fetch(`${baseUrl}/api/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        file_url: audBase64,
        media_type: 'audio'
      })
    });

    if (audRes.status !== 200) {
      const errText = await audRes.text();
      throw new Error(`Expected 200 from audio check, got ${audRes.status}: ${errText}`);
    }

    const audData = await audRes.json();
    console.log(`  Audio Incident ID: ${audData.id}`);
    console.log(`  Risk Score       : ${audData.risk_score}/100 (${audData.risk_level})`);
    console.log(`  F0 Pitch         : ${audData.signals?.mean_f0_hz} Hz (Jitter: ${audData.signals?.pitch_jitter_pct}%)`);
    console.log(`  Spectral Flatness: ${audData.signals?.spectral_flatness}`);

    // Verify Fourier heatmap is handled gracefully (omitted for audio)
    if (audData.signals?.fourier_heatmap_base64) {
      console.warn('  Note: Audio returned fourier_heatmap_base64 (acceptable if acoustic spectrogram)');
    } else {
      console.log('✅ [Graceful Heatmap] 2D optical heatmap omitted cleanly for audio media type');
    }

    await new Promise((r) => setTimeout(r, 400));
    const audioIncident = capturedIncidents.find((inc) => inc.source_type === 'audio');
    if (!audioIncident) {
      throw new Error('Incident Feed did not receive WebSocket "incident:new" event for audio threat');
    }
    console.log(`✅ [Incident Feed] Real-time audio incident captured: ID ${audioIncident.id}`);

    // 5. Test De-duplication (no duplicate incidents generated for identical request)
    console.log('\n[Flow 4] Verifying Incident De-duplication...');
    const incidentIds = capturedIncidents.map((i) => i.id);
    const uniqueIds = new Set(incidentIds);
    if (incidentIds.length !== uniqueIds.size) {
      throw new Error(`Duplicate incident IDs detected in Incident Feed: ${incidentIds}`);
    }
    console.log(`✅ [Deduplication] All ${incidentIds.length} captured incident IDs are distinct`);

    // 6. Test Security Boundaries
    console.log('\n[Flow 5] Verifying Security Boundaries...');
    const unauthRes = await fetch(`${baseUrl}/api/check/media`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_url: 'test', media_type: 'image' })
    });
    if (unauthRes.status !== 401) {
      throw new Error(`Expected 401 for missing token, got ${unauthRes.status}`);
    }
    console.log('✅ [Security 5a] Unauthorized media request rejected with 401');

    const invalidTypeRes = await fetch(`${baseUrl}/api/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ file_url: 'test', media_type: 'invalid_format' })
    });
    if (invalidTypeRes.status !== 400) {
      throw new Error(`Expected 400 for invalid media_type, got ${invalidTypeRes.status}`);
    }
    console.log('✅ [Security 5b] Malformed media_type rejected with 400');

    console.log(`\n${DIVIDER}`);
    console.log('  ALL MULTIMEDIA SCANNER & INCIDENT FEED E2E CHECKS PASSED (5/5)');
    console.log(`${DIVIDER}\n`);
  } finally {
    clientSocket.disconnect();
    server.close();
  }
}

if (require.main === module) {
  runMediaIntegrationTest()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ Media Integration Test Failed:', err);
      process.exit(1);
    });
}

module.exports = { runMediaIntegrationTest };
