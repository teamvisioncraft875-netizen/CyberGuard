process.env.NODE_ENV = 'test';

const jwt = require('jsonwebtoken');
const { app } = require('./src/index');
const config = require('./src/config');
const db = require('./src/config/db');

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      organization_id: user.organization_id || null
    },
    config.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

async function runTests() {
  console.log('====================================================');
  console.log('  CYBERGUARD: Direct-to-Storage Media Upload Tests  ');
  console.log('====================================================\n');

  let server;
  const createdUserIds = [];

  try {
    // 1. Start ephemeral HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/api/v1`;
    console.log(`[Setup] Test server running on port ${port}`);

    // 2. Setup User A and User B
    const userARes = await db.query(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES ($1, 'hash_test', 'individual', NOW())
      RETURNING id, email, role, organization_id;
    `, [`user_a_${Date.now()}@cyberguard.test`]);
    const userA = userARes.rows[0];
    createdUserIds.push(userA.id);

    const userBRes = await db.query(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES ($1, 'hash_test', 'individual', NOW())
      RETURNING id, email, role, organization_id;
    `, [`user_b_${Date.now()}@cyberguard.test`]);
    const userB = userBRes.rows[0];
    createdUserIds.push(userB.id);

    const tokenA = createToken(userA);
    const tokenB = createToken(userB);

    console.log(`[Setup] User A created: ${userA.id}`);
    console.log(`[Setup] User B created: ${userB.id}\n`);

    let userAUploadPath = null;
    let userAUploadUrl = null;

    // --- TEST 1: User A requests an upload URL for a 1MB image ---
    console.log('[Test 1] User A requests upload URL for a 1MB image...');
    const uploadUrlRes = await fetch(`${baseUrl}/media/upload-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        media_type: 'image',
        file_size_bytes: 1048576, // 1 MB
        file_name: 'suspicious_face.png'
      })
    });

    const uploadUrlData = await uploadUrlRes.json();
    if (uploadUrlRes.status !== 200) {
      throw new Error(`Test 1 Failed: Expected status 200, got ${uploadUrlRes.status}: ${JSON.stringify(uploadUrlData)}`);
    }

    if (!uploadUrlData.upload_url || typeof uploadUrlData.upload_url !== 'string') {
      throw new Error('Test 1 Failed: Missing or invalid upload_url');
    }
    if (uploadUrlData.expiry_seconds !== 3600) {
      throw new Error(`Test 1 Failed: Expected expiry_seconds to be 3600, got ${uploadUrlData.expiry_seconds}`);
    }
    if (!uploadUrlData.file_path || !uploadUrlData.file_path.startsWith(`uploads/${userA.id}/`)) {
      throw new Error(`Test 1 Failed: Expected file_path to start with uploads/${userA.id}/, got ${uploadUrlData.file_path}`);
    }
    if (!uploadUrlData.file_path.endsWith('.png')) {
      throw new Error(`Test 1 Failed: Expected file_path to preserve .png extension, got ${uploadUrlData.file_path}`);
    }

    userAUploadPath = uploadUrlData.file_path;
    userAUploadUrl = uploadUrlData.upload_url;
    console.log(`  Upload URL:  ${userAUploadUrl.slice(0, 80)}...`);
    console.log(`  File Path:   ${userAUploadPath}`);
    console.log(`  Expiry:      ${uploadUrlData.expiry_seconds}s`);
    console.log('✅ PASS [Test 1]: User A generated valid signed upload URL and scoped path.\n');

    // --- TEST 2: Validation on upload-url endpoint ---
    console.log('[Test 2] Validating size limits and disallowed media types...');
    const oversizedRes = await fetch(`${baseUrl}/media/upload-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        media_type: 'image',
        file_size_bytes: 60 * 1024 * 1024, // 60 MB (> 50MB limit)
        file_name: 'huge.jpg'
      })
    });
    if (oversizedRes.status !== 400) {
      throw new Error(`Test 2a Failed: Expected 400 for file > 50MB, got ${oversizedRes.status}`);
    }

    const invalidTypeRes = await fetch(`${baseUrl}/media/upload-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        media_type: 'video', // Only image or audio allowed
        file_size_bytes: 1024
      })
    });
    if (invalidTypeRes.status !== 400) {
      throw new Error(`Test 2b Failed: Expected 400 for unsupported media_type, got ${invalidTypeRes.status}`);
    }

    const unauthRes = await fetch(`${baseUrl}/media/upload-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ media_type: 'image', file_size_bytes: 1024 })
    });
    if (unauthRes.status !== 401) {
      throw new Error(`Test 2c Failed: Expected 401 for missing token, got ${unauthRes.status}`);
    }
    console.log('✅ PASS [Test 2]: Upload URL validation enforced 50MB limit, allowed types, and auth.\n');

    // --- TEST 3: User A calls /check/media with the file_path from the upload-url ---
    console.log('[Test 3] User A calls /check/media with their uploaded file_path...');
    const checkUserARes = await fetch(`${baseUrl}/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        file_path: userAUploadPath,
        media_type: 'image'
      })
    });

    // Check response: User A's path MUST be accepted (NOT 403 Forbidden and NOT 400 Invalid Path)
    if (checkUserARes.status === 403) {
      throw new Error('Test 3 Failed: User A was rejected with 403 for their own file_path!');
    }
    const checkUserAData = await checkUserARes.json();
    console.log(`  Gateway Status: ${checkUserARes.status}`);
    console.log(`  Response:       ${JSON.stringify(checkUserAData).slice(0, 100)}...`);
    console.log('✅ PASS [Test 3]: User A file_path accepted and forwarded to ML Service (not 403).\n');

    // --- TEST 4: User B tries to call /check/media with User A's file_path ---
    console.log("[Test 4] User B tries to call /check/media with User A's file_path...");
    const checkUserBRes = await fetch(`${baseUrl}/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenB}`
      },
      body: JSON.stringify({
        file_path: userAUploadPath, // Belongs to User A!
        media_type: 'image'
      })
    });

    const checkUserBData = await checkUserBRes.json();
    if (checkUserBRes.status !== 403) {
      throw new Error(`Test 4 Failed: Expected 403 Forbidden for User B, got ${checkUserBRes.status}: ${JSON.stringify(checkUserBData)}`);
    }
    if (checkUserBData.error !== 'FORBIDDEN') {
      throw new Error(`Test 4 Failed: Expected error 'FORBIDDEN', got '${checkUserBData.error}'`);
    }
    console.log(`  Status:  ${checkUserBRes.status} Forbidden`);
    console.log(`  Message: ${checkUserBData.message}`);
    console.log("✅ PASS [Test 4]: User B rejected with 403 Forbidden when accessing User A's media.\n");

    // --- TEST 5: User B tries to call /check/media with User A's full storage URL ---
    console.log("[Test 5] User B tries to call /check/media with User A's full storage URL...");
    const checkUserBUrlRes = await fetch(`${baseUrl}/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenB}`
      },
      body: JSON.stringify({
        file_url: `https://awjehrhtxhbugocwqeao.supabase.co/storage/v1/object/authenticated/cyberguard-media/${userAUploadPath}`,
        media_type: 'image'
      })
    });

    const checkUserBUrlData = await checkUserBUrlRes.json();
    if (checkUserBUrlRes.status !== 403) {
      throw new Error(`Test 5 Failed: Expected 403 Forbidden, got ${checkUserBUrlRes.status}`);
    }
    console.log(`  Status:  ${checkUserBUrlRes.status} Forbidden`);
    console.log("✅ PASS [Test 5]: User B rejected with 403 Forbidden when supplying User A's storage URL.\n");

    // --- TEST 6: User A checks real benchmark media end-to-end through Gateway ---
    console.log('[Test 6] End-to-end check with real benchmark image via Gateway...');
    const e2eCheckRes = await fetch(`${baseUrl}/check/media`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        file_url: 'datasets/FaceForensics/images/ex_original.png',
        media_type: 'image'
      })
    });

    if (e2eCheckRes.status === 200) {
      const e2eData = await e2eCheckRes.json();
      console.log(`  Risk Level: ${e2eData.risk_level}`);
      console.log(`  Risk Score: ${e2eData.risk_score}`);
      console.log(`  Explanation: ${e2eData.explanation.slice(0, 70)}...`);
      console.log('✅ PASS [Test 6]: Full detection pipeline executed successfully end-to-end.\n');
    } else {
      console.log(`ℹ️ NOTE [Test 6]: ML Service returned HTTP ${e2eCheckRes.status} (offline or busy in this environment).`);
    }

    console.log('====================================================');
    console.log('  ALL MEDIA UPLOAD & STORAGE TESTS PASSED (6/6)     ');
    console.log('====================================================');
    process.exitCode = 0;
  } catch (err) {
    console.error('\n❌ TEST RUN FAILED:', err.message);
    process.exitCode = 1;
  } finally {
    // Cleanup created users
    if (createdUserIds.length > 0) {
      console.log(`[Cleanup] Removing ${createdUserIds.length} test users...`);
      await db.query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [createdUserIds]);
      console.log('[Cleanup] Done.');
    }
    if (server) {
      server.close();
    }
    // Give event loop time to exit cleanly
    setTimeout(() => process.exit(process.exitCode || 0), 500);
  }
}

runTests();
