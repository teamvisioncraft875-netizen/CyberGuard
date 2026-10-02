process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';

const { app } = require('./src');
const jwt = require('jsonwebtoken');
const db = require('./src/config/db');
const User = require('./src/models/User');
const GuardianLink = require('./src/models/GuardianLink');

async function runGuardianGapsTests() {
  console.log('\n════════════════════════════════════════════════════════════════════════');
  console.log('  CYBERGUARD — GUARDIAN MODE GAP ENDPOINTS VERIFICATION SUITE');
  console.log('════════════════════════════════════════════════════════════════════════\n');

  let server;
  let baseUrl;
  const createdUserIds = [];
  const createdLinkIds = [];

  const timestamp = Date.now();
  const userAEmail = `guardian_a_${timestamp}@cyberguard.internal`;
  const userBEmail = `dependent_b_${timestamp}@cyberguard.internal`;
  const userCEmail = `unrelated_c_${timestamp}@cyberguard.internal`;

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

    // 2. Create 3 test individual users directly in DB
    const userA = await User.create({
      email: userAEmail,
      password_hash: 'dummy_hash',
      role: 'individual',
      organization_id: null
    });
    createdUserIds.push(userA.id);

    const userB = await User.create({
      email: userBEmail,
      password_hash: 'dummy_hash',
      role: 'individual',
      organization_id: null
    });
    createdUserIds.push(userB.id);

    const userC = await User.create({
      email: userCEmail,
      password_hash: 'dummy_hash',
      role: 'individual',
      organization_id: null
    });
    createdUserIds.push(userC.id);

    // 3. Generate tokens
    const tokenA = jwt.sign({ id: userA.id, email: userA.email, role: userA.role }, process.env.JWT_SECRET);
    const tokenB = jwt.sign({ id: userB.id, email: userB.email, role: userB.role }, process.env.JWT_SECRET);
    const tokenC = jwt.sign({ id: userC.id, email: userC.email, role: userC.role }, process.env.JWT_SECRET);

    let linkId;

    // ──────────────────────────────────────────────────────────────────────────
    // Step 1: User A links User B as dependent (creates pending link)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- Step 1: User A links User B as dependent (pending link) ---');
    const res1 = await fetch(`${baseUrl}/guardian/link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        guardian_user_id: userA.id,
        dependent_user_id: userB.id
      })
    });

    const data1 = await res1.json();
    if (res1.status !== 201) {
      throw new Error(`Step 1 Failed: Expected status 201, got ${res1.status}: ${JSON.stringify(data1)}`);
    }
    linkId = data1.link_id || data1.id;
    createdLinkIds.push(linkId);
    if (data1.status !== 'pending') {
      throw new Error(`Step 1 Failed: Expected status 'pending', got: ${data1.status}`);
    }
    console.log(`✔ [PASS] Step 1: User A initiated link to User B (link_id: ${linkId}, status: 'pending')`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 2: GET /guardian/links returns the pending link for both User A and User B
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 2: GET /guardian/links returns pending link for User A and User B ---');
    const res2A = await fetch(`${baseUrl}/guardian/links`, {
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    const data2A = await res2A.json();
    if (res2A.status !== 200 || !Array.isArray(data2A.links)) {
      throw new Error(`Step 2 Failed for User A: Expected 200 with links array, got ${res2A.status}`);
    }
    const foundA = data2A.links.find(l => (l.id === linkId || l.link_id === linkId));
    if (!foundA || foundA.guardian_email !== userAEmail || foundA.dependent_email !== userBEmail) {
      throw new Error(`Step 2 Failed for User A: Link not returned with emails: ${JSON.stringify(data2A)}`);
    }

    const res2B = await fetch(`${baseUrl}/guardian/links`, {
      headers: { 'Authorization': `Bearer ${tokenB}` }
    });
    const data2B = await res2B.json();
    if (res2B.status !== 200 || !Array.isArray(data2B.links)) {
      throw new Error(`Step 2 Failed for User B: Expected 200 with links array, got ${res2B.status}`);
    }
    const foundB = data2B.links.find(l => (l.id === linkId || l.link_id === linkId));
    if (!foundB || foundB.guardian_email !== userAEmail || foundB.dependent_email !== userBEmail) {
      throw new Error(`Step 2 Failed for User B: Link not returned with emails: ${JSON.stringify(data2B)}`);
    }
    console.log(`✔ [PASS] Step 2: GET /guardian/links returned pending link for both User A (guardian) and User B (dependent) with both email addresses`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 3: Search for User B by email returns their id/email
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 3: Search for User B by email (/users/search?email=...) ---');
    const res3 = await fetch(`${baseUrl}/users/search?email=${encodeURIComponent(userBEmail)}`, {
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    const data3 = await res3.json();
    if (res3.status !== 200) {
      throw new Error(`Step 3 Failed: Expected 200 from search, got ${res3.status}: ${JSON.stringify(data3)}`);
    }
    const targetFound = (data3.users && data3.users[0]) || data3.user || data3;
    if (targetFound.id !== userB.id || targetFound.email !== userBEmail) {
      throw new Error(`Step 3 Failed: Returned incorrect user data: ${JSON.stringify(data3)}`);
    }
    if (targetFound.password_hash !== undefined) {
      throw new Error(`Step 3 Failed: password_hash was leaked in search response!`);
    }
    console.log(`✔ [PASS] Step 3: Search endpoint successfully located User B (${targetFound.email}) with secure fields only`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 4: User A revokes the link (status becomes 'revoked')
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 4: User A revokes the link (/guardian/link/:id/revoke) ---');
    const res4 = await fetch(`${baseUrl}/guardian/link/${linkId}/revoke`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    const data4 = await res4.json();
    if (res4.status !== 200) {
      throw new Error(`Step 4 Failed: Expected 200 from revoke, got ${res4.status}: ${JSON.stringify(data4)}`);
    }
    if (data4.status !== 'revoked') {
      throw new Error(`Step 4 Failed: Expected status 'revoked', got: ${data4.status}`);
    }
    console.log(`✔ [PASS] Step 4: Link ${linkId} revoked successfully by User A (status: 'revoked')`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 5: Confirm GET /guardian/links no longer shows it by default (unless ?status=revoked)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 5: Confirm GET /guardian/links excludes revoked links by default ---');
    const res5Default = await fetch(`${baseUrl}/guardian/links`, {
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    const data5Default = await res5Default.json();
    const foundRevokedInDefault = data5Default.links.find(l => (l.id === linkId || l.link_id === linkId));
    if (foundRevokedInDefault) {
      throw new Error(`Step 5 Failed: Default /guardian/links still showed revoked link! ${JSON.stringify(data5Default)}`);
    }

    // Now query with ?status=revoked
    const res5Revoked = await fetch(`${baseUrl}/guardian/links?status=revoked`, {
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    const data5Revoked = await res5Revoked.json();
    const foundInRevokedFilter = data5Revoked.links.find(l => (l.id === linkId || l.link_id === linkId));
    if (!foundInRevokedFilter || foundInRevokedFilter.status !== 'revoked') {
      throw new Error(`Step 5 Failed: Query with ?status=revoked failed to return the revoked link! ${JSON.stringify(data5Revoked)}`);
    }
    console.log(`✔ [PASS] Step 5: Default /guardian/links hides revoked links; ?status=revoked explicitly returns them`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 6: User C (unrelated) tries to revoke User A/B's link -> gets 404 (scoping)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- Step 6: Unrelated User C tries to revoke User A/B link (Scoping test) ---');
    const res6 = await fetch(`${baseUrl}/guardian/link/${linkId}/revoke`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenC}` }
    });
    const data6 = await res6.json();
    if (res6.status !== 404) {
      throw new Error(`Step 6 Failed: Expected 404 for unrelated user revoke, got ${res6.status}: ${JSON.stringify(data6)}`);
    }

    const res6Links = await fetch(`${baseUrl}/guardian/links?status=all`, {
      headers: { 'Authorization': `Bearer ${tokenC}` }
    });
    const data6Links = await res6Links.json();
    const foundInC = data6Links.links.find(l => (l.id === linkId || l.link_id === linkId));
    if (foundInC) {
      throw new Error(`Step 6 Failed: User C was able to view User A/B's link!`);
    }
    console.log(`✔ [PASS] Step 6: Unrelated User C strictly isolated (received 404 on revoke attempt, 0 leaked links)`);

    console.log('\n════════════════════════════════════════════════════════════════════════');
    console.log('  ALL 6 GUARDIAN GAP TESTS PASSED 100%!');
    console.log('════════════════════════════════════════════════════════════════════════\n');

  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }

    console.log('[CLEANUP] Cleaning up test records...');
    for (const lid of createdLinkIds) {
      try {
        await db.query('DELETE FROM guardian_links WHERE id = $1', [lid]);
      } catch (_) {}
    }
    for (const uid of createdUserIds) {
      try {
        await db.query('DELETE FROM users WHERE id = $1', [uid]);
      } catch (_) {}
    }
    console.log('[CLEANUP] Complete.');
    await db.pool.end();
  }
}

runGuardianGapsTests().catch((err) => {
  console.error('\n❌ TEST SUITE FAILED:', err);
  process.exit(1);
});
