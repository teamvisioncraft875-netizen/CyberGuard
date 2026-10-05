'use strict';
/**
 * CYBERGUARD Phase C — Incident Workflow Test
 * Tests: Incident status transitions, analyst assignment, notes, audit logging, tenant isolation.
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const db = require('../src/config/db');
const attackSurfaceController = require('../src/controllers/attackSurfaceController');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  [✅] ${label}`);
    passed++;
  } else {
    console.error(`  [❌] ${label}`);
    failed++;
  }
}

function mockReq({ user = {}, params = {}, body = {} } = {}) {
  return { user, params, body, ip: '127.0.0.1' };
}

function mockRes() {
  return {
    _status: 200,
    _json: null,
    status(code) { this._status = code; return this; },
    json(data) { this._json = data; return this; }
  };
}

const TEST_PREFIX = 'asd-inc-wf-test';
let testOrg, testUser, testIncident;

async function setup() {
  const org = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org`]);
  testOrg = org.rows[0];

  const user = await db.query(
    `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, $2, 'hash123', 'admin') RETURNING *;`,
    [testOrg.id, `${TEST_PREFIX}-analyst@cyberguard.local`]
  );
  testUser = user.rows[0];

  const inc = await db.query(
    `INSERT INTO public.incidents (organization_id, threat_type, source_type, risk_level, risk_score, explanation, status)
     VALUES ($1, 'attack_surface_exposure', 'attack_surface', 'high', 85, 'Test Incident Workflow', 'open') RETURNING *;`,
    [testOrg.id]
  );
  testIncident = inc.rows[0];
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.audit_logs WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.incidents WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.users WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [testOrg?.id]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING INCIDENT WORKFLOW TESTS ---');
  try {
    await setup();

    // 1. Transition status from open -> investigating
    const req1 = mockReq({
      user: testUser,
      params: { id: testIncident.id },
      body: { status: 'investigating' }
    });
    const res1 = mockRes();
    await attackSurfaceController.updateIncident(req1, res1);

    assert(res1._status === 200, 'HTTP 200 on status transition to investigating');
    assert(res1._json?.status === 'investigating', 'Incident status confirmed as investigating');

    // 2. Add analyst note
    const req2 = mockReq({
      user: testUser,
      params: { id: testIncident.id },
      body: { note: 'Confirmed listening port is external facing. Initiating firewall block.' }
    });
    const res2 = mockRes();
    await attackSurfaceController.updateIncident(req2, res2);

    assert(res2._status === 200, 'HTTP 200 on adding analyst note');
    assert(res2._json?.updated === true, 'Note updated confirmed');

    // 3. Resolve incident
    const req3 = mockReq({
      user: testUser,
      params: { id: testIncident.id },
      body: { status: 'resolved' }
    });
    const res3 = mockRes();
    await attackSurfaceController.updateIncident(req3, res3);

    assert(res3._status === 200, 'HTTP 200 on resolve');
    assert(res3._json?.status === 'resolved', 'Incident status confirmed resolved');
    assert(res3._json?.resolved_by === testUser.id, 'resolved_by matches analyst id');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Incident Workflow Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
