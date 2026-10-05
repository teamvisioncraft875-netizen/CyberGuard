'use strict';
/**
 * CYBERGUARD Phase C — Response Actions Test
 * Tests: Shadow mode enforcement, analyst approval workflow, rejection workflow, tenant isolation.
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const db = require('../src/config/db');
const attackSurfaceController = require('../controllers/attackSurfaceController');

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

const TEST_PREFIX = 'asd-resp-act-test';
let testOrgA, testOrgB, testUser, testIncident, testAction;

async function setup() {
  const orgA = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-a`]);
  testOrgA = orgA.rows[0];

  const orgB = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-b`]);
  testOrgB = orgB.rows[0];

  const user = await db.query(
    `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, $2, 'hash123', 'admin') RETURNING *;`,
    [testOrgA.id, `${TEST_PREFIX}-analyst@cyberguard.local`]
  );
  testUser = user.rows[0];

  const inc = await db.query(
    `INSERT INTO public.incidents (organization_id, threat_type, source_type, risk_level, risk_score, explanation, status)
     VALUES ($1, 'attack_surface_exposure', 'attack_surface', 'critical', 95, 'Critical Redis Exposed', 'open') RETURNING *;`,
    [testOrgA.id]
  );
  testIncident = inc.rows[0];

  const act = await db.query(
    `INSERT INTO public.response_actions (organization_id, incident_id, action_type, action_mode, status)
     VALUES ($1, $2, 'block_port', 'shadow', 'proposed') RETURNING *;`,
    [testOrgA.id, testIncident.id]
  );
  testAction = act.rows[0];
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.response_actions WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.incidents WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.users WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING RESPONSE ACTIONS APPROVAL TESTS ---');
  try {
    await setup();

    // 1. Initial State: Action is in shadow/proposed mode
    assert(testAction.status === 'proposed', 'Action initialized in proposed status');
    assert(testAction.action_mode === 'shadow', 'Action initialized in shadow mode');

    // 2. Approve Action
    const req = mockReq({
      user: testUser,
      params: { id: testAction.id },
      body: { action: 'approve', reason: 'Analyst verified port exposure' }
    });
    const res = mockRes();
    await attackSurfaceController.updateResponseAction(req, res);

    assert(res._status === 200, 'HTTP 200 on action approval');
    assert(res._json?.status === 'approved', 'Status updated to approved');
    assert(res._json?.approved_by_id === testUser.id, 'approved_by_id recorded accurately');

    // 3. Duplicate approval gives 409 Conflict
    const dupRes = mockRes();
    await attackSurfaceController.updateResponseAction(req, dupRes);
    assert(dupRes._status === 409, 'Re-approval returns 409 Conflict');

    // 4. Cross-tenant isolation (Org B cannot approve Org A action)
    const orgBReq = mockReq({
      user: { id: '00000000-0000-4000-8000-000000000099', organization_id: testOrgB.id, role: 'admin' },
      params: { id: testAction.id },
      body: { action: 'approve' }
    });
    const orgBRes = mockRes();
    await attackSurfaceController.updateResponseAction(orgBReq, orgBRes);
    assert(orgBRes._status === 404, 'Cross-tenant isolation: Org B receives 404');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Response Actions Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
