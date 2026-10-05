'use strict';
/**
 * CYBERGUARD — Attack Surface Discovery Phase C Test Suite
 * Tests all 9 Phase C backend API endpoints and service methods.
 *
 * Requires a live Postgres connection (process.env from .env).
 * Cleans up all test resources on exit.
 *
 * Usage:
 *   cd services/backend && node test/test_attack_surface_phase_c.js
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const db = require('../src/config/db');
const attackSurfaceService = require('../src/services/attackSurfaceService');
const attackSurfaceController = require('../src/controllers/attackSurfaceController');

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, label) {
  if (condition) {
    console.log(`  [✅] ${label}`);
    passed++;
  } else {
    console.error(`  [❌] ${label}`);
    failed++;
    failures.push(label);
  }
}

/** Minimal mock Express request factory */
function mockReq({ user = {}, params = {}, query = {}, body = {} } = {}) {
  return { user, params, query, body, ip: '127.0.0.1' };
}

/** Minimal mock Express response factory */
function mockRes() {
  const res = {
    _status: 200,
    _json: null,
    status(code) { this._status = code; return this; },
    json(data) { this._json = data; return this; }
  };
  return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Data Setup
// ─────────────────────────────────────────────────────────────────────────────
const TEST_PREFIX = 'asd-phase-c-test';
let testOrg, testOrgB, testUser, testDevice, testPortRow, testExposureRow, testIncidentRow, testActionRow;

async function seedTestData() {
  // Org A
  const orgRes = await db.query(
    `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
    [`${TEST_PREFIX}-org-a`]
  );
  testOrg = orgRes.rows[0];

  // Org B (for isolation tests)
  const orgBRes = await db.query(
    `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
    [`${TEST_PREFIX}-org-b`]
  );
  testOrgB = orgBRes.rows[0];

  // Admin User in Org A (for approval & incident assignment tests)
  const userRes = await db.query(
    `INSERT INTO public.users (organization_id, email, password_hash, role)
     VALUES ($1, $2, 'hash123', 'admin') RETURNING *;`,
    [testOrg.id, `${TEST_PREFIX}-admin@cyberguard.local`]
  );
  testUser = userRes.rows[0];

  // Device in Org A
  const devRes = await db.query(
    `INSERT INTO public.devices (organization_id, hostname, platform, status)
     VALUES ($1, $2, 'server', 'active') RETURNING *;`,
    [testOrg.id, `${TEST_PREFIX}-host.local`]
  );
  testDevice = devRes.rows[0];

  // Listening port (public PostgreSQL)
  const portRes = await db.query(
    `INSERT INTO public.device_listening_ports
       (organization_id, device_id, port, protocol, bind_address, exposure_scope, process_name, status)
     VALUES ($1, $2, 5432, 'tcp', '0.0.0.0', 'public', 'postgres', 'open')
     RETURNING *;`,
    [testOrg.id, testDevice.id]
  );
  testPortRow = portRes.rows[0];

  // Exposure record
  const expRes = await db.query(
    `INSERT INTO public.attack_surface_exposures
       (organization_id, device_id, port_id, rule_id, severity, risk_score, title, description, remediation, status, first_seen_at, last_seen_at)
     VALUES ($1, $2, $3, 'EXP-CRIT-POSTGRES', 'critical', 90,
             'Public PostgreSQL Database',
             'PostgreSQL port publicly accessible.',
             'Restrict listen_addresses.',
             'active', NOW() - INTERVAL '2 days', NOW())
     RETURNING *;`,
    [testOrg.id, testDevice.id, testPortRow.id]
  );
  testExposureRow = expRes.rows[0];

  // Linked incident
  const incRes = await db.query(
    `INSERT INTO public.incidents
       (organization_id, threat_type, source_type, risk_level, risk_score, explanation, status)
     VALUES ($1, 'attack_surface_exposure', 'attack_surface', 'critical', 90,
             'Test Phase C incident', 'open')
     RETURNING *;`,
    [testOrg.id]
  );
  testIncidentRow = incRes.rows[0];

  // Link exposure to incident
  await db.query(
    `UPDATE public.attack_surface_exposures SET incident_id = $1 WHERE id = $2;`,
    [testIncidentRow.id, testExposureRow.id]
  );

  // MITRE mapping for incident
  await db.query(
    `INSERT INTO public.mitre_mappings (incident_id, technique_id, technique_name)
     VALUES ($1, 'T1190', 'Exploit Public-Facing Application');`,
    [testIncidentRow.id]
  );

  // Response action for the incident (in shadow/proposed)
  const raRes = await db.query(
    `INSERT INTO public.response_actions
       (organization_id, incident_id, action_type, action_mode, status)
     VALUES ($1, $2, 'notify_admin', 'shadow', 'proposed')
     RETURNING *;`,
    [testOrg.id, testIncidentRow.id]
  );
  testActionRow = raRes.rows[0];

  // Queue a scan command for the device
  await db.query(
    `INSERT INTO public.agent_commands
       (organization_id, device_id, command_type, target_data, status)
     VALUES ($1, $2, 'scan_attack_surface', '{}', 'pending');`,
    [testOrg.id, testDevice.id]
  );
}

async function cleanupTestData() {
  console.log('\nCleaning up Phase C test resources...');
  try {
    // Clean in dependency order
    await db.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1);`, [[testOrg?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = $1;`, [testIncidentRow?.id]);
    await db.query(`DELETE FROM public.response_actions WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.incidents WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.attack_surface_exposures WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.agent_commands WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.users WHERE organization_id = ANY($1);`, [[testOrg?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [[testOrg?.id, testOrgB?.id].filter(Boolean)]);
    console.log('Cleanup complete.');
  } catch (e) {
    console.warn('Cleanup warning:', e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

async function testDashboard() {
  console.log('\n--- TEST 1: GET DASHBOARD (SUMMARY CARDS, RISK DISTRIBUTION, TOP ASSETS) ---');

  const data = await attackSurfaceService.getDashboard({ organization_id: testOrg.id });

  assert(typeof data.summary === 'object', '1A: summary block present');
  assert(typeof data.summary.total_active === 'number', '1B: total_active is a number');
  assert(data.summary.total_active >= 1, '1C: at least 1 active exposure in org A');
  assert(data.summary.critical_active >= 1, '1D: critical_active >= 1');
  assert(typeof data.summary.open_incidents === 'number', '1E: open_incidents is a number');
  assert(typeof data.risk_distribution === 'object', '1F: risk_distribution block present');
  assert(typeof data.risk_distribution.critical === 'number', '1G: risk_distribution.critical is a number');
  assert(Array.isArray(data.category_breakdown), '1H: category_breakdown is array');
  assert(data.category_breakdown.length >= 1, '1I: category_breakdown has entries');
  assert(Array.isArray(data.top_risky_assets), '1J: top_risky_assets is array');
  assert(data.top_risky_assets.length >= 1, '1K: top_risky_assets has entries');
  assert(data.top_risky_assets[0].hostname !== undefined, '1L: top_risky_assets entries have hostname');
  assert(typeof data.top_risky_assets[0].max_risk_score === 'number', '1M: top_risky_assets[0].max_risk_score is number');

  // Controller-level test
  const req = mockReq({ user: { organization_id: testOrg.id } });
  const res = mockRes();
  await attackSurfaceController.getDashboard(req, res);
  assert(res._status === 200, '1N: HTTP 200 on GET /dashboard');
  assert(res._json?.summary !== undefined, '1O: controller returns summary object');

  // Org isolation: org B should see 0 active exposures
  const dataB = await attackSurfaceService.getDashboard({ organization_id: testOrgB.id });
  assert(dataB.summary.total_active === 0, '1P: Org B sees 0 exposures (tenant isolation)');
}

async function testExposureDetail() {
  console.log('\n--- TEST 2: GET EXPOSURE DETAIL ---');

  const data = await attackSurfaceService.getExposureById({
    organization_id: testOrg.id,
    exposure_id: testExposureRow.id
  });

  assert(data !== null, '2A: exposure found');
  assert(data.id === testExposureRow.id, '2B: correct exposure id returned');
  assert(data.hostname !== undefined, '2C: hostname present from device join');
  assert(data.port !== undefined, '2D: port present from port join');
  assert(data.protocol !== undefined, '2E: protocol present');
  assert(data.rule_id === 'EXP-CRIT-POSTGRES', '2F: correct rule_id');
  assert(data.severity === 'critical', '2G: severity is critical');
  assert(Array.isArray(data.mitre_mappings), '2H: mitre_mappings is array');
  assert(data.mitre_mappings.length >= 1, '2I: at least 1 MITRE mapping from linked incident');
  assert(data.mitre_mappings[0].technique_id === 'T1190', '2J: correct MITRE technique T1190');
  assert(data.incident !== null, '2K: linked incident summary present');
  assert(data.incident.status === 'open', '2L: linked incident is open');
  assert(data.description !== null && data.description !== undefined, '2M: description from detection rule');
  assert(data.remediation !== null && data.remediation !== undefined, '2N: remediation from detection rule');

  // Tenant isolation: Org B cannot fetch Org A exposure
  const dataB = await attackSurfaceService.getExposureById({
    organization_id: testOrgB.id,
    exposure_id: testExposureRow.id
  });
  assert(dataB === null, '2O: Org B cannot fetch Org A exposure (tenant isolation)');

  // Invalid UUID returns null (no DB error)
  const nullData = await attackSurfaceService.getExposureById({
    organization_id: testOrg.id,
    exposure_id: 'not-a-uuid'
  });
  assert(nullData === null, '2P: invalid UUID returns null gracefully');

  // Controller-level: 404 on wrong org
  const reqB = mockReq({ user: { organization_id: testOrgB.id }, params: { id: testExposureRow.id } });
  const resB = mockRes();
  await attackSurfaceController.getExposureById(reqB, resB);
  assert(resB._status === 404, '2Q: controller returns 404 for cross-tenant exposure fetch');
}

async function testAnalytics() {
  console.log('\n--- TEST 3: GET ANALYTICS (TIME-SERIES + CATEGORY PIE) ---');

  const data = await attackSurfaceService.getAnalytics({ organization_id: testOrg.id, days: 7 });

  assert(data.period_days === 7, '3A: period_days matches request');
  assert(typeof data.summary === 'object', '3B: summary block present');
  assert(typeof data.summary.total_active === 'number', '3C: total_active is number');
  assert(typeof data.summary.avg_risk_score === 'number', '3D: avg_risk_score is number');
  assert(typeof data.summary.avg_time_to_remediate_hours === 'number', '3E: avg_time_to_remediate_hours is number');
  assert(Array.isArray(data.exposure_trend), '3F: exposure_trend is array');
  assert(data.exposure_trend.length >= 1, '3G: exposure_trend has entries');
  assert(data.exposure_trend[0].date !== undefined, '3H: exposure_trend entries have date');
  assert(typeof data.exposure_trend[0].active_count === 'number', '3I: exposure_trend entries have active_count number');
  assert(Array.isArray(data.incident_trend), '3J: incident_trend is array');
  assert(Array.isArray(data.mitigation_trend), '3K: mitigation_trend is array');
  assert(Array.isArray(data.category_breakdown), '3L: category_breakdown is array');

  // Days clamp: max 90
  const dataMax = await attackSurfaceService.getAnalytics({ organization_id: testOrg.id, days: 999 });
  assert(dataMax.period_days === 90, '3M: days clamped to 90 max');

  // Controller-level
  const req = mockReq({ user: { organization_id: testOrg.id }, query: { days: '14' } });
  const res = mockRes();
  await attackSurfaceController.getAnalytics(req, res);
  assert(res._status === 200, '3N: HTTP 200 on GET /analytics');
  assert(res._json?.period_days === 14, '3O: controller returns correct period_days');
}

async function testScanHistory() {
  console.log('\n--- TEST 4: GET SCAN HISTORY (PAGINATED FLEET SCANS) ---');

  const data = await attackSurfaceService.getScanHistory({
    organization_id: testOrg.id,
    limit: 10,
    offset: 0
  });

  assert(typeof data.total === 'number', '4A: total is a number');
  assert(data.total >= 1, '4B: at least 1 scan in history');
  assert(Array.isArray(data.scans), '4C: scans is array');
  assert(data.scans.length >= 1, '4D: scans has at least 1 entry');
  assert(data.scans[0].device_id !== undefined, '4E: scan entry has device_id');
  assert(data.scans[0].hostname !== undefined, '4F: scan entry has hostname from join');
  assert(data.scans[0].status !== undefined, '4G: scan entry has status');
  assert(data.scans[0].initiated_at !== undefined, '4H: scan entry has initiated_at');

  // Limit clamp
  const dataClamped = await attackSurfaceService.getScanHistory({
    organization_id: testOrg.id,
    limit: 999
  });
  assert(dataClamped.limit <= 100, '4I: limit clamped to <= 100');

  // Org isolation
  const dataB = await attackSurfaceService.getScanHistory({ organization_id: testOrgB.id });
  assert(dataB.total === 0, '4J: Org B sees 0 scans (tenant isolation)');

  // Controller-level
  const req = mockReq({ user: { organization_id: testOrg.id }, query: {} });
  const res = mockRes();
  await attackSurfaceController.getScanHistory(req, res);
  assert(res._status === 200, '4K: HTTP 200 on GET /scans');
  assert(res._json?.scans !== undefined, '4L: controller response has scans array');
}

async function testResponseActionApproval() {
  console.log('\n--- TEST 5: RESPONSE ACTION APPROVAL WORKFLOW ---');

  // Verify action starts as proposed
  const beforeRes = await db.query(
    `SELECT status FROM public.response_actions WHERE id = $1;`,
    [testActionRow.id]
  );
  assert(beforeRes.rows[0].status === 'proposed', '5A: action starts in proposed status');

  // Mock admin user
  const adminUser = testUser;

  // Approve the action
  const approveReq = mockReq({
    user: adminUser,
    params: { id: testActionRow.id },
    body: { action: 'approve', reason: 'Validated by SOC analyst' }
  });
  const approveRes = mockRes();
  await attackSurfaceController.updateResponseAction(approveReq, approveRes);

  assert(approveRes._status === 200, '5B: HTTP 200 on approve');
  assert(approveRes._json?.status === 'approved', '5C: response action status is approved');
  assert(approveRes._json?.approved_by_id === adminUser.id, '5D: approved_by_id is analyst id');

  // Verify in DB
  const afterRes = await db.query(
    `SELECT status, approved_by_id, approved_at FROM public.response_actions WHERE id = $1;`,
    [testActionRow.id]
  );
  assert(afterRes.rows[0].status === 'approved', '5E: DB confirms status=approved');
  assert(afterRes.rows[0].approved_by_id === adminUser.id, '5F: DB confirms approved_by_id');
  assert(afterRes.rows[0].approved_at !== null, '5G: DB has approved_at timestamp');

  // Re-approving an approved action should be 409 CONFLICT
  const reApproveReq = mockReq({
    user: adminUser,
    params: { id: testActionRow.id },
    body: { action: 'approve' }
  });
  const reApproveRes = mockRes();
  await attackSurfaceController.updateResponseAction(reApproveReq, reApproveRes);
  assert(reApproveRes._status === 409, '5H: 409 Conflict on re-approval of already-approved action');

  // Org isolation: Org B cannot approve Org A action
  const orgBReq = mockReq({
    user: { id: '00000000-0000-4000-8000-000000000002', organization_id: testOrgB.id, role: 'admin' },
    params: { id: testActionRow.id },
    body: { action: 'approve' }
  });
  const orgBRes = mockRes();
  await attackSurfaceController.updateResponseAction(orgBReq, orgBRes);
  assert(orgBRes._status === 404, '5I: Org B cannot approve Org A response action (tenant isolation)');

  // Invalid action value returns 400
  const badReq = mockReq({
    user: adminUser,
    params: { id: testActionRow.id },
    body: { action: 'execute_immediately' }
  });
  const badRes = mockRes();
  await attackSurfaceController.updateResponseAction(badReq, badRes);
  assert(badRes._status === 400, '5J: invalid action value returns 400');
}

async function testIncidentWorkflow() {
  console.log('\n--- TEST 6: INCIDENT WORKFLOW (STATUS UPDATE + NOTE + ASSIGNMENT) ---');

  const adminUser = testUser;

  // Verify incident starts as open
  const before = await db.query(
    `SELECT status FROM public.incidents WHERE id = $1;`,
    [testIncidentRow.id]
  );
  assert(before.rows[0].status === 'open', '6A: incident starts as open');

  // Change status to investigating
  const investigateReq = mockReq({
    user: adminUser,
    params: { id: testIncidentRow.id },
    body: { status: 'investigating' }
  });
  const investigateRes = mockRes();
  await attackSurfaceController.updateIncident(investigateReq, investigateRes);
  assert(investigateRes._status === 200, '6B: HTTP 200 on status update to investigating');
  assert(investigateRes._json?.status === 'investigating', '6C: response confirms investigating');

  // Verify in DB
  const afterInv = await db.query(
    `SELECT status FROM public.incidents WHERE id = $1;`,
    [testIncidentRow.id]
  );
  assert(afterInv.rows[0].status === 'investigating', '6D: DB confirms status=investigating');

  // Add analyst note (note-only request, no status change)
  const noteReq = mockReq({
    user: adminUser,
    params: { id: testIncidentRow.id },
    body: { note: 'Reviewed: PostgreSQL exposed to internet. Contacting system owner.' }
  });
  const noteRes = mockRes();
  await attackSurfaceController.updateIncident(noteReq, noteRes);
  assert(noteRes._status === 200, '6E: HTTP 200 on note-only request');
  assert(noteRes._json?.updated === true, '6F: note-only returns updated:true');

  // Resolve incident
  const resolveReq = mockReq({
    user: adminUser,
    params: { id: testIncidentRow.id },
    body: { status: 'resolved' }
  });
  const resolveRes = mockRes();
  await attackSurfaceController.updateIncident(resolveReq, resolveRes);
  assert(resolveRes._status === 200, '6G: HTTP 200 on resolve');
  assert(resolveRes._json?.status === 'resolved', '6H: response confirms resolved');
  assert(resolveRes._json?.resolved_by === adminUser.id, '6I: resolved_by is analyst id');

  // Invalid status returns 400
  const badReq = mockReq({
    user: adminUser,
    params: { id: testIncidentRow.id },
    body: { status: 'deleted' }
  });
  const badRes = mockRes();
  await attackSurfaceController.updateIncident(badReq, badRes);
  assert(badRes._status === 400, '6J: invalid status value returns 400');

  // Empty body returns 400
  const emptyReq = mockReq({
    user: adminUser,
    params: { id: testIncidentRow.id },
    body: {}
  });
  const emptyRes = mockRes();
  await attackSurfaceController.updateIncident(emptyReq, emptyRes);
  assert(emptyRes._status === 400, '6K: empty body returns 400');

  // Org B cannot touch Org A incident
  const orgBReq = mockReq({
    user: { id: '00000000-0000-4000-8000-000000000002', organization_id: testOrgB.id, role: 'admin' },
    params: { id: testIncidentRow.id },
    body: { status: 'resolved' }
  });
  const orgBRes = mockRes();
  await attackSurfaceController.updateIncident(orgBReq, orgBRes);
  assert(orgBRes._status === 404, '6L: Org B cannot update Org A incident (tenant isolation)');
}

async function testRouteRegistration() {
  console.log('\n--- TEST 7: ROUTE REGISTRATION SMOKE TEST ---');

  // Verify adminRoutes loads without errors
  const adminRoutes = require('../src/routes/adminRoutes');
  assert(typeof adminRoutes === 'function', '7A: adminRoutes module loads as Express router');

  // Verify all 8 Phase C handlers are exported from controller
  const handlers = [
    'getExposures', 'getOverview', 'triggerScan',  // Phase B
    'getDashboard', 'getExposureById', 'getAnalytics',  // Phase C
    'getScanHistory', 'updateResponseAction', 'updateIncident'  // Phase C
  ];
  for (const h of handlers) {
    assert(typeof attackSurfaceController[h] === 'function', `7B: controller.${h} is a function`);
  }

  // Verify Phase C service methods are exported
  const serviceMethods = ['getDashboard', 'getExposureById', 'getAnalytics', 'getScanHistory'];
  for (const m of serviceMethods) {
    assert(typeof attackSurfaceService[m] === 'function', `7C: service.${m} is a function`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main runner
// ─────────────────────────────────────────────────────────────────────────────
(async () => {
  console.log('========================================================================');
  console.log('CYBERGUARD — Attack Surface Discovery Phase C Test Suite');
  console.log('========================================================================');

  try {
    await seedTestData();
  } catch (e) {
    console.error('[FATAL] Seed failed:', e.message);
    await db.end?.();
    process.exit(1);
  }

  try {
    await testDashboard();
    await testExposureDetail();
    await testAnalytics();
    await testScanHistory();
    await testResponseActionApproval();
    await testIncidentWorkflow();
    await testRouteRegistration();
  } catch (e) {
    console.error('[FATAL] Test runner error:', e.message, e.stack);
    failed++;
    failures.push(`FATAL: ${e.message}`);
  } finally {
    await cleanupTestData();

    console.log('\n========================================================================');
    if (failed === 0) {
      console.log(`🎉 ALL PHASE C SOC WORKFLOW CHECKS PASSED! (${passed} assertions)`);
    } else {
      console.error(`❌ ${failed} FAILURE(S), ${passed} passed.`);
      console.error('Failed assertions:');
      failures.forEach(f => console.error(`  • ${f}`));
    }
    console.log('========================================================================\n');

    await db.end?.();
    process.exit(failed === 0 ? 0 : 1);
  }
})();
