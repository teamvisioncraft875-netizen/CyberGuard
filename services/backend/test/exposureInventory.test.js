'use strict';
/**
 * CYBERGUARD Phase C — Exposure Inventory Test
 * Tests: Filtering, search queries, pagination enforcement (up to 100 max), and detail fetching.
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const db = require('../src/config/db');
const attackSurfaceService = require('../src/services/attackSurfaceService');

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

const TEST_PREFIX = 'asd-inv-test';
let testOrg, testDevice, testPort, testExposure;

async function setup() {
  const org = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org`]);
  testOrg = org.rows[0];

  const dev = await db.query(
    `INSERT INTO public.devices (organization_id, hostname, platform, status) VALUES ($1, $2, 'workstation', 'active') RETURNING *;`,
    [testOrg.id, `${TEST_PREFIX}-host-alpha`]
  );
  testDevice = dev.rows[0];

  const port = await db.query(
    `INSERT INTO public.device_listening_ports (organization_id, device_id, port, protocol, bind_address, exposure_scope, process_name, status)
     VALUES ($1, $2, 3389, 'tcp', '0.0.0.0', 'public', 'TermService', 'open') RETURNING *;`,
    [testOrg.id, testDevice.id]
  );
  testPort = port.rows[0];

  const exp = await db.query(
    `INSERT INTO public.attack_surface_exposures (organization_id, device_id, port_id, rule_id, severity, risk_score, title, description, remediation, status)
     VALUES ($1, $2, $3, 'EXP-CRIT-RDP', 'critical', 95, 'Public RDP Gateway', 'Remote Desktop Protocol publicly exposed.', 'Enable NLA.', 'active') RETURNING *;`,
    [testOrg.id, testDevice.id, testPort.id]
  );
  testExposure = exp.rows[0];
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.attack_surface_exposures WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.devices WHERE organization_id = $1;`, [testOrg?.id]);
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [testOrg?.id]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING EXPOSURE INVENTORY TESTS ---');
  try {
    await setup();

    // 1. Search Query Test
    const searchRes = await attackSurfaceService.getExposures({
      organization_id: testOrg.id,
      search: 'TermService'
    });
    assert(searchRes.total >= 1, 'Search by process name matches finding');
    assert(searchRes.exposures[0].port === 3389, 'Finding port matches RDP 3389');

    // 2. Severity Filter Test
    const filterRes = await attackSurfaceService.getExposures({
      organization_id: testOrg.id,
      severity: 'critical'
    });
    assert(filterRes.total >= 1, 'Severity filter matches critical findings');

    // 3. Pagination Enforcement
    const pageRes = await attackSurfaceService.getExposures({
      organization_id: testOrg.id,
      limit: 999
    });
    assert(pageRes.limit <= 100, 'Pagination limit clamped to <= 100 maximum');

    // 4. Detail Fetching
    const detail = await attackSurfaceService.getExposureById({
      organization_id: testOrg.id,
      exposure_id: testExposure.id
    });
    assert(detail !== null, 'Exposure details retrieved by ID');
    assert(detail.rule_id === 'EXP-CRIT-RDP', 'Detail rule_id verified');
    assert(detail.hostname === `${TEST_PREFIX}-host-alpha`, 'Detail joined hostname verified');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Exposure Inventory Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
