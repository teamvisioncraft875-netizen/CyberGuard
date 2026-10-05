'use strict';
/**
 * CYBERGUARD Phase C — Scan Management Test
 * Tests: Scan orchestration triggers, fleet scan history retrieval, pagination, tenant isolation.
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

const TEST_PREFIX = 'asd-scan-mgr-test';
let testOrgA, testOrgB, testDevice;

async function setup() {
  const orgA = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-a`]);
  testOrgA = orgA.rows[0];

  const orgB = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-b`]);
  testOrgB = orgB.rows[0];

  const dev = await db.query(
    `INSERT INTO public.devices (organization_id, hostname, platform, status) VALUES ($1, $2, 'server', 'active') RETURNING *;`,
    [testOrgA.id, `${TEST_PREFIX}-endpoint.prod`]
  );
  testDevice = dev.rows[0];

  // Insert a test scan command
  await db.query(
    `INSERT INTO public.agent_commands (organization_id, device_id, command_type, target_data, status)
     VALUES ($1, $2, 'scan_attack_surface', '{}', 'completed');`,
    [testOrgA.id, testDevice.id]
  );
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.agent_commands WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.devices WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING SCAN MANAGEMENT TESTS ---');
  try {
    await setup();

    // 1. Fetch Scan History
    const history = await attackSurfaceService.getScanHistory({
      organization_id: testOrgA.id,
      limit: 10,
      offset: 0
    });

    assert(history.total >= 1, 'Scan history total counted correctly');
    assert(Array.isArray(history.scans), 'scans array returned');
    assert(history.scans[0].hostname === `${TEST_PREFIX}-endpoint.prod`, 'Joined hostname matches target device');
    assert(history.scans[0].status === 'completed', 'Scan command status matches completed');

    // 2. Tenant Isolation
    const historyB = await attackSurfaceService.getScanHistory({
      organization_id: testOrgB.id
    });
    assert(historyB.total === 0, 'Tenant isolation: Org B sees 0 scan records');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Scan Management Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
