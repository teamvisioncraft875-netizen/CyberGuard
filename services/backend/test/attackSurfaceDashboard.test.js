'use strict';
/**
 * CYBERGUARD Phase C — Attack Surface Dashboard Test
 * Tests: Dashboard statistics accuracy, summary cards, risk distribution, category breakdown, top risky assets, tenant isolation.
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const db = require('../src/config/db');
const attackSurfaceService = require('../src/services/attackSurfaceService');
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

const TEST_PREFIX = 'asd-dash-test';
let testOrgA, testOrgB, testDevice, testPort, testExposure;

async function setup() {
  const orgA = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-a`]);
  testOrgA = orgA.rows[0];

  const orgB = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org-b`]);
  testOrgB = orgB.rows[0];

  const dev = await db.query(
    `INSERT INTO public.devices (organization_id, hostname, platform, status) VALUES ($1, $2, 'server', 'active') RETURNING *;`,
    [testOrgA.id, `${TEST_PREFIX}-db.internal`]
  );
  testDevice = dev.rows[0];

  const port = await db.query(
    `INSERT INTO public.device_listening_ports (organization_id, device_id, port, protocol, bind_address, exposure_scope, process_name, status)
     VALUES ($1, $2, 6379, 'tcp', '0.0.0.0', 'public', 'redis-server', 'open') RETURNING *;`,
    [testOrgA.id, testDevice.id]
  );
  testPort = port.rows[0];

  const exp = await db.query(
    `INSERT INTO public.attack_surface_exposures (organization_id, device_id, port_id, rule_id, severity, risk_score, title, description, remediation, status)
     VALUES ($1, $2, $3, 'EXP-CRIT-REDIS', 'critical', 95, 'Public Redis Cache', 'Exposed unauthenticated Redis cache.', 'Bind to 127.0.0.1.', 'active') RETURNING *;`,
    [testOrgA.id, testDevice.id, testPort.id]
  );
  testExposure = exp.rows[0];
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.attack_surface_exposures WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.devices WHERE organization_id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
    await db.query(`DELETE FROM public.organizations WHERE id = ANY($1);`, [[testOrgA?.id, testOrgB?.id].filter(Boolean)]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING ATTACK SURFACE DASHBOARD TESTS ---');
  try {
    await setup();

    const data = await attackSurfaceService.getDashboard({ organization_id: testOrgA.id });

    assert(typeof data.summary === 'object', 'Dashboard summary block returned');
    assert(data.summary.total_active >= 1, 'Total active exposures counted accurately');
    assert(data.summary.critical_active >= 1, 'Critical exposures counted accurately');
    assert(typeof data.risk_distribution === 'object', 'Risk distribution object present');
    assert(data.risk_distribution.critical >= 1, 'Risk distribution critical count accurate');
    assert(Array.isArray(data.category_breakdown), 'Category breakdown returned as array');
    assert(data.category_breakdown.some((c) => c.category === 'Redis Exposure'), 'Redis Exposure detected in category breakdown');
    assert(Array.isArray(data.top_risky_assets), 'Top risky assets returned as array');
    assert(data.top_risky_assets[0].hostname === `${TEST_PREFIX}-db.internal`, 'Top risky asset hostname verified');

    // Tenant Isolation Test
    const dataB = await attackSurfaceService.getDashboard({ organization_id: testOrgB.id });
    assert(dataB.summary.total_active === 0, 'Tenant isolation: Org B sees 0 active exposures');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Dashboard Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
