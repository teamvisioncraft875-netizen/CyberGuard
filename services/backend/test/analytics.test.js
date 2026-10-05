'use strict';
/**
 * CYBERGUARD Phase C — Analytics Test
 * Tests: Analytics aggregation, time-series generation, days clamping (max 90), and metric calculations.
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

const TEST_PREFIX = 'asd-analytics-test';
let testOrg;

async function setup() {
  const org = await db.query(`INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`, [`${TEST_PREFIX}-org`]);
  testOrg = org.rows[0];
}

async function cleanup() {
  try {
    await db.query(`DELETE FROM public.organizations WHERE id = $1;`, [testOrg?.id]);
  } catch (err) {
    console.warn('Cleanup warning:', err.message);
  }
}

(async () => {
  console.log('--- RUNNING EXPOSURE ANALYTICS TESTS ---');
  try {
    await setup();

    // 1. Fetch 7-day analytics
    const res7 = await attackSurfaceService.getAnalytics({
      organization_id: testOrg.id,
      days: 7
    });

    assert(res7.period_days === 7, 'period_days reflects request');
    assert(typeof res7.summary === 'object', 'Summary metrics block present');
    assert(typeof res7.summary.avg_risk_score === 'number', 'avg_risk_score is numeric');
    assert(Array.isArray(res7.exposure_trend), 'exposure_trend is an array');
    assert(Array.isArray(res7.incident_trend), 'incident_trend is an array');
    assert(Array.isArray(res7.mitigation_trend), 'mitigation_trend is an array');
    assert(Array.isArray(res7.category_breakdown), 'category_breakdown is an array');

    // 2. Days Clamping Test
    const resClamped = await attackSurfaceService.getAnalytics({
      organization_id: testOrg.id,
      days: 500
    });
    assert(resClamped.period_days === 90, 'Days parameter clamped to 90 days maximum');
  } catch (err) {
    console.error('Test error:', err);
    failed++;
  } finally {
    await cleanup();
    await db.end?.();
    console.log(`Analytics Test Result: ${passed} passed, ${failed} failed.\n`);
    process.exit(failed === 0 ? 0 : 1);
  }
})();
