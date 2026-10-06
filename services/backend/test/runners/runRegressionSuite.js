/**
 * Full Regression Suite Runner — Executes all CyberGuard verification suites
 */
const { spawn } = require('child_process');
const path = require('path');

const REGRESSION_TESTS = [
  'test_incident_deduplication.js',
  'test_incident_correlation.js',
  'test_incident_groups.js',
  'test_attack_chain_engine.js',
  'test_soc_investigation_platform.js',
  'test_audit_remediation.js',
  'test_siem_foundation.js',
  'test_siem_correlation_engine.js',
  'test_siem_live_soc.js',
  'test_threat_intelligence.js'
];

async function runTest(testFile) {
  return new Promise((resolve) => {
    const fullPath = path.join(__dirname, '..', testFile);
    const start = Date.now();
    console.log(`\n========================================================================`);
    console.log(`[EXECUTING SUITE] ${testFile}`);
    console.log(`========================================================================`);

    const child = spawn(process.execPath, [fullPath], {
      stdio: 'inherit',
      env: { ...process.env, NODE_ENV: 'test', SKIP_RATE_LIMIT: 'true' }
    });

    child.on('close', (code) => {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      if (code === 0) {
        console.log(`\n[SUCCESS] ${testFile} passed in ${duration}s`);
        resolve({ file: testFile, passed: true, duration });
      } else {
        console.error(`\n[FAILURE] ${testFile} failed with exit code ${code} in ${duration}s`);
        resolve({ file: testFile, passed: false, duration });
      }
    });
  });
}

async function runRegressionSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Full Platform Regression Test Suite Runner');
  console.log('========================================================================');

  const start = Date.now();
  const results = [];

  for (const testFile of REGRESSION_TESTS) {
    const res = await runTest(testFile);
    results.push(res);
  }

  const totalDuration = ((Date.now() - start) / 1000).toFixed(2);
  const passedCount = results.filter(r => r.passed).length;

  console.log('\n========================================================================');
  console.log(`REGRESSION SUMMARY: ${passedCount}/${results.length} SUITES PASSED in ${totalDuration}s`);
  console.log('========================================================================');

  results.forEach(r => {
    const mark = r.passed ? '✅' : '❌';
    console.log(`  ${mark} ${r.file} (${r.duration}s)`);
  });

  if (passedCount < results.length) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  runRegressionSuite();
}

module.exports = { runRegressionSuite };
