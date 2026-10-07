/**
 * Smoke Suite Runner — Fast verification (< 30 seconds) of critical SIEM components
 * Executes: test_siem_foundation.js, test_siem_correlation_engine.js, test_siem_live_soc.js
 */
const { spawn } = require('child_process');
const path = require('path');

const SMOKE_TESTS = [
  'test_siem_foundation.js',
  'test_siem_correlation_engine.js',
  'test_siem_live_soc.js'
];

async function runTest(testFile) {
  return new Promise((resolve) => {
    const fullPath = path.join(__dirname, '..', testFile);
    const start = Date.now();
    console.log(`\n[RUNNING SMOKE TEST] ${testFile}...`);

    const child = spawn(process.execPath, [fullPath], {
      stdio: 'inherit',
      env: { ...process.env, NODE_ENV: 'test', SKIP_RATE_LIMIT: 'true' }
    });

    child.on('close', (code) => {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      if (code === 0) {
        console.log(`[PASS] ${testFile} (${duration}s)`);
        resolve({ file: testFile, passed: true, duration });
      } else {
        console.error(`[FAIL] ${testFile} with code ${code} (${duration}s)`);
        resolve({ file: testFile, passed: false, duration });
      }
    });
  });
}

async function runSmokeSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Smoke Test Suite Runner (Target: < 30 seconds)');
  console.log('========================================================================');

  const suiteStart = Date.now();
  const results = [];

  for (const testFile of SMOKE_TESTS) {
    const res = await runTest(testFile);
    results.push(res);
  }

  const totalDuration = ((Date.now() - suiteStart) / 1000).toFixed(2);
  const allPassed = results.every(r => r.passed);

  console.log('\n========================================================================');
  console.log(`SMOKE SUITE SUMMARY: ${results.filter(r => r.passed).length}/${results.length} PASSED in ${totalDuration}s`);
  console.log('========================================================================');

  if (!allPassed) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  runSmokeSuite();
}

module.exports = { runSmokeSuite };
