/**
 * Parallel Regression Suite Runner — Executes independent test suites concurrently
 * Preserves deterministic isolation, captures per-suite outputs, and reports consolidated results.
 */
const { spawn } = require('child_process');
const path = require('path');

const PARALLEL_BATCHES = [
  // Batch 1: Core incident graph & engine suites
  [
    'test_incident_deduplication.js',
    'test_incident_correlation.js',
    'test_incident_groups.js',
    'test_attack_chain_engine.js'
  ],
  // Batch 2: SOC platform, remediation, and foundation
  [
    'test_soc_investigation_platform.js',
    'test_audit_remediation.js',
    'test_siem_foundation.js'
  ],
  // Batch 3: High-throughput correlation & live SOC streaming
  [
    'test_siem_correlation_engine.js',
    'test_siem_live_soc.js'
  ]
];

function runSuiteChild(testFile) {
  return new Promise((resolve) => {
    const fullPath = path.join(__dirname, '..', testFile);
    const start = Date.now();
    let stdoutData = '';
    let stderrData = '';

    const child = spawn(process.execPath, [fullPath], {
      env: { ...process.env, NODE_ENV: 'test', SKIP_RATE_LIMIT: 'true' }
    });

    child.stdout.on('data', (d) => { stdoutData += d.toString(); });
    child.stderr.on('data', (d) => { stderrData += d.toString(); });

    child.on('close', (code) => {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      const passed = code === 0;

      // Extract results line if present
      const match = stdoutData.match(/RESULTS:?\s*(\d+)\s*PASSED[,\s]*(\d+)\s*FAILED/i) ||
                    stdoutData.match(/TEST SUITE RESULTS:\s*(\d+)\s*PASSED\s*\|\s*(\d+)\s*FAILED/i);
      const summaryLine = match ? match[0] : (passed ? 'PASSED' : 'FAILED');

      resolve({
        file: testFile,
        passed,
        code,
        duration,
        summary: summaryLine,
        stdout: stdoutData,
        stderr: stderrData
      });
    });
  });
}

async function runParallelSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Parallel Test Suite Runner (Concurrent Process Execution)');
  console.log('========================================================================\n');

  const overallStart = Date.now();
  const allResults = [];

  for (let i = 0; i < PARALLEL_BATCHES.length; i++) {
    const batch = PARALLEL_BATCHES[i];
    console.log(`[PARALLEL BATCH ${i + 1}/${PARALLEL_BATCHES.length}] Spawning ${batch.length} concurrent suites:`);
    batch.forEach(f => console.log(`   ➜ ${f}`));

    const batchStart = Date.now();
    const batchResults = await Promise.all(batch.map(file => runSuiteChild(file)));
    const batchDuration = ((Date.now() - batchStart) / 1000).toFixed(2);

    console.log(`\n--- BATCH ${i + 1} COMPLETED in ${batchDuration}s ---`);
    for (const r of batchResults) {
      const statusIcon = r.passed ? '✅' : '❌';
      console.log(`  ${statusIcon} ${r.file.padEnd(36)} | Duration: ${r.duration}s | ${r.summary}`);
      if (!r.passed) {
        console.error(`\n[ERROR OUTPUT FOR ${r.file}]:\n${r.stderr || r.stdout.slice(-1000)}`);
      }
    }
    console.log('------------------------------------------------------------------------\n');
    allResults.push(...batchResults);
  }

  const totalDuration = ((Date.now() - overallStart) / 1000).toFixed(2);
  const totalPassed = allResults.filter(r => r.passed).length;

  console.log('========================================================================');
  console.log(`PARALLEL RUN COMPLETE: ${totalPassed}/${allResults.length} SUITES PASSED in ${totalDuration}s`);
  console.log('========================================================================');

  if (totalPassed < allResults.length) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  runParallelSuite();
}

module.exports = { runParallelSuite };
