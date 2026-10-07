/**
 * Performance Suite Runner — Executes the SIEM scale, throughput, and SLA benchmark suite
 */
const { spawn } = require('child_process');
const path = require('path');

async function runPerformanceRunner() {
  const fullPath = path.join(__dirname, '..', 'test_siem_performance.js');
  const start = Date.now();

  const child = spawn(process.execPath, [fullPath], {
    stdio: 'inherit',
    env: { ...process.env, NODE_ENV: 'test', SKIP_RATE_LIMIT: 'true' }
  });

  child.on('close', (code) => {
    const duration = ((Date.now() - start) / 1000).toFixed(2);
    if (code === 0) {
      console.log(`\n[SUCCESS] Performance Benchmark Suite passed in ${duration}s`);
      process.exit(0);
    } else {
      console.error(`\n[FAILURE] Performance Benchmark Suite failed with code ${code} in ${duration}s`);
      process.exit(1);
    }
  });
}

if (require.main === module) {
  runPerformanceRunner();
}

module.exports = { runPerformanceRunner };
