const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');

async function run() {
  const sql = fs.readFileSync(path.join(__dirname, '024_threat_intel_response_policies.sql'), 'utf-8');
  console.log('Running migration 024...');
  await db.query(sql);
  console.log('Migration 024 executed successfully.');
  process.exit(0);
}

run().catch((err) => {
  console.error('Migration 024 failed:', err);
  process.exit(1);
});
