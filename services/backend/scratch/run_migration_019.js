const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');

async function run() {
  console.log('Applying migration 019_hardening_pipeline.sql...');
  const sql = fs.readFileSync(path.join(__dirname, '..', 'sql', '019_hardening_pipeline.sql'), 'utf8');
  try {
    await db.query(sql);
    console.log('Migration 019 applied successfully!');
  } catch (err) {
    console.error('Migration failed:', err.message);
  } finally {
    await db.pool.end();
  }
}

run();
