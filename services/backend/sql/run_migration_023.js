const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');

async function applyMigration023() {
  try {
    const sqlPath = path.resolve(__dirname, './023_create_threat_intelligence_tables.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log('Applying 023_create_threat_intelligence_tables.sql...');
    await db.query(sql);
    console.log('Migration 023 applied successfully.');
  } catch (err) {
    console.error('Failed to apply migration 023:', err.message);
    process.exit(1);
  } finally {
    if (db.pool) {
      await db.pool.end();
    }
    process.exit(0);
  }
}

applyMigration023();
