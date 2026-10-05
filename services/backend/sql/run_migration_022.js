const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');

async function applyMigration022() {
  try {
    const sqlPath = path.resolve(__dirname, '../sql/022_harden_attack_surface_phase_b.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log('Applying 022_harden_attack_surface_phase_b.sql...');
    await db.query(sql);
    console.log('Migration 022 applied successfully.');
  } catch (err) {
    console.error('Failed to apply migration 022:', err);
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

applyMigration022();
