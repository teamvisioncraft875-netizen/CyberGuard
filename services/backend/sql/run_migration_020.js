const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');

async function applyMigration020() {
  try {
    const sqlPath = path.resolve(__dirname, '../sql/020_create_attack_surface_tables.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log('Applying 020_create_attack_surface_tables.sql...');
    await db.query(sql);
    console.log('Migration 020 applied successfully.');

    const res = await db.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'device_listening_ports'
      ORDER BY ordinal_position;
    `);
    console.log('device_listening_ports columns:', res.rows.map(r => `${r.column_name} (${r.data_type})`).join(', '));
  } catch (err) {
    console.error('Failed to apply migration 020:', err);
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

applyMigration020();
