const { query, pool } = require('../config/db');

/**
 * Database Connectivity Test Utility
 * Verifies live connection to Supabase / PostgreSQL by executing SELECT NOW()
 */
async function testDbConnection() {
  console.log('[CYBERGUARD DB] Testing database connection...');
  try {
    const result = await query('SELECT NOW() AS current_time, current_database() AS database_name;');
    const row = result.rows[0];

    console.log('[CYBERGUARD DB] ✓ Successfully connected to PostgreSQL/Supabase:');
    console.log(`  - Database:     ${row.database_name}`);
    console.log(`  - Server Time:  ${row.current_time}`);
    return true;
  } catch (error) {
    console.error('[CYBERGUARD DB] ✗ Connection test failed:');
    console.error(`  - Error:        ${error.message}`);
    if (!process.env.SUPABASE_DB_URL) {
      console.error('  - Hint:         Ensure SUPABASE_DB_URL is set in your .env file.');
    }
    return false;
  } finally {
    await pool.end();
  }
}

// Run directly if invoked from command line
if (require.main === module) {
  testDbConnection().then((success) => {
    process.exit(success ? 0 : 1);
  });
}

module.exports = testDbConnection;
