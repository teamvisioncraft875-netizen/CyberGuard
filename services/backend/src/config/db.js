const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

// PostgreSQL Connection Pool configuration
// Uses SUPABASE_DB_URL or local fallback
const connectionString = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: connectionString || 'postgresql://postgres:password@localhost:5432/cyberguard',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('[DB Pool Error]', err.message);
});

/**
 * Executes a parameterized SQL query against PostgreSQL.
 * @param {string} text - SQL query text with $1, $2 placeholders
 * @param {Array} params - Parameter array
 * @returns {Promise<Object>} Query result
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    if (process.env.DEBUG_SQL === 'true') {
      console.log('[SQL Query]', { text, duration, rows: res.rowCount });
    }
    return res;
  } catch (error) {
    console.error('[SQL Error]', { text, error: error.message });
    throw error;
  }
}

module.exports = {
  query,
  pool
};
