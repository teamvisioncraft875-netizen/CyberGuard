const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const dotenv = require('dotenv');

// Load environment variables across common monorepo locations if not already set
if (!process.env.SUPABASE_DB_URL) {
  const envPaths = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(__dirname, '../../.env'),       // services/backend/.env
    path.resolve(__dirname, '../../../../.env'), // monorepo root .env
  ];

  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      dotenv.config({ path: envPath });
      if (process.env.SUPABASE_DB_URL) break;
    }
  }
}

const DEFAULT_POOL_MAX = parseInt(process.env.DB_POOL_MAX || '10', 10);
const DEFAULT_IDLE_TIMEOUT_MS = 30000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 0; // 0 disables client acquisition timeout for queueing

const connectionString = process.env.SUPABASE_DB_URL;

// Determine SSL requirement (Supabase requires SSL in remote environments)
const isLocalhost = connectionString && (connectionString.includes('localhost') || connectionString.includes('127.0.0.1'));
const sslConfig = isLocalhost || !connectionString ? false : { rejectUnauthorized: false };

const pool = new Pool({
  connectionString,
  ssl: sslConfig,
  max: DEFAULT_POOL_MAX,
  idleTimeoutMillis: DEFAULT_IDLE_TIMEOUT_MS,
  connectionTimeoutMillis: DEFAULT_CONNECTION_TIMEOUT_MS,
});

pool.on('error', (err) => {
  console.error('[CYBERGUARD DB] Unexpected idle client error:', err.message);
});

/**
 * Execute a parameterized query against PostgreSQL.
 * @param {string} text - SQL query string with $1, $2 placeholders
 * @param {Array} [params] - Query parameters
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(text, params = []) {
  if (!connectionString) {
    throw new Error('[CYBERGUARD DB] SUPABASE_DB_URL environment variable is not defined.');
  }

  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;

    if (process.env.NODE_ENV === 'development' && process.env.DEBUG_SQL === 'true') {
      console.log('[CYBERGUARD DB Query]', { text, duration: `${duration}ms`, rows: result.rowCount });
    }

    return result;
  } catch (error) {
    console.error('[CYBERGUARD DB Query Error]', {
      query: text,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Acquire a dedicated client from the pool for transactions.
 * @returns {Promise<import('pg').PoolClient>}
 */
async function getClient() {
  if (!connectionString) {
    throw new Error('[CYBERGUARD DB] SUPABASE_DB_URL environment variable is not defined.');
  }
  const client = await pool.connect();
  return client;
}

/**
 * Execute a transaction block with automatic COMMIT and ROLLBACK.
 * @param {Function} callback - Async function receiving client
 * @returns {Promise<any>}
 */
async function transaction(callback) {
  const client = await getClient();
  let txError = null;
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    txError = error;
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      // rollback error suppressed
    }
    throw error;
  } finally {
    client.release(txError ? true : undefined);
  }
}

module.exports = {
  pool,
  query,
  getClient,
  transaction,
};
