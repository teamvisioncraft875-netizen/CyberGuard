const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables across common monorepo locations in layered priority
// Order: process.cwd()/.env -> services/backend/.env -> monorepo root .env
// Variables defined in higher-priority locations are preserved (override: false).
const envPaths = [
  path.resolve(process.cwd(), '.env'),
  path.resolve(__dirname, '../../.env'),       // services/backend/.env
  path.resolve(__dirname, '../../../../.env'), // monorepo root .env
];

for (const envPath of envPaths) {
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath, override: false });
  }
}

// Enforce mandatory security secrets at app startup
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not set');
}

// Derive default Supabase project URL from SUPABASE_DB_URL if not explicitly specified
let defaultSupabaseUrl = process.env.SUPABASE_URL;
if (!defaultSupabaseUrl && process.env.SUPABASE_DB_URL) {
  const match = process.env.SUPABASE_DB_URL.match(/postgres\.([a-zA-Z0-9_-]+):/);
  if (match) {
    defaultSupabaseUrl = `https://${match[1]}.supabase.co`;
  }
}

const config = Object.freeze({
  PORT: parseInt(process.env.PORT, 10) || 5000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET,
  SUPABASE_DB_URL: process.env.SUPABASE_DB_URL,
  SUPABASE_URL: defaultSupabaseUrl || 'https://awjehrhtxhbugocwqeao.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '',
  SUPABASE_STORAGE_BUCKET: process.env.SUPABASE_STORAGE_BUCKET || 'cyberguard-media',
  ML_SERVICE_URL: process.env.ML_SERVICE_URL || 'http://localhost:8000',
  REDIS_URL: process.env.REDIS_URL || null,
  BACKEND_URL: process.env.CYBERGUARD_BACKEND_URL || process.env.BACKEND_URL || 'http://localhost:5000',
  backend_url: process.env.CYBERGUARD_BACKEND_URL || process.env.BACKEND_URL || 'http://localhost:5000',
  GEMINI_MODEL: process.env.GEMINI_MODEL || 'gemini-2.0-flash',
});

module.exports = config;
