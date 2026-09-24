const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables across common monorepo locations if not already set
if (!process.env.JWT_SECRET || !process.env.SUPABASE_DB_URL) {
  const envPaths = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(__dirname, '../../.env'),       // services/backend/.env
    path.resolve(__dirname, '../../../../.env'), // monorepo root .env
  ];

  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      dotenv.config({ path: envPath });
      if (process.env.JWT_SECRET) break;
    }
  }
}

// Enforce mandatory security secrets at app startup
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not set');
}

const config = Object.freeze({
  PORT: parseInt(process.env.PORT, 10) || 5000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET,
  SUPABASE_DB_URL: process.env.SUPABASE_DB_URL,
  ML_SERVICE_URL: process.env.ML_SERVICE_URL || 'http://localhost:8000',
});

module.exports = config;
