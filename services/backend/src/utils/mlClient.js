const config = require('../config');

const ML_SERVICE_TIMEOUT_MS = 10000;

/**
 * Dispatches analysis requests to the FastAPI ML Microservice with timeout and error handling.
 */
async function callMlEngine(endpoint, payload) {
  const baseUrl = (process.env.ML_SERVICE_URL || config.ML_SERVICE_URL || 'http://localhost:8000').replace(/\/+$/, '');
  const url = `${baseUrl}${endpoint}`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(ML_SERVICE_TIMEOUT_MS)
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`ML Service responded with HTTP ${response.status}: ${errorBody}`);
  }

  return await response.json();
}

module.exports = {
  callMlEngine,
  ML_SERVICE_TIMEOUT_MS
};
