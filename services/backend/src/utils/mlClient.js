const config = require('../config');
const redis = require('../config/redis');

const DEFAULT_TIMEOUT_MS = 10000;
const EXTERNAL_API_CACHE_TTL = 86400; // 24 hours in seconds

/**
 * Generic cached wrapper for external threat intelligence services.
 * Key format: "api_cache:<service>:<identifier>" (e.g., "api_cache:vt:example.com")
 * TTL: 24 hours (86400 seconds)
 *
 * @param {string} service - 'vt' | 'safebrowsing' | 'abuseipdb'
 * @param {string} identifier - URL, domain, or IP address
 * @param {Function} fetcherFn - Async function executing the live call on cache miss
 * @param {number} [ttlSeconds=86400] - TTL in seconds
 * @returns {Promise<any>}
 */
async function callCachedExternalApi(service, identifier, fetcherFn, ttlSeconds = EXTERNAL_API_CACHE_TTL) {
  const cacheKey = `api_cache:${service}:${identifier}`;

  // 1. Check Redis Cache
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        parsed._cached = true;
        parsed._cache_key = cacheKey;
        return parsed;
      } catch (parseErr) {
        return cached;
      }
    }
  } catch (err) {
    console.warn(`[mlClient Cache Read Error: ${cacheKey}]`, err.message);
  }

  // 2. Cache miss or Redis down: Execute real call
  const result = await fetcherFn();

  // 3. Store result in Redis with 24-hour TTL
  try {
    const serialized = typeof result === 'object' ? JSON.stringify(result) : String(result);
    await redis.set(cacheKey, serialized, { EX: ttlSeconds });
  } catch (err) {
    console.warn(`[mlClient Cache Write Error: ${cacheKey}]`, err.message);
  }

  return result;
}

/**
 * Dedicated helper for VirusTotal lookups with 24-hour Redis cache
 */
async function callVirusTotal(identifier, fetcherFn) {
  return await callCachedExternalApi('vt', identifier, fetcherFn);
}

/**
 * Dedicated helper for Google Safe Browsing lookups with 24-hour Redis cache
 */
async function callSafeBrowsing(identifier, fetcherFn) {
  return await callCachedExternalApi('safebrowsing', identifier, fetcherFn);
}

/**
 * Dedicated helper for AbuseIPDB lookups with 24-hour Redis cache
 */
async function callAbuseIpDb(identifier, fetcherFn) {
  return await callCachedExternalApi('abuseipdb', identifier, fetcherFn);
}

/**
 * Internal raw dispatcher to the FastAPI ML Microservice
 */
async function _dispatchMlEngine(endpoint, payload) {
  const baseUrl = (process.env.ML_SERVICE_URL || config.ML_SERVICE_URL || 'http://localhost:8000').replace(/\/+$/, '');
  const url = `${baseUrl}${endpoint}`;
  const timeoutMs = process.env.ML_SERVICE_TIMEOUT_MS ? parseInt(process.env.ML_SERVICE_TIMEOUT_MS, 10) : DEFAULT_TIMEOUT_MS;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`ML Service responded with HTTP ${response.status}: ${errorBody}`);
  }

  return await response.json();
}

/**
 * Dispatches analysis requests to the FastAPI ML Microservice with timeout, caching, and error handling.
 * Automatically wraps URL / domain threat checks in the 24-hour VirusTotal Redis cache.
 */
async function callMlEngine(endpoint, payload) {
  // If analyzing a URL, cache the external threat scan under 'api_cache:vt:<url>'
  if (endpoint === '/internal/analyze/url' && payload?.url) {
    return await callVirusTotal(payload.url, () => _dispatchMlEngine(endpoint, payload));
  }

  return await _dispatchMlEngine(endpoint, payload);
}

module.exports = {
  callMlEngine,
  callCachedExternalApi,
  callVirusTotal,
  callSafeBrowsing,
  callAbuseIpDb,
  EXTERNAL_API_CACHE_TTL,
  ML_SERVICE_TIMEOUT_MS: DEFAULT_TIMEOUT_MS
};
