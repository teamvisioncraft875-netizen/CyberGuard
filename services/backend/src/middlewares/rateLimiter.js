const rateLimit = require('express-rate-limit');

/**
 * Standard error handler for rate limit exceeded responses.
 * Returns HTTP 429 with consistent JSON payload.
 */
const rateLimitHandler = (req, res) => {
  res.status(429).json({
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many requests, please try again later.'
  });
};

/**
 * Auth Limiter: 5 requests per 15 minutes per IP.
 * Strict protection for authentication endpoints (login, signup) against brute-force attacks.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10000, // Relaxed for walkthrough and development testing
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => true, // Rate limiting paused for testing/walkthrough
  handler: rateLimitHandler
});

/**
 * Check Limiter: 100 requests per 15 minutes per IP.
 * Applied to threat inspection routes (/check/*) to prevent abuse of the upstream AI/ML engine.
 */
const checkLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => process.env.SKIP_RATE_LIMIT === 'true',
  handler: rateLimitHandler
});

/**
 * General Limiter: 300 requests per 15 minutes per IP.
 * Applied to all other authenticated routes (incidents, actions, guardian, analytics, telemetry).
 *
 * NOTE ON FUTURE ENHANCEMENT:
 * Rate limiting is currently keyed by IP address by default. For authenticated routes,
 * this could be upgraded in the future to key by `req.user?.id` instead of IP (via keyGenerator)
 * for more precise per-tenant/per-user quota enforcement, but IP-based limiting provides
 * robust gateway protection for current operational requirements.
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => process.env.SKIP_RATE_LIMIT === 'true',
  handler: rateLimitHandler
});

/**
 * Search Limiter: 30 requests per 15 minutes per IP.
 * Applied to user search endpoints (/users/search) for autocomplete and guardian linking.
 */
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => process.env.SKIP_RATE_LIMIT === 'true',
  handler: rateLimitHandler
});

/**
 * Secret Check Limiter: 20 requests per 15 minutes per IP.
 * Lower limit for scan-heavy secret and credential exposure scanning (/check/secret).
 */
const secretCheckLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => process.env.SKIP_RATE_LIMIT === 'true',
  handler: rateLimitHandler
});

/**
 * Agent Limiter: 100 requests per 15 minutes per device_id (or IP fallback).
 * Prevents endpoint exhaustion while allowing multiple distinct agents behind the same corporate NAT/IP.
 */
const agentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  keyGenerator: (req) => req.params.device_id || req.ip,
  validate: { keyGeneratorIpFallback: false },
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  skip: () => process.env.SKIP_RATE_LIMIT === 'true',
  handler: rateLimitHandler
});

module.exports = {
  authLimiter,
  checkLimiter,
  generalLimiter,
  searchLimiter,
  secretCheckLimiter,
  agentLimiter
};
