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
  max: 5,
  standardHeaders: true, // Return standard RateLimit-* headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  statusCode: 429,
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
  handler: rateLimitHandler
});

module.exports = {
  authLimiter,
  checkLimiter,
  generalLimiter
};
