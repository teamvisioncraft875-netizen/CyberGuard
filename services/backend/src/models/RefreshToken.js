const crypto = require('crypto');
const db = require('../config/db');
const redis = require('../config/redis');

const REFRESH_TOKEN_EXPIRY_DAYS = 7;
const REFRESH_TOKEN_TTL_SECONDS = REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60; // 604,800 seconds

/**
 * RefreshToken Model — Manages cryptographically secure dual-token authentication tokens
 * with Redis 7-day fast caching and PostgreSQL persistence.
 */
const RefreshToken = {
  /**
   * Hashes a raw refresh token using SHA-256
   * @param {string} token
   * @returns {string} SHA-256 hex digest
   */
  hash(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  },

  /**
   * Generates a 32-byte random token, hashes with SHA-256, stores hash + expiry in DB,
   * caches in Redis with a 7-day TTL, and returns the unhashed token for the client.
   *
   * @param {string} user_id - UUID of the user
   * @returns {Promise<string>} Unhashed raw refresh token string
   */
  async create(user_id) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = this.hash(rawToken);

    const text = `
      INSERT INTO public.refresh_tokens (user_id, token_hash, is_revoked, created_at, expires_at)
      VALUES ($1, $2, FALSE, NOW(), NOW() + INTERVAL '${REFRESH_TOKEN_EXPIRY_DAYS} days')
      RETURNING id, user_id, expires_at;
    `;

    const res = await db.query(text, [user_id, tokenHash]);
    const record = res.rows[0];

    // Write to Redis cache: "refresh_token:<tokenHash>"
    const cacheKey = `refresh_token:${tokenHash}`;
    try {
      await redis.set(
        cacheKey,
        JSON.stringify({
          user_id: record.user_id,
          expires_at: record.expires_at
        }),
        { EX: REFRESH_TOKEN_TTL_SECONDS }
      );
    } catch (err) {
      console.warn(`[RefreshToken Cache Write Warning: ${cacheKey}]`, err.message);
    }

    return rawToken;
  },

  /**
   * Queries Redis first for the token. On cache miss or expiry, queries Postgres as fallback
   * and populates Redis. If revoked or invalid, ensures key is removed from Redis.
   *
   * @param {string} tokenHash - SHA-256 hash of token to validate
   * @param {string|null} [user_id=null] - Optional user_id to restrict check
   * @returns {Promise<string|null>} user_id if valid, or null if invalid/expired/revoked
   */
  async findValid(tokenHash, user_id = null) {
    const cacheKey = `refresh_token:${tokenHash}`;

    // 1. Check Redis first
    try {
      const cached = await redis.get(cacheKey);
      if (cached) {
        const data = JSON.parse(cached);
        const expiresAt = new Date(data.expires_at).getTime();

        if (expiresAt > Date.now()) {
          if (!user_id || String(user_id) === String(data.user_id)) {
            return data.user_id;
          }
        } else {
          // Token expired in Redis
          await redis.del(cacheKey);
        }
      }
    } catch (err) {
      console.warn(`[RefreshToken Cache Read Warning: ${cacheKey}]`, err.message);
    }

    // 2. Redis miss: Query Postgres
    let text;
    let params;

    if (user_id) {
      text = `
        SELECT user_id, expires_at
        FROM public.refresh_tokens
        WHERE token_hash = $1
          AND user_id = $2
          AND is_revoked = FALSE
          AND expires_at > NOW()
        LIMIT 1;
      `;
      params = [tokenHash, user_id];
    } else {
      text = `
        SELECT user_id, expires_at
        FROM public.refresh_tokens
        WHERE token_hash = $1
          AND is_revoked = FALSE
          AND expires_at > NOW()
        LIMIT 1;
      `;
      params = [tokenHash];
    }

    const res = await db.query(text, params);
    if (res.rows.length === 0) {
      // Postgres says invalid or revoked: keep Redis in sync
      try {
        await redis.del(cacheKey);
      } catch (delErr) {}
      return null;
    }

    const row = res.rows[0];

    // 3. Write back to Redis for future fast hits
    try {
      const remainingSeconds = Math.max(1, Math.floor((new Date(row.expires_at).getTime() - Date.now()) / 1000));
      await redis.set(
        cacheKey,
        JSON.stringify({
          user_id: row.user_id,
          expires_at: row.expires_at
        }),
        { EX: remainingSeconds }
      );
    } catch (err) {
      console.warn(`[RefreshToken Cache Backfill Warning: ${cacheKey}]`, err.message);
    }

    return row.user_id;
  },

  /**
   * Revokes all active refresh tokens for a specific user and deletes them from Redis and Postgres.
   *
   * @param {string} user_id - UUID of user
   * @returns {Promise<number>} Number of tokens revoked
   */
  async revokeByUserId(user_id) {
    // 1. Fetch active token hashes to evict from Redis
    let tokenHashes = [];
    try {
      const selectRes = await db.query(
        'SELECT token_hash FROM public.refresh_tokens WHERE user_id = $1 AND is_revoked = FALSE',
        [user_id]
      );
      tokenHashes = selectRes.rows.map(r => r.token_hash);
    } catch (err) {
      console.warn('[RefreshToken revokeByUserId fetch warning]', err.message);
    }

    // 2. Revoke in Postgres
    const text = `
      UPDATE public.refresh_tokens
      SET is_revoked = TRUE
      WHERE user_id = $1 AND is_revoked = FALSE;
    `;
    const res = await db.query(text, [user_id]);

    // 3. Delete from Redis
    for (const tokenHash of tokenHashes) {
      try {
        await redis.del(`refresh_token:${tokenHash}`);
      } catch (err) {
        console.warn(`[RefreshToken Redis Del Warning: refresh_token:${tokenHash}]`, err.message);
      }
    }

    return res.rowCount;
  },

  /**
   * Revokes a specific token by its hash and deletes it from Redis and Postgres.
   *
   * @param {string} tokenHash - SHA-256 hash of token to revoke
   * @returns {Promise<boolean>} True if a token was revoked
   */
  async revokeByTokenHash(tokenHash) {
    // 1. Evict from Redis
    try {
      await redis.del(`refresh_token:${tokenHash}`);
    } catch (err) {
      console.warn(`[RefreshToken Redis Del Warning: refresh_token:${tokenHash}]`, err.message);
    }

    // 2. Revoke in Postgres
    const text = `
      UPDATE public.refresh_tokens
      SET is_revoked = TRUE
      WHERE token_hash = $1;
    `;
    const res = await db.query(text, [tokenHash]);
    return res.rowCount > 0;
  }
};

module.exports = RefreshToken;
