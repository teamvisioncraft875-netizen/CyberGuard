const crypto = require('crypto');
const db = require('../config/db');

const REFRESH_TOKEN_EXPIRY_DAYS = 7;

/**
 * RefreshToken Model — Manages cryptographically secure dual-token authentication tokens
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
   * and returns the unhashed token for the client.
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

    await db.query(text, [user_id, tokenHash]);
    return rawToken;
  },

  /**
   * Queries the database, confirms token exists, is_revoked = false, expires_at > now().
   * If user_id is provided, also ensures it matches.
   *
   * @param {string} tokenHash - SHA-256 hash of token to validate
   * @param {string|null} [user_id=null] - Optional user_id to restrict check
   * @returns {Promise<string|null>} user_id if valid, or null if invalid/expired
   */
  async findValid(tokenHash, user_id = null) {
    let text;
    let params;

    if (user_id) {
      text = `
        SELECT user_id
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
        SELECT user_id
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
      return null;
    }
    return res.rows[0].user_id;
  },

  /**
   * Revokes all active refresh tokens for a specific user (e.g., on logout).
   *
   * @param {string} user_id - UUID of user
   * @returns {Promise<number>} Number of tokens revoked
   */
  async revokeByUserId(user_id) {
    const text = `
      UPDATE public.refresh_tokens
      SET is_revoked = TRUE
      WHERE user_id = $1 AND is_revoked = FALSE;
    `;
    const res = await db.query(text, [user_id]);
    return res.rowCount;
  },

  /**
   * Revokes a specific token by its hash.
   *
   * @param {string} tokenHash - SHA-256 hash of token to revoke
   * @returns {Promise<boolean>} True if a token was revoked
   */
  async revokeByTokenHash(tokenHash) {
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
