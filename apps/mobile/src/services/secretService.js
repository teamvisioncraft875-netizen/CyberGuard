import { apiClient } from './apiClient';

/**
 * Secret Service — Coordinates credential and secret exposure scanning
 * with the CYBERGUARD backend (/api/v1/check/secret).
 *
 * PRIVACY & SECURITY PROTOCOL:
 * - Never logs or persists candidate secrets.
 * - Dispatches payload securely via HTTPS/authenticated API client.
 * - Never includes secret values in errors, analytics, or navigation params.
 * - Discards in-memory strings immediately upon request completion.
 */
export const secretService = {
  /**
   * Scans a string, config, or code snippet for exposed secrets and credentials.
   * Route: POST /api/v1/check/secret
   *
   * @param {string} input - Text content to scan for exposed secrets
   * @param {Object} [options]
   * @param {string} [options.context] - Optional scan context identifier
   * @returns {Promise<{
   *   id?: string|null,
   *   risk_level: string,
   *   risk_score: number,
   *   explanation: string,
   *   detected_secrets: Array<{ secret_type: string, severity: string, location: string }>,
   *   signals: Object,
   *   recommended_actions: Array<string>
   * }>}
   */
  async scanSecret(input, options = {}) {
    if (!input || typeof input !== 'string' || input.trim().length === 0) {
      throw new Error('Please enter or paste text to scan for exposed credentials.');
    }

    const payload = {
      input: input.trim()
    };

    if (options.context && typeof options.context === 'string') {
      payload.context = options.context.trim();
    }

    try {
      // Dispatches to POST /api/v1/check/secret
      // Notice: candidate secret string is NEVER printed to console
      const response = await apiClient.post('/check/secret', payload);
      return response;
    } catch (error) {
      if (error.status === 429) {
        throw new Error('Rate limit exceeded (20 requests per 15 minutes). Please wait before scanning again.');
      }
      if (error.status === 400) {
        throw new Error(error.message || 'Invalid secret scan payload provided.');
      }
      if (error.status === 502) {
        throw new Error('Threat inspection service temporarily unavailable. Please retry.');
      }
      throw new Error(error.message || 'Secret scan request failed. Please check connection and retry.');
    }
  }
};
