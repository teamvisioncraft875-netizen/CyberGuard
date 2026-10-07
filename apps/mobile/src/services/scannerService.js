import { apiClient } from './apiClient';

/**
 * Scanner Service — Dispatches URL and message analysis payloads to CyberGuard threat engines.
 * Communicates strictly via central apiClient (JWT Bearer injection + automatic token refresh).
 * Privacy: Does not permanently cache, persist, or log message/URL contents locally.
 */
export const scannerService = {
  /**
   * Dispatches URL threat detection check to POST /api/v1/check/url
   * @param {string} url - Target URL to analyze
   * @returns {Promise<{ id?: string, risk_level: string, explanation: string, recommended_actions?: string[], signals?: object, cached?: boolean }>}
   */
  async scanUrl(url) {
    if (!url || typeof url !== 'string' || !url.trim()) {
      throw new Error('Please enter a valid URL to scan');
    }

    const trimmedUrl = url.trim();
    // Normalize protocol if missing so backend receives valid http/https string
    const normalizedUrl = /^https?:\/\//i.test(trimmedUrl)
      ? trimmedUrl
      : `https://${trimmedUrl}`;

    return await apiClient.post('/check/url', { url: normalizedUrl });
  },

  /**
   * Dispatches message/phishing analysis to POST /api/v1/check/message
   * @param {string} text - Message text to inspect
   * @param {'sms'|'email'|'social'} sourceType - Channel source
   * @returns {Promise<{ id?: string, risk_level: string, explanation: string, recommended_actions?: string[], signals?: object }>}
   */
  async scanMessage(text, sourceType = 'sms') {
    if (!text || typeof text !== 'string' || !text.trim()) {
      throw new Error('Please enter message text to inspect');
    }

    const validSources = ['sms', 'email', 'social'];
    const normalizedSource = validSources.includes(sourceType?.toLowerCase())
      ? sourceType.toLowerCase()
      : 'sms';

    return await apiClient.post('/check/message', {
      text: text.trim(),
      source_type: normalizedSource
    });
  }
};
