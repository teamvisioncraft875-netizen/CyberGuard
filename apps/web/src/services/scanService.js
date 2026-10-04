import apiClient from './apiClient';

/**
 * AI Threat Scanning & Detection service for CYBERGUARD Gateway
 */
export const scanService = {
  /**
   * Inspect message text for phishing, social engineering, or fraud
   * POST /api/v1/check/message
   */
  async checkMessage({ text, source_type = 'email' }) {
    const data = await apiClient.post('/check/message', {
      text,
      source_type,
    });
    return data;
  },

  /**
   * Inspect destination URL for malicious redirects, typosquatting, or phishing
   * POST /api/v1/check/url
   */
  async checkUrl({ url }) {
    const data = await apiClient.post('/check/url', {
      url,
    });
    return data;
  },

  /**
   * Inspect image or audio file for synthetic deepfake artifacts
   * POST /api/v1/check/media
   */
  async checkMedia({ file_url, media_type = 'image' }) {
    const data = await apiClient.post('/check/media', {
      file_url,
      media_type,
    });
    return data;
  },
};

export default scanService;
