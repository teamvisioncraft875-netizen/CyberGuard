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
   * Request signed upload URL from gateway for direct-to-Supabase storage upload
   * POST /api/v1/media/upload-url
   */
  async getUploadUrl({ media_type, file_size_bytes, file_name }) {
    const data = await apiClient.post('/media/upload-url', {
      media_type,
      file_size_bytes,
      file_name,
    });
    return data;
  },

  /**
   * Upload raw binary directly to Supabase storage signed URL.
   * Uses native XMLHttpRequest to avoid client-side auth header leakage and provides real byte progress.
   */
  async uploadFileToSignedUrl(uploadUrl, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', uploadUrl);
      xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');

      if (xhr.upload && typeof onProgress === 'function') {
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable && event.total > 0) {
            const percent = Math.round((event.loaded / event.total) * 100);
            onProgress(percent);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(xhr.response);
        } else {
          const err = new Error(`Storage upload failed with HTTP status ${xhr.status}`);
          err.status = xhr.status;
          err.code = 'UPLOAD_FAILED';
          reject(err);
        }
      };

      xhr.onerror = () => {
        const err = new Error('Network error occurred during direct storage upload');
        err.code = 'NETWORK_ERROR';
        reject(err);
      };

      xhr.ontimeout = () => {
        const err = new Error('Storage upload request timed out');
        err.code = 'TIMEOUT';
        reject(err);
      };

      xhr.send(file);
    });
  },

  /**
   * Inspect image or audio file for synthetic deepfake artifacts
   * POST /api/v1/check/media
   */
  async checkMedia({ file_path, file_url, media_type = 'image' }) {
    const payload = { media_type };
    if (file_path) {
      payload.file_path = file_path;
    }
    if (file_url) {
      payload.file_url = file_url;
    }

    const data = await apiClient.post('/check/media', payload);
    return data;
  },

  /**
   * Inspect code, environment files, or text snippets for exposed credentials, private keys, and tokens
   * POST /api/v1/check/secret
   *
   * @param {Object} payload
   * @param {string} payload.input - Code, configuration, or text content to inspect
   * @param {string} [payload.context] - Optional file name, commit, or source context
   * @returns {Promise<{ id: string|null, risk_level: string, risk_score: number, explanation: string, detected_secrets: Array<{ secret_type: string, severity: string, location: string }>, signals: Object, recommended_actions: Array<string> }>}
   */
  async checkSecret({ input, context } = {}) {
    const payload = { input };
    if (context && typeof context === 'string' && context.trim().length > 0) {
      payload.context = context.trim();
    }
    const data = await apiClient.post('/check/secret', payload);
    return data;
  },
};

export default scanService;
