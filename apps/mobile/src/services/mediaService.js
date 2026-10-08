import { apiClient } from './apiClient';

export const MAX_MEDIA_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

export const SUPPORTED_EXTENSIONS = {
  image: ['jpg', 'jpeg', 'png', 'webp', 'gif'],
  audio: ['wav', 'mp3', 'ogg', 'flac', 'm4a']
};

/**
 * Media Service — Coordinates signed URL requests, direct-to-storage binary uploads,
 * and deepfake AI analysis with the CYBERGUARD backend.
 */
export const mediaService = {
  /**
   * Request a pre-signed upload URL and unique file path from the gateway.
   * Route: POST /api/v1/media/upload-url
   *
   * @param {Object} params
   * @param {'image'|'audio'} params.mediaType
   * @param {number} params.fileSizeBytes
   * @param {string} params.fileName
   * @returns {Promise<{ upload_url: string, file_path: string, expiry_seconds: number }>}
   */
  async requestUploadUrl({ mediaType, fileSizeBytes, fileName }) {
    if (!mediaType || !['image', 'audio'].includes(mediaType)) {
      throw new Error("mediaType must be either 'image' or 'audio'");
    }

    if (!fileSizeBytes || fileSizeBytes <= 0) {
      throw new Error('Valid file size is required');
    }

    if (fileSizeBytes > MAX_MEDIA_SIZE_BYTES) {
      throw new Error('File exceeds maximum allowed size limit of 50 MB');
    }

    return await apiClient.post('/media/upload-url', {
      media_type: mediaType,
      file_size_bytes: fileSizeBytes,
      file_name: fileName || `upload_${Date.now()}`
    });
  },

  /**
   * Uploads raw binary directly to the signed storage URL using XMLHttpRequest.
   * Avoids proxying large binary payloads through the API gateway.
   *
   * @param {string} uploadUrl - Signed upload target URL
   * @param {Object} fileAsset - File object or asset descriptor from picker
   * @param {Function} [onProgress] - Optional progress callback receiving percentage (0-100)
   * @returns {Promise<boolean>}
   */
  async uploadToSignedUrl(uploadUrl, fileAsset, onProgress) {
    if (!uploadUrl) throw new Error('Signed upload URL is required');
    if (!fileAsset) throw new Error('File asset is required');

    let binaryData = null;
    let mimeType = fileAsset.mimeType || 'application/octet-stream';

    // If running on Web and native File object is attached
    if (fileAsset.file) {
      binaryData = fileAsset.file;
      mimeType = fileAsset.file.type || mimeType;
    } else if (fileAsset.uri) {
      // On React Native, load local URI into blob
      try {
        binaryData = await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.onload = function () {
            resolve(xhr.response);
          };
          xhr.onerror = function () {
            reject(new Error('Failed to read selected local file'));
          };
          xhr.responseType = 'blob';
          xhr.open('GET', fileAsset.uri, true);
          xhr.send(null);
        });
      } catch (readErr) {
        throw new Error(`Unable to load local file: ${readErr.message}`);
      }
    }

    if (!binaryData) {
      throw new Error('Unable to read binary data from selected file');
    }

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', uploadUrl, true);
      xhr.setRequestHeader('Content-Type', mimeType);

      if (xhr.upload && typeof onProgress === 'function') {
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable && event.total > 0) {
            const percent = Math.round((event.loaded / event.total) * 100);
            onProgress(Math.min(100, Math.max(0, percent)));
          }
        };
      }

      xhr.onload = () => {
        // Clean up blob if applicable
        if (binaryData && typeof binaryData.close === 'function') {
          try {
            binaryData.close();
          } catch {}
        }

        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(true);
        } else {
          const err = new Error(`Storage upload failed with HTTP status ${xhr.status}`);
          err.status = xhr.status;
          reject(err);
        }
      };

      xhr.onerror = () => {
        if (binaryData && typeof binaryData.close === 'function') {
          try {
            binaryData.close();
          } catch {}
        }
        reject(new Error('Network error occurred during direct storage upload'));
      };

      xhr.ontimeout = () => {
        if (binaryData && typeof binaryData.close === 'function') {
          try {
            binaryData.close();
          } catch {}
        }
        reject(new Error('Storage upload request timed out'));
      };

      xhr.send(binaryData);
    });
  },

  /**
   * Dispatches deepfake analysis request for uploaded media file.
   * Route: POST /api/v1/check/media
   *
   * @param {Object} params
   * @param {string} params.filePath - Storage file path returned by upload URL API
   * @param {'image'|'audio'} params.mediaType - Media classification
   * @returns {Promise<Object>}
   */
  async scanMedia({ filePath, mediaType }) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('Valid storage file_path is required for media analysis');
    }
    if (!mediaType || !['image', 'audio'].includes(mediaType)) {
      throw new Error("mediaType must be 'image' or 'audio'");
    }

    return await apiClient.post('/check/media', {
      file_path: filePath,
      media_type: mediaType
    });
  }
};
