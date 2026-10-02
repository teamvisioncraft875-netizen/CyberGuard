const { generateSignedUploadUrl } = require('../config/storage');

/**
 * Media Controller — Handles signed upload URL generation and media storage orchestration
 * for deepfake detection workflows.
 */
const mediaController = {
  /**
   * POST /api/v1/media/upload-url
   *
   * Request body:
   * {
   *   "media_type": "image" | "audio",
   *   "file_size_bytes": 1048576,
   *   "file_name": "portrait.png"
   * }
   *
   * Response:
   * {
   *   "upload_url": "https://...",
   *   "file_path": "uploads/<user_id>/<timestamp>_<random_id>.<ext>",
   *   "expiry_seconds": 3600
   * }
   */
  async getUploadUrl(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required to generate upload URL'
      });
    }

    const { media_type, file_size_bytes, file_name } = req.body;

    // Validate media_type
    if (!media_type || !['image', 'audio'].includes(media_type)) {
      return res.status(400).json({
        error: 'INVALID_MEDIA_TYPE',
        message: "media_type must be 'image' or 'audio'"
      });
    }

    // Validate file_size_bytes
    const size = Number(file_size_bytes);
    if (file_size_bytes === undefined || isNaN(size) || size <= 0) {
      return res.status(400).json({
        error: 'INVALID_FILE_SIZE',
        message: 'A valid positive file_size_bytes number is required'
      });
    }

    if (size > 50 * 1024 * 1024) {
      return res.status(400).json({
        error: 'FILE_TOO_LARGE',
        message: 'file_size_bytes exceeds maximum allowed limit of 50MB (52,428,800 bytes)'
      });
    }

    try {
      const result = await generateSignedUploadUrl({
        userId: req.user.id,
        mediaType: media_type,
        fileSizeBytes: size,
        fileName: file_name,
        expiresIn: 3600
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[mediaController.getUploadUrl Error]', err.message);
      return res.status(500).json({
        error: 'STORAGE_ERROR',
        message: 'Failed to generate signed upload URL'
      });
    }
  }
};

module.exports = mediaController;
