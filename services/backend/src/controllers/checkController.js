/**
 * Check Controller — Handles threat detection requests for messages, URLs, and multimedia.
 * Acts as Gateway orchestrator dispatching payloads to internal FastAPI detection engines.
 */
const checkController = {
  /**
   * POST /api/v1/check/message
   */
  async checkMessage(req, res) {
    const { text, source_type } = req.body;

    // Validate request shape
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'INVALID_TEXT', message: 'Non-empty message text is required' });
    }
    const validSources = ['email', 'sms', 'social'];
    if (!source_type || !validSources.includes(source_type)) {
      return res.status(400).json({ error: 'INVALID_SOURCE_TYPE', message: "source_type must be one of: 'email', 'sms', 'social'" });
    }

    // TODO: Forward payload to FastAPI ML Service (POST /internal/analyze/message),
    // persist Incident and IncidentEvidence in PostgreSQL, and broadcast alert via WebSocket if risk_level >= Medium.

    return res.status(200).json({
      risk_level: 'High',
      explanation: 'High Risk: Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link.',
      recommended_action: 'Do not click any links. Report and delete the message immediately.'
    });
  },

  /**
   * POST /api/v1/check/url
   */
  async checkUrl(req, res) {
    const { url } = req.body;

    // Validate request shape
    if (!url || typeof url !== 'string' || !url.startsWith('http')) {
      return res.status(400).json({ error: 'INVALID_URL', message: 'A valid http/https URL string is required' });
    }

    // TODO: Forward payload to FastAPI ML Service (POST /internal/analyze/url),
    // query domain reputation cache, persist Incident in PostgreSQL, and broadcast if critical.

    return res.status(200).json({
      risk_level: 'Critical',
      explanation: 'Critical Risk: Domain registered 2 days ago mimics PayPal brand name and is flagged on active phishing blacklists.',
      recommended_action: 'Block domain network-wide and revoke any credentials entered on this site.'
    });
  },

  /**
   * POST /api/v1/check/media
   */
  async checkMedia(req, res) {
    const { file_url, media_type } = req.body;

    // Validate request shape
    if (!file_url || typeof file_url !== 'string') {
      return res.status(400).json({ error: 'INVALID_FILE_URL', message: 'A valid file_url string is required' });
    }
    const validMediaTypes = ['image', 'audio'];
    if (!media_type || !validMediaTypes.includes(media_type)) {
      return res.status(400).json({ error: 'INVALID_MEDIA_TYPE', message: "media_type must be 'image' or 'audio'" });
    }

    // TODO: Forward to FastAPI ML Service (POST /internal/analyze/media),
    // invoke Vision Transformer (ViT) or ASVspoof audio detector, store IncidentEvidence, and persist Incident.

    return res.status(200).json({
      risk_level: 'High',
      explanation: 'High Risk: Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative voice models.',
      recommended_action: 'Verify speaker identity via a secondary known channel before taking financial or sensitive action.',
      confidence_score: 0.89
    });
  }
};

module.exports = checkController;
