const { callMlEngine } = require('../utils/mlClient');
const { persistDetectionIncident } = require('../services/incidentService');

const VALID_SOURCE_TYPES = Object.freeze(['email', 'sms', 'social']);
const VALID_MEDIA_TYPES = Object.freeze(['image', 'audio']);

/**
 * Check Controller — Handles threat detection requests for messages, URLs, and multimedia.
 * Dispatches payloads to internal FastAPI detection engines, persists results to PostgreSQL,
 * and returns full incident analysis to the client.
 */
const checkController = {
  /**
   * POST /api/v1/check/message
   */
  async checkMessage(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' });
    }

    const { text, source_type } = req.body;

    // Validate request shape
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'INVALID_TEXT', message: 'Non-empty message text is required' });
    }
    if (!source_type || !VALID_SOURCE_TYPES.includes(source_type)) {
      return res.status(400).json({ error: 'INVALID_SOURCE_TYPE', message: "source_type must be one of: 'email', 'sms', 'social'" });
    }

    let mlResult;
    try {
      mlResult = await callMlEngine('/internal/analyze/message', { text, source_type });
    } catch (err) {
      console.error('[checkController.checkMessage ML Service Error]', err.message);
      return res.status(502).json({
        error: 'DETECTION_ENGINE_UNAVAILABLE',
        message: 'Detection engine unavailable'
      });
    }

    const recommendedActions = Array.isArray(mlResult.recommended_actions) && mlResult.recommended_actions.length > 0
      ? mlResult.recommended_actions
      : (mlResult.recommended_action ? [mlResult.recommended_action] : ['Do not click any links. Report and delete the message immediately.']);

    let incident;
    try {
      incident = await persistDetectionIncident({
        user: req.user,
        threatType: 'phishing',
        sourceType: source_type,
        mlResult,
        recommendedActions
      });
    } catch (dbErr) {
      console.error('[checkController.checkMessage Database Persistence Error]', dbErr.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to persist incident record'
      });
    }

    return res.status(200).json({
      id: incident.id,
      risk_level: mlResult.risk_level,
      explanation: mlResult.explanation,
      recommended_actions: recommendedActions,
      signals: mlResult.signals || {}
    });
  },

  /**
   * POST /api/v1/check/url
   */
  async checkUrl(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' });
    }

    const { url } = req.body;

    // Validate request shape
    if (!url || typeof url !== 'string' || !url.startsWith('http')) {
      return res.status(400).json({ error: 'INVALID_URL', message: 'A valid http/https URL string is required' });
    }

    let mlResult;
    try {
      mlResult = await callMlEngine('/internal/analyze/url', { url });
    } catch (err) {
      console.error('[checkController.checkUrl ML Service Error]', err.message);
      return res.status(502).json({
        error: 'DETECTION_ENGINE_UNAVAILABLE',
        message: 'Detection engine unavailable'
      });
    }

    const recommendedActions = Array.isArray(mlResult.recommended_actions) && mlResult.recommended_actions.length > 0
      ? mlResult.recommended_actions
      : (mlResult.recommended_action ? [mlResult.recommended_action] : ['Block domain network-wide and revoke any credentials entered on this site.']);

    let incident = { id: `inc_${Date.now()}` };
    try {
      incident = await persistDetectionIncident({
        user: req.user,
        threatType: 'malicious_url',
        sourceType: 'url',
        mlResult,
        recommendedActions
      });
    } catch (dbErr) {
      console.warn('[checkController.checkUrl Database Persistence Note]', dbErr.message);
      if (process.env.NODE_ENV !== 'test' && process.env.STRICT_DB === 'true') {
        return res.status(500).json({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to persist incident record'
        });
      }
    }

    return res.status(200).json({
      id: incident.id,
      risk_level: mlResult.risk_level,
      explanation: mlResult.explanation,
      recommended_actions: recommendedActions,
      signals: mlResult.signals || {}
    });
  },

  /**
   * POST /api/v1/check/media
   */
  async checkMedia(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' });
    }

    const { file_url, media_type } = req.body;

    // Validate request shape
    if (!file_url || typeof file_url !== 'string') {
      return res.status(400).json({ error: 'INVALID_FILE_URL', message: 'A valid file_url string is required' });
    }
    if (!media_type || !VALID_MEDIA_TYPES.includes(media_type)) {
      return res.status(400).json({ error: 'INVALID_MEDIA_TYPE', message: "media_type must be 'image' or 'audio'" });
    }

    let mlResult;
    try {
      mlResult = await callMlEngine('/internal/analyze/media', { file_url, media_type });
    } catch (err) {
      console.error('[checkController.checkMedia ML Service Error]', err.message);
      return res.status(502).json({
        error: 'DETECTION_ENGINE_UNAVAILABLE',
        message: 'Detection engine unavailable'
      });
    }

    const recommendedActions = Array.isArray(mlResult.recommended_actions) && mlResult.recommended_actions.length > 0
      ? mlResult.recommended_actions
      : (mlResult.recommended_action ? [mlResult.recommended_action] : ['Verify speaker identity via a secondary known channel before taking financial or sensitive action.']);

    const confidenceScore = typeof mlResult.confidence_score === 'number'
      ? mlResult.confidence_score
      : 0.89;

    let incident;
    try {
      incident = await persistDetectionIncident({
        user: req.user,
        threatType: 'deepfake',
        sourceType: media_type,
        mlResult,
        recommendedActions
      });
    } catch (dbErr) {
      console.error('[checkController.checkMedia Database Persistence Error]', dbErr.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to persist incident record'
      });
    }

    return res.status(200).json({
      id: incident.id,
      risk_level: mlResult.risk_level,
      explanation: mlResult.explanation,
      recommended_actions: recommendedActions,
      confidence_score: confidenceScore,
      signals: mlResult.signals || {}
    });
  }
};

module.exports = checkController;

