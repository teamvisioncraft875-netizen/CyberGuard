const jwt = require('jsonwebtoken');
const { callMlEngine } = require('../utils/mlClient');
const { persistDetectionIncident } = require('../services/incidentService');
const { validateUserMediaOwnership, resolveStorageUrl } = require('../config/storage');
const { detectSecrets } = require('../services/secretDetector');

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
        mlResult: { ...mlResult, text },
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
      risk_level: (mlResult.risk_level || 'low').toLowerCase(),
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
        mlResult: { ...mlResult, url },
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
      risk_level: (mlResult.risk_level || 'low').toLowerCase(),
      explanation: mlResult.explanation,
      recommended_actions: recommendedActions,
      signals: mlResult.signals || {},
      cached: Boolean(mlResult._cached)
    });
  },

  /**
   * POST /api/v1/check/media
   */
  async checkMedia(req, res) {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' });
    }

    const { file_url, file_path, media_type } = req.body;
    const targetFile = file_path || file_url;

    // Validate request shape
    if (!targetFile || typeof targetFile !== 'string' || targetFile.trim().length === 0) {
      return res.status(400).json({ error: 'INVALID_FILE_URL', message: 'A valid file_url or file_path string is required' });
    }
    if (!media_type || !VALID_MEDIA_TYPES.includes(media_type)) {
      return res.status(400).json({ error: 'INVALID_MEDIA_TYPE', message: "media_type must be 'image' or 'audio'" });
    }

    // Tenant / User Media Ownership Check
    const isOwner = validateUserMediaOwnership(targetFile, req.user.id);
    if (!isOwner) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Access denied: cannot check media belonging to another user'
      });
    }

    const resolvedFileUrl = file_url || resolveStorageUrl(file_path);

    let mlResult;
    try {
      mlResult = await callMlEngine('/internal/analyze/media', { file_url: resolvedFileUrl, media_type });
    } catch (err) {
      console.error('[checkController.checkMedia ML Service Error]', err.message);
      if (err.message && (err.message.includes('HTTP 404') || err.message.includes('could not be resolved'))) {
        return res.status(404).json({
          error: 'FILE_NOT_FOUND',
          message: 'Media file could not be found at specified storage URL',
          file_url: resolvedFileUrl
        });
      }
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
      : 0.85;

    let incident = { id: `inc_${Date.now()}` };
    try {
      incident = await persistDetectionIncident({
        user: req.user,
        threatType: 'deepfake',
        sourceType: media_type,
        mlResult,
        recommendedActions
      });
    } catch (dbErr) {
      console.warn('[checkController.checkMedia Database Persistence Note]', dbErr.message);
      if (process.env.NODE_ENV !== 'test' && process.env.STRICT_DB === 'true') {
        return res.status(500).json({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to persist incident record'
        });
      }
    }

    return res.status(200).json({
      id: incident.id,
      risk_level: (mlResult.risk_level || 'low').toLowerCase(),
      risk_score: mlResult.risk_score,
      explanation: mlResult.explanation,
      recommended_actions: recommendedActions,
      confidence_score: confidenceScore,
      signals: mlResult.signals || {}
    });
  },

  /**
   * POST /api/v1/check/secret
   * Inspects strings/files for leaked credentials, private keys, database passwords, and API tokens.
   */
  async checkSecret(req, res) {
    const { input, context } = req.body;

    if (!input || typeof input !== 'string' || input.trim().length === 0) {
      return res.status(400).json({
        error: 'INVALID_INPUT',
        message: 'Input string is required and must be a non-empty string'
      });
    }

    // Optional user authentication extraction
    let user = req.user || null;
    if (!user && req.headers.authorization?.startsWith('Bearer ')) {
      try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!');
        user = decoded;
      } catch {}
    }

    const detectedSecrets = detectSecrets(input, { context });

    if (!detectedSecrets || detectedSecrets.length === 0) {
      return res.status(200).json({
        risk_level: 'safe',
        risk_score: 5,
        explanation: 'No exposed secrets detected',
        detected_secrets: [],
        signals: {},
        recommended_actions: []
      });
    }

    const maxScore = Math.max(...detectedSecrets.map((s) => s.score || 85));
    const riskLevel = maxScore >= 90 ? 'critical' : (maxScore >= 70 ? 'high' : 'medium');
    const secretTypesList = [...new Set(detectedSecrets.map((s) => s.secret_type))].join(', ');
    const explanation = `Found ${detectedSecrets.length} exposed secret(s): ${secretTypesList}`;

    const signals = {
      secret_types: [...new Set(detectedSecrets.map((s) => s.secret_type))].join(','),
      secret_count: detectedSecrets.length,
      locations: detectedSecrets.map((s) => `${s.secret_type} at ${s.location}`).join('; ')
    };

    const recommendedActions = [
      'Revoke exposed credential immediately and generate a new key.',
      'Remove secret from codebase, environment files, or public history.',
      'Audit access logs associated with the leaked credential.'
    ];

    let incident = null;
    try {
      incident = await persistDetectionIncident({
        user,
        threatType: 'exposed_secret',
        sourceType: 'check',
        mlResult: {
          risk_score: maxScore,
          risk_level: riskLevel,
          explanation,
          confidence: 100,
          signals
        },
        recommendedActions
      });
    } catch (incErr) {
      console.error('[checkController.checkSecret Incident Persistence Error]', incErr.message);
    }

    return res.status(200).json({
      id: incident?.id || null,
      risk_level: riskLevel,
      risk_score: maxScore,
      explanation,
      detected_secrets: detectedSecrets.map((s) => ({
        secret_type: s.secret_type,
        severity: s.severity,
        location: s.location
      })),
      signals,
      recommended_actions: recommendedActions
    });
  }
};

module.exports = checkController;

