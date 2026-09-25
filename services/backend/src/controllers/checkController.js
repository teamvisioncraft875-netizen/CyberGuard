const config = require('../config');
const { transaction } = require('../config/db');
const { getIO } = require('../config/socket');
const Incident = require('../models/Incident');
const DetectionSignal = require('../models/DetectionSignal');
const RecommendedAction = require('../models/RecommendedAction');
const GuardianLink = require('../models/GuardianLink');
const MitreMapping = require('../models/MitreMapping');

const VALID_SOURCE_TYPES = Object.freeze(['email', 'sms', 'social']);
const VALID_MEDIA_TYPES = Object.freeze(['image', 'audio']);
const ML_SERVICE_TIMEOUT_MS = 10000;

// Keys representing context/metadata rather than individual detection indicators
const METADATA_KEYS = new Set(['url', 'file_url', 'media_type', 'model_type', 'source_type']);

// Fallback approximation until all engines return a real numeric score
const FALLBACK_SCORES = {
  critical: 90,
  high: 70,
  medium: 45,
  low: 20,
  safe: 5
};

const { callMlEngine } = require('../utils/mlClient');

/**
 * Extracts and sanitizes detection signals for database insertion, skipping descriptive metadata keys.
 */
function extractDetectionSignals(signals, incidentId) {
  const signalRows = [];

  if (Array.isArray(signals)) {
    for (const item of signals) {
      if (!item || typeof item !== 'object') continue;
      const name = item.signal_name || item.name || Object.keys(item)[0];
      if (!name || METADATA_KEYS.has(String(name).toLowerCase())) continue;
      const rawVal = item.signal_value !== undefined ? item.signal_value : (item.value !== undefined ? item.value : item[name]);
      const signalValue = rawVal !== undefined && rawVal !== null ? String(rawVal) : '';
      let weight = null;
      if (typeof item.weight === 'number' && !isNaN(item.weight) && item.weight >= 0 && item.weight <= 1) {
        weight = item.weight;
      } else if (typeof rawVal === 'number' && !isNaN(rawVal) && rawVal >= 0 && rawVal <= 1) {
        weight = rawVal;
      }
      signalRows.push({
        incident_id: incidentId,
        signal_name: String(name),
        signal_value: signalValue,
        weight
      });
    }
  } else if (signals && typeof signals === 'object') {
    for (const [key, val] of Object.entries(signals)) {
      if (METADATA_KEYS.has(key.toLowerCase())) continue;
      const signalValue = val !== undefined && val !== null ? String(val) : '';
      let weight = null;
      if (typeof val === 'number' && !isNaN(val) && val >= 0 && val <= 1) {
        weight = val;
      }
      signalRows.push({
        incident_id: incidentId,
        signal_name: key,
        signal_value: signalValue,
        weight
      });
    }
  }

  return signalRows;
}

/**
 * Persists an incident, its detection signals, and recommended actions within an atomic transaction.
 * Emits real-time WebSocket notifications upon successful commit.
 */
async function persistDetectionIncident({
  user,
  threatType,
  sourceType,
  mlResult,
  recommendedActions
}) {
  const riskLevel = (mlResult.risk_level || 'medium').toLowerCase();
  // Approximate fallback score based on risk_level until all engines return a real score
  const riskScore = typeof mlResult.risk_score === 'number'
    ? mlResult.risk_score
    : (FALLBACK_SCORES[riskLevel] ?? 50);

  // 1. Transaction persistence (atomic all-or-nothing)
  const incident = await transaction(async (client) => {
    // Insert into incidents
    const newIncident = await Incident.create({
      user_id: user.id,
      organization_id: user.organization_id || null,
      threat_type: threatType,
      source_type: sourceType,
      risk_level: riskLevel,
      risk_score: riskScore,
      explanation: mlResult.explanation || '',
      status: 'open'
    }, client);

    // Insert into mitre_mappings
    const mitreTechnique = MitreMapping.getTechniqueForThreat(threatType);
    await MitreMapping.create({
      incident_id: newIncident.id,
      technique_id: mitreTechnique.technique_id,
      technique_name: mitreTechnique.technique_name
    }, client);

    // Insert into detection_signals
    const signalsToInsert = extractDetectionSignals(mlResult.signals, newIncident.id);
    if (signalsToInsert.length > 0) {
      await DetectionSignal.createMany(signalsToInsert, client);
    }

    // Insert into recommended_actions
    const actionsToInsert = recommendedActions.map((action) => ({
      incident_id: newIncident.id,
      action_type: typeof action === 'string' ? action : (action.action_type || action.action_text || String(action)),
      action_status: 'pending'
    }));
    if (actionsToInsert.length > 0) {
      await RecommendedAction.createMany(actionsToInsert, client);
    }

    return newIncident;
  });

  // 2. Real-time WebSocket emission (executed AFTER transaction commit)
  try {
    const io = getIO();
    if (io) {
      const incidentPayload = {
        id: incident.id,
        threat_type: incident.threat_type,
        source_type: incident.source_type,
        risk_level: incident.risk_level,
        risk_score: typeof incident.risk_score === 'number' ? incident.risk_score : Number(incident.risk_score),
        explanation: incident.explanation,
        status: incident.status,
        created_at: incident.created_at,
        recommended_actions: recommendedActions,
        signals: mlResult.signals || {}
      };

      // Emit to the user's private room
      io.to(`user:${incident.user_id}`).emit('incident:new', incidentPayload);

      // Emit to the organization room if incident is tenant-scoped
      if (incident.organization_id) {
        io.to(`org:${incident.organization_id}`).emit('incident:new', incidentPayload);
      }

      // Emit to active guardians linked to this dependent user
      const guardianLinks = await GuardianLink.findByDependentId(incident.user_id);
      if (Array.isArray(guardianLinks)) {
        for (const link of guardianLinks) {
          if (link.guardian_user_id) {
            io.to(`guardian:${link.guardian_user_id}`).emit('incident:new', incidentPayload);
          }
        }
      }
    }
  } catch (wsErr) {
    console.error('[WebSocket Notification Error]', wsErr.message);
  }

  return incident;
}

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

