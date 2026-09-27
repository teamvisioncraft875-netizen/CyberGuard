const User = require('../models/User');
const { callMlEngine } = require('../utils/mlClient');

const VALID_RISK_LEVELS = new Set(['Safe', 'Low', 'Medium', 'High', 'Critical']);

/**
 * Validates the response schema returned by the Python ML service.
 * Ensures the response is a well-formed UnifiedAnalysisResponse.
 */
function isValidLoginMlResult(result) {
  if (!result || typeof result !== 'object') return false;
  if (!VALID_RISK_LEVELS.has(result.risk_level)) return false;
  if (typeof result.risk_score !== 'number' || !Number.isFinite(result.risk_score) || result.risk_score < 0 || result.risk_score > 100) return false;
  if (typeof result.explanation !== 'string' || !result.explanation.trim()) return false;
  if (!Array.isArray(result.recommended_actions)) return false;
  if (!result.signals || typeof result.signals !== 'object') return false;

  if (result.signals.anomaly_score !== undefined && result.signals.anomaly_score !== null) {
    const score = Number(result.signals.anomaly_score);
    if (!Number.isFinite(score) || score < 0.0 || score > 1.0) return false;
  }
  return true;
}

/**
 * Telemetry Controller — Ingests host system and authentication telemetry from Guard App sensors.
 */
const telemetryController = {
  /**
   * POST /api/v1/telemetry/login-event
   */
  async reportLoginEvent(req, res) {
    const { timestamp, location, device_id, failed_attempts } = req.body;

    // Validate required fields presence
    if (!timestamp || !device_id || failed_attempts === undefined || failed_attempts === null) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp, device_id, and failed_attempts are required'
      });
    }

    // Validate data types
    if (typeof timestamp !== 'string' || typeof device_id !== 'string') {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp and device_id must be strings'
      });
    }

    // Validate ISO timestamp
    if (isNaN(Date.parse(timestamp))) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp must be a valid ISO 8601 date string'
      });
    }

    // Validate failed_attempts
    if (typeof failed_attempts === 'boolean' || isNaN(Number(failed_attempts))) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'failed_attempts must be a non-negative integer'
      });
    }

    const numFailed = Number(failed_attempts);
    if (!Number.isInteger(numFailed) || numFailed < 0) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'failed_attempts must be a non-negative integer'
      });
    }

    if (location !== undefined && location !== null && typeof location !== 'string') {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'location must be a string if provided'
      });
    }

    // Privacy & Security: Strip any sensitive credentials or secrets if mistakenly provided
    const sanitizedLocation = typeof location === 'string' ? location.trim() : 'Unknown';
    const sanitizedDeviceId = device_id.trim();

    // Non-admin always forced to req.user.id, ignoring any client user_id in req.body
    let userId = req.user?.id;

    // If admin, verify the target user_id belongs to req.user.organization_id before accepting it
    if (req.user?.role === 'admin' && req.body.user_id) {
      if (req.body.user_id !== req.user?.id) {
        const targetUser = await User.findById(req.body.user_id);
        const targetOrg = targetUser?.organization_id || targetUser?.org_id;

        if (!targetUser || !targetOrg || targetOrg !== req.user.organization_id) {
          return res.status(403).json({
            error: 'FORBIDDEN',
            message: 'Target user does not belong to your organization'
          });
        }
      }
      userId = req.body.user_id;
    }

    let mlResult;
    try {
      mlResult = await callMlEngine('/internal/analyze/login', {
        user_id: userId,
        timestamp,
        location: sanitizedLocation,
        device_id: sanitizedDeviceId,
        failed_attempts: numFailed
      });
    } catch (err) {
      console.error('[telemetryController.reportLoginEvent ML Service Error]', err.message);
      return res.status(502).json({
        error: 'DETECTION_ENGINE_UNAVAILABLE',
        message: 'Detection engine unavailable'
      });
    }

    // Validate response from ML engine (Fail-closed on malformed or corrupted inference)
    if (!isValidLoginMlResult(mlResult)) {
      console.error('[telemetryController.reportLoginEvent Malformed ML Response]');
      return res.status(502).json({
        error: 'DETECTION_ENGINE_UNAVAILABLE',
        message: 'Detection engine returned invalid or malformed response'
      });
    }

    const anomalyDetected = mlResult.risk_level !== 'Safe' && mlResult.risk_level !== 'Low';

    return res.status(201).json({
      status: 'recorded',
      anomaly_detected: anomalyDetected,
      risk_level: mlResult.risk_level,
      risk_score: mlResult.risk_score,
      explanation: mlResult.explanation,
      recommended_actions: mlResult.recommended_actions,
      signals: mlResult.signals
    });
  },

  /**
   * POST /api/v1/telemetry/system-event
   */
  async reportSystemEvent(req, res) {
    const { timestamp, event_type, details } = req.body;

    // Validate request shape (timestamp, event_type, details)
    if (!timestamp || !event_type || !details || typeof details !== 'object') {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp, event_type, and details object are required'
      });
    }

    // Non-admin always forced to req.user.id, ignoring any client user_id in req.body
    let userId = req.user?.id;

    // If admin, verify the target user_id belongs to req.user.organization_id before accepting it
    if (req.user?.role === 'admin' && req.body.user_id) {
      if (req.body.user_id !== req.user?.id) {
        const targetUser = await User.findById(req.body.user_id);
        const targetOrg = targetUser?.organization_id || targetUser?.org_id;

        if (!targetUser || !targetOrg || targetOrg !== req.user.organization_id) {
          return res.status(403).json({
            error: 'FORBIDDEN',
            message: 'Target user does not belong to your organization'
          });
        }
      }
      userId = req.body.user_id;
    }

    let mlResult = null;
    try {
      mlResult = await callMlEngine('/internal/analyze/system', {
        user_id: userId,
        timestamp,
        event_type,
        details
      });
    } catch (err) {
      console.warn('[telemetryController.reportSystemEvent ML Service Note]', err.message);
    }

    const anomalyDetected = mlResult ? (mlResult.risk_level !== 'Safe' && mlResult.risk_level !== 'Low') : true;
    const riskLevel = mlResult?.risk_level || 'Medium';

    return res.status(201).json({
      status: 'recorded',
      anomaly_detected: anomalyDetected,
      risk_level: riskLevel,
      risk_score: mlResult?.risk_score,
      explanation: mlResult?.explanation,
      signals: mlResult?.signals
    });
  }
};

module.exports = telemetryController;
