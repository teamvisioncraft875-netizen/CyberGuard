const User = require('../models/User');
const LoginEvent = require('../models/LoginEvent');
const TelemetryEvent = require('../models/TelemetryEvent');
const { callMlEngine } = require('../utils/mlClient');
const { persistDetectionIncident } = require('../services/incidentService');

const ANOMALOUS_RISK_TIERS = new Set(['medium', 'high', 'critical']);

/**
 * Telemetry Controller — Ingests host system and authentication telemetry from Guard App sensors.
 * Persists raw telemetry records to PostgreSQL and spawns incident records for anomalous events.
 */
const telemetryController = {
  /**
   * POST /api/v1/telemetry/login-event
   */
  async reportLoginEvent(req, res) {
    const { timestamp, location, device_id, failed_attempts } = req.body;

    // Validate request shape (timestamp, device_id, failed_attempts)
    if (!timestamp || !device_id || failed_attempts === undefined) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'timestamp, device_id, and failed_attempts are required'
      });
    }

    // Non-admin always forced to req.user.id, ignoring any client user_id in req.body
    let userId = req.user?.id;
    let userOrgId = req.user?.organization_id || null;

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
        userOrgId = targetOrg;
      }
      userId = req.body.user_id;
    }

    let mlResult = null;
    try {
      mlResult = await callMlEngine('/internal/analyze/login', {
        user_id: userId,
        timestamp,
        location: location || 'Unknown',
        device_id,
        failed_attempts: Number(failed_attempts) || 0
      });
    } catch (err) {
      console.warn('[telemetryController.reportLoginEvent ML Service Note]', err.message);
    }

    // 1. Insert raw row into login_events regardless of risk level
    try {
      await LoginEvent.create({
        user_id: userId,
        device_id,
        device_fingerprint: device_id,
        ip_address: req.body.ip_address || req.ip || null,
        location: location || 'Unknown',
        success: Number(failed_attempts) === 0,
        failed_attempt_count: Number(failed_attempts) || 0
      });
    } catch (dbErr) {
      console.warn('[telemetryController.reportLoginEvent DB Note]', dbErr.message);
    }

    const anomalyDetected = mlResult ? (mlResult.risk_level !== 'Safe' && mlResult.risk_level !== 'Low') : true;
    const riskLevel = mlResult?.risk_level || 'High';
    const riskLevelLower = (mlResult?.risk_level || '').toLowerCase();
    const isAnomalous = ANOMALOUS_RISK_TIERS.has(riskLevelLower);

    // 2. If anomaly detected (medium/high/critical), persist incident with MITRE mapping and alerts
    let incident = null;
    if (mlResult && isAnomalous) {
      const recommendedActions = Array.isArray(mlResult.recommended_actions) && mlResult.recommended_actions.length > 0
        ? mlResult.recommended_actions
        : (mlResult.recommended_action
            ? [mlResult.recommended_action]
            : ['Terminate active sessions and force password reset for compromised user account.', 'Enforce multi-factor authentication (MFA).']);

      try {
        incident = await persistDetectionIncident({
          user: {
            id: userId,
            organization_id: userOrgId
          },
          threatType: 'account_takeover',
          sourceType: 'login',
          mlResult,
          recommendedActions
        });
      } catch (incErr) {
        console.warn('[telemetryController.reportLoginEvent Incident Note]', incErr.message);
      }
    }

    // 3. Response shape
    const responsePayload = {
      status: 'recorded',
      anomaly_detected: anomalyDetected,
      risk_level: riskLevel
    };
    if (incident?.id) {
      responsePayload.incident_id = incident.id;
    }

    return res.status(201).json(responsePayload);
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
    let userOrgId = req.user?.organization_id || null;

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
        userOrgId = targetOrg;
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

    // 1. Insert raw row into telemetry_events regardless of risk level
    try {
      await TelemetryEvent.create({
        user_id: userId,
        device_id: req.body.device_id || null,
        event_type,
        payload: details
      });
    } catch (dbErr) {
      console.warn('[telemetryController.reportSystemEvent DB Note]', dbErr.message);
    }

    const anomalyDetected = mlResult ? (mlResult.risk_level !== 'Safe' && mlResult.risk_level !== 'Low') : true;
    const riskLevel = mlResult?.risk_level || 'Medium';
    const riskLevelLower = (mlResult?.risk_level || '').toLowerCase();
    const isAnomalous = ANOMALOUS_RISK_TIERS.has(riskLevelLower);

    // 2. If anomaly detected (medium/high/critical), persist incident with MITRE mapping and alerts
    let incident = null;
    if (mlResult && isAnomalous) {
      const recommendedActions = Array.isArray(mlResult.recommended_actions) && mlResult.recommended_actions.length > 0
        ? mlResult.recommended_actions
        : (mlResult.recommended_action
            ? [mlResult.recommended_action]
            : ['Investigate anomalous host activity and isolate network interface if unauthorized traffic persists.']);

      try {
        incident = await persistDetectionIncident({
          user: {
            id: userId,
            organization_id: userOrgId
          },
          threatType: 'technical_threat',
          sourceType: 'system',
          mlResult,
          recommendedActions
        });
      } catch (incErr) {
        console.warn('[telemetryController.reportSystemEvent Incident Note]', incErr.message);
      }
    }

    // 3. Response shape
    const responsePayload = {
      status: 'recorded',
      anomaly_detected: anomalyDetected,
      risk_level: riskLevel,
      risk_score: mlResult?.risk_score,
      explanation: mlResult?.explanation,
      signals: mlResult?.signals
    };
    if (incident?.id) {
      responsePayload.incident_id = incident.id;
    }

    return res.status(201).json(responsePayload);
  }
};

module.exports = telemetryController;
