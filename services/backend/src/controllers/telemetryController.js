const User = require('../models/User');

/**
 * Telemetry Controller — Ingests host system and authentication telemetry from Guard App sensors.
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

    // TODO: Insert record into LoginEvent model with userId, dispatch to FastAPI ML Service (POST /internal/analyze/login)

    return res.status(201).json({
      status: 'recorded',
      anomaly_detected: true,
      risk_level: 'High'
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

    // TODO: Persist event into TelemetryEvent model with resolvedUserId...

    return res.status(201).json({
      status: 'recorded',
      anomaly_detected: true,
      risk_level: 'Medium'
    });
  }
};

module.exports = telemetryController;
