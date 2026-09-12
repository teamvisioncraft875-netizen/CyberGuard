/**
 * Telemetry Controller — Ingests host system and authentication telemetry from Guard App sensors.
 */
const telemetryController = {
  /**
   * POST /api/v1/telemetry/login-event
   */
  async reportLoginEvent(req, res) {
    const { user_id, timestamp, location, device_id, failed_attempts } = req.body;

    // Validate request shape
    if (!user_id || !timestamp || !device_id || failed_attempts === undefined) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'user_id, timestamp, device_id, and failed_attempts are required'
      });
    }

    // TODO: Insert record into LoginEvent model, dispatch to FastAPI ML Service (POST /internal/analyze/login)
    // for Isolation Forest evaluation, and persist Incident if anomaly is detected.

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
    const { user_id, timestamp, event_type, details } = req.body;

    // Validate request shape
    if (!user_id || !timestamp || !event_type || !details || typeof details !== 'object') {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'user_id, timestamp, event_type, and details object are required'
      });
    }

    // TODO: Persist event into TelemetryEvent model, dispatch to FastAPI ML Service (POST /internal/analyze/system),
    // and broadcast host system alert if process or network spikes indicate malicious activity.

    return res.status(201).json({
      status: 'recorded',
      anomaly_detected: true,
      risk_level: 'Medium'
    });
  }
};

module.exports = telemetryController;
