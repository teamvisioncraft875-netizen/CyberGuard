const express = require('express');
const telemetryController = require('../controllers/telemetryController');
const auth = require('../middlewares/auth');
const agentService = require('../services/agentService');

const router = express.Router();

/**
 * Flexible middleware for POST /telemetry/system-event:
 * Allows EITHER Agent credentials (credential_id + credential_secret) OR User JWT (auth.js).
 */
const flexibleSystemEventAuth = async (req, res, next) => {
  const credential_id = req.body?.credential_id || req.headers['x-agent-credential-id'];
  const credential_secret = req.body?.credential_secret || req.headers['x-agent-credential-secret'];
  const device_id = req.body?.device_id || req.headers['x-agent-device-id'];

  if (credential_id && credential_secret) {
    try {
      let device = null;
      if (device_id) {
        device = await agentService.verifyAgentCredentials(device_id, credential_id, credential_secret);
      } else {
        device = await agentService.verifyAgentCredentialsByCredentialId(credential_id, credential_secret);
      }

      if (!device) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'Invalid agent credentials or device disabled'
        });
      }

      req.agent = {
        device_id: device.id,
        organization_id: device.organization_id,
        user_id: device.user_id || null
      };
      return next();
    } catch (err) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Agent authentication failed'
      });
    }
  }

  // If no agent credentials present, require standard user JWT auth
  return auth(req, res, next);
};

// Guard App sensor telemetry ingestion (Requires JWT)
router.post('/login-event', auth, telemetryController.reportLoginEvent);

// System telemetry ingestion (Accepts User JWT OR Agent credentials)
router.post('/system-event', flexibleSystemEventAuth, telemetryController.reportSystemEvent);

module.exports = router;
