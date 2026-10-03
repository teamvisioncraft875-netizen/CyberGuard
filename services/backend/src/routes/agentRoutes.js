const express = require('express');
const agentController = require('../controllers/agentController');
const { generalLimiter, agentLimiter } = require('../middlewares/rateLimiter');
const jwt = require('jsonwebtoken');
const config = require('../config');

const router = express.Router();

// Optional JWT inspection for status endpoint (to enforce tenant scoping for admins)
const optionalJwt = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.split(' ')[1];
      req.user = jwt.verify(token, config.JWT_SECRET);
    } catch (e) {
      // Ignore invalid token, let endpoint handler decide
    }
  }
  next();
};

// 1. Enrollment (authenticated via one-time enrollment token)
router.post('/enroll', generalLimiter, agentController.enroll);

// 2. Heartbeat (authenticated via agent credential_id + credential_secret)
router.post('/:device_id/heartbeat', agentLimiter, agentController.heartbeat);

// 3. Command queue (authenticated via agent credential_id + credential_secret)
router.get('/:device_id/commands', agentLimiter, agentController.getCommands);

// 4. Command execution result (authenticated via agent credential_id + credential_secret)
router.post('/:device_id/commands/:command_id/result', agentLimiter, agentController.recordCommandResult);

const firewallController = require('../controllers/firewallController');

// 5. Device status view (Admin or Agent)
router.get('/:device_id/status', generalLimiter, optionalJwt, agentController.getStatus);

// 6. Protected targets (agent safe list download)
router.get('/:device_id/protected-targets', generalLimiter, firewallController.getProtectedTargets);

module.exports = router;
