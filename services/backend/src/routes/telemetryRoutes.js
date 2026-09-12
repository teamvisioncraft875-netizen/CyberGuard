const express = require('express');
const telemetryController = require('../controllers/telemetryController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Guard App sensor telemetry ingestion (Requires JWT)
router.post('/login-event', auth, telemetryController.reportLoginEvent);
router.post('/system-event', auth, telemetryController.reportSystemEvent);

module.exports = router;
