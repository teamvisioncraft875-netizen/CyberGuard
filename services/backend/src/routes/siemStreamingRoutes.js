const express = require('express');
const router = express.Router();
const siemStreamingController = require('../controllers/siemStreamingController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// Streaming and live metric endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 1. Live Server-Sent Events (SSE) Stream
router.get('/stream', siemStreamingController.stream);

// 2. Real-Time Operational Dashboard Metrics
router.get('/live-metrics', siemStreamingController.getLiveMetrics);

module.exports = router;
