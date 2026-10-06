const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const threatIntelAnalyticsController = require('../controllers/threatIntelAnalyticsController');

const router = express.Router();

// Enforce authentication, analyst/admin RBAC, and rate limiting
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));
router.use(generalLimiter);

// Analytics endpoints
router.get('/trends', threatIntelAnalyticsController.getTrends);
router.get('/top-indicators', threatIntelAnalyticsController.getTopIndicators);
router.get('/top-domains', threatIntelAnalyticsController.getTopDomains);
router.get('/top-ips', threatIntelAnalyticsController.getTopIPs);
router.get('/feed-performance', threatIntelAnalyticsController.getFeedPerformance);
router.get('/ioc-stats', threatIntelAnalyticsController.getIOCStats);
router.get('/provider-metrics', threatIntelAnalyticsController.getProviderMetrics);
router.get('/executive-summary', threatIntelAnalyticsController.getExecutiveSummary);

module.exports = router;
