const express = require('express');
const router = express.Router();
const siemSocController = require('../controllers/siemSocController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All SOC endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 1. Real-Time Alert Feed via SSE
router.get('/live', siemSocController.liveStream);

// 2. Alert Lifecycle Management
router.get('/alerts', siemSocController.listAlerts);
router.get('/alerts/:id', siemSocController.getAlertById);
router.patch('/alerts/:id', siemSocController.updateAlert);

// 3. SOC Metrics Dashboard
router.get('/dashboard/metrics', siemSocController.getDashboardMetrics);
router.get('/dashboard/trends', siemSocController.getDashboardTrends);

// 4. Analyst Queue
router.get('/queue', siemSocController.getQueue);

// 5. Timeline API
router.get('/timeline', siemSocController.getTimeline);

// 6. Performance Dashboard APIs (Admin Only)
router.get('/performance', roleCheck(['admin']), siemSocController.getPerformance);
router.get('/performance/history', roleCheck(['admin']), siemSocController.getPerformanceHistory);

module.exports = router;
