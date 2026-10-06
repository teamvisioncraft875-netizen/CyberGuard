const express = require('express');
const router = express.Router();
const siemController = require('../controllers/siemController');
const siemStreamingRoutes = require('./siemStreamingRoutes');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All SIEM endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 0. Real-Time Streaming & Live Operational Metrics (Phase 2)
router.use('/', siemStreamingRoutes);

// 1. Ingestion Endpoint
router.post('/events', siemController.ingestEvents);

// 2. Search & Detail Endpoints
router.get('/events', siemController.searchEvents);
router.get('/events/:id', siemController.getEventById);

// 3. Event Source Management
router.get('/sources', siemController.listSources);
router.post('/sources', siemController.createSource);

// 4. Ingestion Job Status
router.get('/jobs/:id', siemController.getJobById);

// 5. SOC Intelligence & Telemetry Statistics
router.get('/stats', siemController.getStats);

module.exports = router;
