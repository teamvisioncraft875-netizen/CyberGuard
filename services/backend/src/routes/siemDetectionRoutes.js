const express = require('express');
const router = express.Router();
const siemDetectionController = require('../controllers/siemDetectionController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// Detection hit and rule management endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 1. Detection Hits Endpoints
router.get('/detections', siemDetectionController.listDetections);
router.get('/detections/:id', siemDetectionController.getDetectionById);

// 2. Detection Rules Endpoints
router.get('/rules', siemDetectionController.listRules);
router.post('/rules', siemDetectionController.createRule);
router.patch('/rules/:id', siemDetectionController.updateRule);

module.exports = router;
