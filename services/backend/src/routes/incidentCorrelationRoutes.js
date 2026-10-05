const express = require('express');
const incidentCorrelationController = require('../controllers/incidentCorrelationController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

/**
 * Incident Correlation Routes
 * Mounted at /api/v1/incidents or directly on router
 */
router.get(
  '/:id/related',
  auth,
  roleCheck(['admin', 'analyst']),
  incidentCorrelationController.getRelatedIncidents
);

module.exports = router;
