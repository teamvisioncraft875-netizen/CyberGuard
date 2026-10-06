const express = require('express');
const incidentController = require('../controllers/incidentController');
const incidentCorrelationRoutes = require('./incidentCorrelationRoutes');
const attackChainRoutes = require('./attackChainRoutes');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

// Incident Correlation Graph & Relationship Routes
router.use('/', incidentCorrelationRoutes);

// Attack Chain & MITRE Progression Routes
router.use('/', attackChainRoutes);

// SOC Investigation Workspace, Command Center, Prioritization & Workflow Routes
const investigationRoutes = require('./investigationRoutes');
router.use('/', investigationRoutes);

// Incident triage and management (Requires JWT)
router.get('/', auth, incidentController.listIncidents);
router.get('/:id', auth, incidentController.getIncidentById);
router.patch('/:id', auth, roleCheck(['admin']), incidentController.updateIncidentStatus);

module.exports = router;
