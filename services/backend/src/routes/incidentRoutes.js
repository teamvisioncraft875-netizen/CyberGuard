const express = require('express');
const incidentController = require('../controllers/incidentController');
const incidentCorrelationRoutes = require('./incidentCorrelationRoutes');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

// Incident Correlation Graph & Relationship Routes
router.use('/', incidentCorrelationRoutes);

// Incident triage and management (Requires JWT)
router.get('/', auth, incidentController.listIncidents);
router.get('/:id', auth, incidentController.getIncidentById);
router.patch('/:id', auth, roleCheck(['admin']), incidentController.updateIncidentStatus);

module.exports = router;
