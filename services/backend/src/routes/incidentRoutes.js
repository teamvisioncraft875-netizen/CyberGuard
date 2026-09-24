const express = require('express');
const incidentController = require('../controllers/incidentController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

// Incident triage and management (Requires JWT)
router.get('/', auth, incidentController.listIncidents);
router.patch('/:id', auth, roleCheck(['admin']), incidentController.updateIncidentStatus);

module.exports = router;
