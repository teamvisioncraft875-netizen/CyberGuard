const express = require('express');
const incidentGroupController = require('../controllers/incidentGroupController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

/**
 * Incident Group & Campaign Aggregation Routes
 * Base route: /api/v1/incident-groups
 */

// List incident groups with filtering
router.get('/', auth, roleCheck(['admin', 'analyst']), incidentGroupController.listGroups);

// Get incident group details, members, and aggregate metrics
router.get('/:id', auth, roleCheck(['admin', 'analyst']), incidentGroupController.getGroupById);

// Resolve an incident group and its member incidents (admin only)
router.post('/:id/resolve', auth, roleCheck(['admin']), incidentGroupController.resolveGroup);

module.exports = router;
