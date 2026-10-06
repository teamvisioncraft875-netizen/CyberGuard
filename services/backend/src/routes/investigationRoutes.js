const express = require('express');
const investigationController = require('../controllers/investigationController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

// All investigation & SOC command center endpoints require authenticated SOC analysts or admins
const socAuth = [auth, roleCheck(['admin', 'analyst'])];

// 1. Static paths first (to avoid being trapped by /:id)
router.get('/prioritized', socAuth, investigationController.getPrioritizedIncidents);
router.get('/queue', socAuth, investigationController.getQueue);

// 2. Incident-specific investigation endpoints
router.get('/:id/workspace', socAuth, investigationController.getWorkspace);
router.post('/:id/notes', socAuth, investigationController.addNote);
router.get('/:id/recommendations', socAuth, investigationController.getRecommendations);
router.get('/:id/command-center', socAuth, investigationController.getCommandCenter);

// 3. Analyst workflow actions
router.post('/:id/assign', socAuth, investigationController.assignIncident);
router.post('/:id/escalate', socAuth, investigationController.escalateIncident);
router.post('/:id/resolve', socAuth, investigationController.resolveIncident);
router.post('/:id/reopen', socAuth, investigationController.reopenIncident);

module.exports = router;
