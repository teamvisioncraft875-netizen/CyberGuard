const express = require('express');
const router = express.Router();
const copilotController = require('../controllers/copilotController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All Copilot endpoints require authentication and SOC Analyst / Senior Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst', 'senior_analyst']));

// 1. Direct Copilot Inquiries
router.post('/query', copilotController.query);

// 2. Multi-turn Investigation Sessions (Sprint C Phase 2)
router.post('/sessions', copilotController.createSession);
router.get('/sessions', copilotController.listSessions);
router.get('/sessions/:id', copilotController.getSessionById);
router.delete('/sessions/:id', copilotController.deleteSession);
router.post('/sessions/:id/message', copilotController.postMessage);

// 3. Operational Actions & SOAR Integration (Sprint C Phase 3)
router.post('/recommend-actions', copilotController.recommendActions);
router.post('/execute-action', copilotController.executeAction);
router.post('/recommend-playbooks', copilotController.recommendPlaybooks);
router.get('/sessions/:id/actions', copilotController.getSessionActions);

// 4. Natural Language SOC Operations (Sprint C Phase 4)
router.post('/command', copilotController.command);
router.post('/plan', copilotController.plan);
router.post('/explain', copilotController.explain);
router.get('/sessions/:id/timeline', copilotController.getSessionTimeline);

module.exports = router;
