const express = require('express');
const router = express.Router();
const copilotController = require('../controllers/copilotController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// Copilot endpoints require authentication and SOC Analyst / Senior Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst', 'senior_analyst']));

// POST /api/v1/copilot/query
router.post('/query', copilotController.query);

module.exports = router;
