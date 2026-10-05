const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const threatIntelController = require('../controllers/threatIntelController');

const router = express.Router();

// Enforce authentication, RBAC (analyst and admin roles only), and general rate-limiting
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));
router.use(generalLimiter);

// Threat Intelligence API endpoints
router.get('/dashboard', threatIntelController.getDashboard);
router.get('/indicators', threatIntelController.listIndicators);
router.get('/indicators/:id', threatIntelController.getIndicator);
router.get('/feed-health', threatIntelController.getFeedHealth);
router.get('/feed-statistics', threatIntelController.getFeedStatistics);
router.get('/matches', threatIntelController.getRecentMatches);

module.exports = router;
