const express = require('express');
const router = express.Router();
const threatIntelController = require('../controllers/threatIntelController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

// All Threat Intelligence endpoints require authentication and SOC Analyst / Admin privileges
router.use(auth);
router.use(roleCheck(['admin', 'analyst']));

// 1. IOC Management
router.post('/iocs', threatIntelController.createIOC);
router.get('/iocs', threatIntelController.listIOCs);
router.get('/iocs/:id', threatIntelController.getIOCById);
router.patch('/iocs/:id', threatIntelController.updateIOC);
router.delete('/iocs/:id', threatIntelController.deleteIOC);

// 2. Sightings
router.get('/sightings', threatIntelController.listSightings);

// 3. Threat Statistics Dashboard
router.get('/dashboard', threatIntelController.getDashboard);

// 4. Legacy Indicator & Feed APIs
router.get('/indicators', threatIntelController.listIndicators);
router.get('/indicators/:id', threatIntelController.getIndicator);
router.get('/feed-health', threatIntelController.getFeedHealth);
router.get('/feed-statistics', threatIntelController.getFeedStatistics);
router.get('/matches', threatIntelController.getRecentMatches);

module.exports = router;
