const express = require('express');
const analyticsController = require('../controllers/analyticsController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Command Dashboard Analytics (Requires JWT)
router.get('/overview', auth, analyticsController.getOverview);
router.get('/trends', auth, analyticsController.getTrends);
router.get('/mitre', auth, analyticsController.getMitreBreakdown);

module.exports = router;
