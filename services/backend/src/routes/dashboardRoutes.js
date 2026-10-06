const express = require('express');
const dashboardController = require('../controllers/dashboardController');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');

const router = express.Router();

const socAuth = [auth, roleCheck(['admin', 'analyst'])];

router.get('/overview', socAuth, dashboardController.getOverview);
router.get('/trends', socAuth, dashboardController.getTrends);
router.get('/metrics', socAuth, dashboardController.getMetrics);

module.exports = router;
