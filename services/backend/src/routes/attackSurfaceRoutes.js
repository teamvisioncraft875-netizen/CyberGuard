const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const attackSurfaceController = require('../controllers/attackSurfaceController');

const router = express.Router();

router.use(auth);
router.use(roleCheck(['admin']));
router.use(generalLimiter);

// Attack Surface Discovery API endpoints
router.get('/dashboard', attackSurfaceController.getDashboard);
router.get('/exposures', attackSurfaceController.getExposures);
router.get('/exposures/:id', attackSurfaceController.getExposureById);
router.get('/analytics', attackSurfaceController.getAnalytics);
router.get('/scans', attackSurfaceController.getScanHistory);
router.post('/scan', attackSurfaceController.triggerScan);

module.exports = router;
