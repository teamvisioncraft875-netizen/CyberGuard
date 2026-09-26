const express = require('express');
const guardianController = require('../controllers/guardianController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Guardian Mode routes (Requires JWT)
router.post('/link', auth, guardianController.linkDependent);
router.post('/link/:id/accept', auth, guardianController.acceptGuardianLink);
router.post('/link/:id/decline', auth, guardianController.declineGuardianLink);
router.post('/link/:id/revoke', auth, guardianController.declineGuardianLink);
router.get('/alerts', auth, guardianController.getDependentAlerts);

module.exports = router;
