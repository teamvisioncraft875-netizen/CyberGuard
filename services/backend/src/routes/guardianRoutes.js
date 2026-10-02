const express = require('express');
const guardianController = require('../controllers/guardianController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Guardian Mode routes (Requires JWT)
router.get('/links', auth, guardianController.listLinks);
router.post('/link', auth, guardianController.linkDependent);
router.post('/link/:id/accept', auth, guardianController.acceptGuardianLink);
router.post('/link/:id/decline', auth, guardianController.declineGuardianLink);
router.post('/link/:id/revoke', auth, guardianController.revokeLink);
router.get('/alerts', auth, guardianController.getDependentAlerts);
router.get('/users/search', auth, guardianController.searchUserByEmail);

module.exports = router;
