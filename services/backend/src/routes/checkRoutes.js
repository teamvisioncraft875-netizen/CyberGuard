const express = require('express');
const checkController = require('../controllers/checkController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Threat detection checks (Requires JWT)
router.post('/message', auth, checkController.checkMessage);
router.post('/url', auth, checkController.checkUrl);
router.post('/media', auth, checkController.checkMedia);

module.exports = router;
