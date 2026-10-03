const express = require('express');
const checkController = require('../controllers/checkController');
const mediaController = require('../controllers/mediaController');
const auth = require('../middlewares/auth');
const { secretCheckLimiter } = require('../middlewares/rateLimiter');

const router = express.Router();

// Threat detection checks (Requires JWT)
router.post('/message', auth, checkController.checkMessage);
router.post('/url', auth, checkController.checkUrl);
router.post('/media', auth, checkController.checkMedia);
router.post('/media/upload-url', auth, mediaController.getUploadUrl);

// Secret & Credential Exposure Check (Public, strictly rate-limited: 20 req / 15m)
router.post('/secret', secretCheckLimiter, checkController.checkSecret);

module.exports = router;
