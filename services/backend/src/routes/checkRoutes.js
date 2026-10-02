const express = require('express');
const checkController = require('../controllers/checkController');
const auth = require('../middlewares/auth');

const router = express.Router();

const mediaController = require('../controllers/mediaController');

// Threat detection checks (Requires JWT)
router.post('/message', auth, checkController.checkMessage);
router.post('/url', auth, checkController.checkUrl);
router.post('/media', auth, checkController.checkMedia);
router.post('/media/upload-url', auth, mediaController.getUploadUrl);

module.exports = router;
