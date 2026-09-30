const express = require('express');
const mediaController = require('../controllers/mediaController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Generate signed upload URL for direct-to-Supabase upload (requires JWT)
router.post('/upload-url', auth, mediaController.getUploadUrl);

module.exports = router;
