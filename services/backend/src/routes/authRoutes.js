const express = require('express');
const authController = require('../controllers/authController');
const auth = require('../middlewares/auth');

const { authLimiter } = require('../middlewares/rateLimiter');

const router = express.Router();

// Public routes with strict rate limiting
router.post('/signup', authLimiter, authController.signup);
router.post('/login', authLimiter, authController.login);
router.post('/refresh', authController.refresh); // Public, validates refresh token directly

// Protected routes
router.get('/me', auth, authController.getMe);
router.post('/logout', auth, authController.logout);

module.exports = router;
