const express = require('express');
const authController = require('../controllers/authController');
const auth = require('../middlewares/auth');

const { authLimiter } = require('../middlewares/rateLimiter');

const router = express.Router();

// Public routes with strict rate limiting (5 req / 15 min per IP)
router.post('/signup', authLimiter, authController.signup);
router.post('/login', authLimiter, authController.login);

// Protected routes
router.get('/me', auth, authController.getMe);

module.exports = router;
