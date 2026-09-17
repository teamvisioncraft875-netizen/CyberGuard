const express = require('express');
const authController = require('../controllers/authController');
const auth = require('../middlewares/auth');

const router = express.Router();

// Public routes
router.post('/signup', authController.signup);
router.post('/login', authController.login);

// Protected routes
router.get('/me', auth, authController.getMe);

module.exports = router;
