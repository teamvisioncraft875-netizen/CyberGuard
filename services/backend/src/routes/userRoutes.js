const express = require('express');
const guardianController = require('../controllers/guardianController');
const auth = require('../middlewares/auth');

const router = express.Router();

// GET /api/v1/users/search?email=<email>
router.get('/search', auth, guardianController.searchUserByEmail);

module.exports = router;
