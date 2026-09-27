const express = require('express');
const actionController = require('../controllers/actionController');
const auth = require('../middlewares/auth');

const router = express.Router();

// PATCH /api/v1/actions/:id
router.patch('/:id', auth, actionController.updateActionStatus);

module.exports = router;
