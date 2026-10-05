const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const responseAdminController = require('../controllers/responseAdminController');
const attackSurfaceController = require('../controllers/attackSurfaceController');

const router = express.Router();

router.use(auth);
router.use(roleCheck(['admin']));
router.use(generalLimiter);

// GET /api/v1/response-actions
router.get('/', responseAdminController.listResponseActions);

// PATCH /api/v1/response-actions/:id (Analyst approve/reject shadow mode response action)
router.patch('/:id', attackSurfaceController.updateResponseAction);

// POST /api/v1/response-actions/:id/approve
router.post('/:id/approve', responseAdminController.approveResponseAction);

module.exports = router;
