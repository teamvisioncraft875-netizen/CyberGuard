const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const responseAdminController = require('../controllers/responseAdminController');

const router = express.Router();

// GET /api/v1/admin/response-actions: auth + roleCheck(['admin'])
router.get(
  '/response-actions',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  responseAdminController.listResponseActions
);

// POST /api/v1/admin/response-policies: auth + roleCheck(['admin'])
router.post(
  '/response-policies',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  responseAdminController.createResponsePolicy
);

// GET /api/v1/admin/response-policies: auth + roleCheck(['admin'])
router.get(
  '/response-policies',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  responseAdminController.listResponsePolicies
);

// POST /api/v1/admin/actions/:id/approve: auth + roleCheck(['admin'])
router.post(
  '/actions/:id/approve',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  responseAdminController.approveResponseAction
);

// POST /api/v1/admin/response-actions/:id/approve (alias)
router.post(
  '/response-actions/:id/approve',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  responseAdminController.approveResponseAction
);

module.exports = router;
