const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const auditController = require('../controllers/auditController');

const router = express.Router();

// GET /api/v1/audit-logs: auth + roleCheck(['admin']) + generalLimiter
router.get('/', auth, roleCheck(['admin']), generalLimiter, auditController.listAuditLogs);

module.exports = router;
