const express = require('express');
const auth = require('../middlewares/auth');
const roleCheck = require('../middlewares/roleCheck');
const { generalLimiter } = require('../middlewares/rateLimiter');
const responseAdminController = require('../controllers/responseAdminController');
const actionExecutionController = require('../controllers/actionExecutionController');

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

// POST /api/v1/admin/actions/:id/execute: auth + roleCheck(['admin'])
router.post(
  '/actions/:id/execute',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  actionExecutionController.executeAction
);

// POST /api/v1/admin/response-actions/:id/execute (alias)
router.post(
  '/response-actions/:id/execute',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  actionExecutionController.executeAction
);

// POST /api/v1/admin/agents/tokens: auth + roleCheck(['admin'])
const agentController = require('../controllers/agentController');
const firewallController = require('../controllers/firewallController');

// GET /api/v1/admin/agents: list org-scoped agents
router.get(
  '/agents',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  agentController.listAgents
);

// POST /api/v1/admin/agents/tokens: auth + roleCheck(['admin'])
router.post(
  '/agents/tokens',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  agentController.createEnrollmentToken
);

// Firewall Rules Management: auth + roleCheck(['admin'])
// GET /api/v1/admin/firewall-rules: list org-scoped firewall rules
router.get(
  '/firewall-rules',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  firewallController.listRules
);

// POST /api/v1/admin/firewall-rules/validate: pre-validate IP/domain
router.post(
  '/firewall-rules/validate',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  firewallController.validateRule
);

// POST /api/v1/admin/firewall-rules: create firewall rule in 'pending' status
router.post(
  '/firewall-rules',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  firewallController.createRule
);

// DELETE /api/v1/admin/firewall-rules/:rule_id: revoke rule (mark 'pending_delete')
router.delete(
  '/firewall-rules/:rule_id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  firewallController.deleteRule
);

// POST /api/v1/admin/agents/:agent_id/firewall-commands: manually queue firewall command to agent
router.post(
  '/agents/:agent_id/firewall-commands',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  firewallController.createManualFirewallCommand
);

// Attack Surface Discovery Phase B APIs
const attackSurfaceController = require('../controllers/attackSurfaceController');

// GET /api/v1/admin/attack-surface/exposures: list org attack surface exposures
router.get(
  '/attack-surface/exposures',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getExposures
);

// GET /api/v1/admin/attack-surface/overview: get fleet attack surface overview metrics
router.get(
  '/attack-surface/overview',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getOverview
);

// POST /api/v1/admin/attack-surface/scan: queue attack surface scan command for agent(s)
router.post(
  '/attack-surface/scan',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.triggerScan
);

module.exports = router;


