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

// ─────────────────────────────────────────────────────────────────────────────
// Attack Surface Discovery — Phase B + Phase C APIs
// ─────────────────────────────────────────────────────────────────────────────
const attackSurfaceController = require('../controllers/attackSurfaceController');

// ── Phase B ──────────────────────────────────────────────────────────────────

// GET /api/v1/admin/attack-surface/exposures
router.get(
  '/attack-surface/exposures',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getExposures
);

// GET /api/v1/admin/attack-surface/overview
router.get(
  '/attack-surface/overview',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getOverview
);

// POST /api/v1/admin/attack-surface/scan
router.post(
  '/attack-surface/scan',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.triggerScan
);

// ── Phase C ──────────────────────────────────────────────────────────────────

// GET /api/v1/admin/attack-surface/dashboard
// SOC dashboard: summary cards, risk distribution, category breakdown, top risky assets
router.get(
  '/attack-surface/dashboard',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getDashboard
);

// GET /api/v1/admin/attack-surface/exposures/:id
// Exposure detail: port metadata, MITRE mappings, linked incident timeline
// (Registered after the bare /exposures route — express matches literal first)
router.get(
  '/attack-surface/exposures/:id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getExposureById
);

// GET /api/v1/admin/attack-surface/analytics
// Time-series charts: exposure_trend, incident_trend, mitigation_trend, category_breakdown
router.get(
  '/attack-surface/analytics',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getAnalytics
);

// GET /api/v1/admin/attack-surface/scans
// Fleet scan history (paginated scan_attack_surface agent commands)
router.get(
  '/attack-surface/scans',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.getScanHistory
);

// PATCH /api/v1/admin/attack-surface/response-actions/:id
// Analyst approve/reject a proposed response action (shadow mode — no automatic execution)
router.patch(
  '/attack-surface/response-actions/:id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.updateResponseAction
);

// PATCH /api/v1/admin/attack-surface/incidents/:id
// Analyst update incident status, assign analyst, or add a note
router.patch(
  '/attack-surface/incidents/:id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.updateIncident
);

// Aliases for direct admin endpoint routes
router.patch(
  '/response-actions/:id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.updateResponseAction
);

router.patch(
  '/incidents/:id',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  attackSurfaceController.updateIncident
);

// =========================================================================
// DDoS Detection & Threat Monitoring Endpoints: auth + roleCheck(['admin'])
// =========================================================================
const ddosController = require('../controllers/ddosController');

// POST /api/v1/admin/ddos/scan: trigger manual detection scan
router.post(
  '/ddos/scan',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  ddosController.scan
);

// GET /api/v1/admin/ddos/threats: view active threats scoped to org
router.get(
  '/ddos/threats',
  auth,
  roleCheck(['admin']),
  generalLimiter,
  ddosController.getThreats
);

module.exports = router;
