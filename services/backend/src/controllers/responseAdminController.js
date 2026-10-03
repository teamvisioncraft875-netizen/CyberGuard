const ResponseAction = require('../models/ResponseAction');
const ResponsePolicy = require('../models/ResponsePolicy');
const PolicyEngine = require('../services/PolicyEngine');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');
const notificationService = require('../services/notificationService');

/**
 * Controller for Administrative Automated Response Endpoints (Phase 1B).
 */
const responseAdminController = {
  /**
   * GET /api/v1/admin/response-actions
   * Lists response actions scoped to the admin's organization with filtering and pagination.
   */
  async listResponseActions(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization to view response actions'
        });
      }

      const { incident_id, status, from, to, limit, offset } = req.query;

      const result = await ResponseAction.list({
        organization_id,
        incident_id,
        status,
        from,
        to,
        limit,
        offset
      });

      return res.status(200).json({
        success: true,
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        actions: result.actions
      });
    } catch (err) {
      console.error('[Admin Response Actions List Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve response actions'
      });
    }
  },

  /**
   * POST /api/v1/admin/response-policies
   * Creates a new automated response policy for the admin's organization.
   */
  async createResponsePolicy(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization to create response policies'
        });
      }

      const { name, rules, enabled } = req.body;

      if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: 'Policy name is required and must be a non-empty string'
        });
      }

      try {
        PolicyEngine.validateRules(rules);
      } catch (valErr) {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: valErr.message
        });
      }

      const policy = await ResponsePolicy.create({
        organization_id,
        name: name.trim(),
        enabled: enabled !== undefined ? Boolean(enabled) : true,
        created_by_id: req.user.id,
        rules
      });

      return res.status(201).json({
        success: true,
        policy
      });
    } catch (err) {
      console.error('[Admin Create Response Policy Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to create response policy'
      });
    }
  },

  /**
   * GET /api/v1/admin/response-policies
   * Lists response policies scoped to the admin's organization.
   */
  async listResponsePolicies(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization to view response policies'
        });
      }

      const policies = await ResponsePolicy.listByOrg(organization_id);

      return res.status(200).json({
        success: true,
        policies
      });
    } catch (err) {
      console.error('[Admin Response Policies List Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve response policies'
      });
    }
  },

  /**
   * POST /api/v1/admin/actions/:id/approve
   * Approves or rejects a proposed / pending response action.
   */
  async approveResponseAction(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization to approve actions'
        });
      }

      const { id } = req.params;
      const { approved } = req.body;

      if (typeof approved !== 'boolean') {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: 'Field "approved" is required and must be a boolean (true or false)'
        });
      }

      // Find action scoped to caller's org
      const action = await ResponseAction.findByIdAndOrg(id, organization_id);
      if (!action) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Response action not found or does not belong to your organization'
        });
      }

      const newStatus = approved ? 'approved' : 'rejected';
      const updatedAction = await ResponseAction.setApproval(id, {
        organization_id,
        status: newStatus,
        approved_by_id: req.user.id,
        approved_at: new Date()
      });

      // Fire append-only audit log
      auditLog({
        organization_id,
        user_id: req.user.id,
        actor_type: 'admin',
        action: approved ? AUDIT_ACTIONS.RESPONSE_ACTION_APPROVED : AUDIT_ACTIONS.RESPONSE_ACTION_REJECTED,
        resource_type: 'response_action',
        resource_id: id,
        details: {
          action_type: action.action_type,
          previous_status: action.status,
          new_status: newStatus,
          approved
        },
        ip_address: req.ip || req.headers['x-forwarded-for'] || null
      });

      // Send confirmation email to approver
      notificationService.sendApprovalConfirmation(updatedAction, req.user, approved).catch((nErr) => {
        console.error('[NotificationService Approval Confirmation Error]', nErr.message);
      });

      return res.status(200).json({
        success: true,
        action: updatedAction
      });
    } catch (err) {
      console.error('[Admin Approve Response Action Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to update response action status'
      });
    }
  }
};

module.exports = responseAdminController;
