const ResponseAction = require('../models/ResponseAction');
const ResponsePolicy = require('../models/ResponsePolicy');
const PolicyEngine = require('../services/PolicyEngine');

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
  }
};

module.exports = responseAdminController;
