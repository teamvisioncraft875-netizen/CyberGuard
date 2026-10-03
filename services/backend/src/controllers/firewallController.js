const firewallService = require('../services/firewallService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Firewall Controller — REST endpoints for firewall rule administration
 * and agent safe target distribution.
 */
const firewallController = {
  /**
   * GET /api/v1/admin/firewall-rules
   * Lists firewall rules scoped to the authenticated admin's organization.
   */
  async listRules(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization'
        });
      }

      const { agent_id, status, rule_type, limit, offset } = req.query;

      const result = await firewallService.listFirewallRules(orgId, {
        agent_id,
        status,
        rule_type,
        limit,
        offset
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[firewallController.listRules error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve firewall rules'
      });
    }
  },

  /**
   * POST /api/v1/admin/firewall-rules/validate
   * Pre-validates a candidate target IP or domain without creating a rule.
   */
  async validateRule(req, res) {
    try {
      const { rule_type, target_data } = req.body || {};

      if (!rule_type || !target_data) {
        return res.status(400).json({
          valid: false,
          error: 'Both rule_type and target_data are required'
        });
      }

      const validation = firewallService.validateFirewallInput(rule_type, target_data);

      return res.status(200).json({
        valid: validation.valid,
        error_if_invalid: validation.valid ? null : validation.error,
        error: validation.error || null,
        target_ip: validation.target_ip || null,
        target_domain: validation.target_domain || null
      });
    } catch (err) {
      console.error('[firewallController.validateRule error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Error during rule validation'
      });
    }
  },

  /**
   * POST /api/v1/admin/firewall-rules
   * Creates a new firewall rule in 'pending' status for an agent.
   */
  async createRule(req, res) {
    try {
      const { agent_id, rule_type, target_data } = req.body || {};
      const userId = req.user?.id || null;

      if (!agent_id || !UUID_REGEX.test(agent_id)) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: 'Valid agent_id UUID is required'
        });
      }

      if (!rule_type || !['block_ip', 'block_domain'].includes(rule_type)) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: "rule_type must be either 'block_ip' or 'block_domain'"
        });
      }

      if (!target_data) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: 'target_data payload is required'
        });
      }

      const result = await firewallService.createFirewallRule(
        agent_id,
        rule_type,
        target_data,
        userId
      );

      if (!result.valid) {
        return res.status(400).json({
          error: 'VALIDATION_FAILED',
          message: result.error,
          validation_result: result.validation_result
        });
      }

      if (!result.success) {
        return res.status(500).json({
          error: 'RULE_CREATION_FAILED',
          message: result.error
        });
      }

      return res.status(201).json({
        success: true,
        rule_id: result.rule_id,
        status: result.status,
        rule: result.rule,
        validation_result: result.validation_result
      });
    } catch (err) {
      console.error('[firewallController.createRule error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to create firewall rule'
      });
    }
  },

  /**
   * DELETE /api/v1/admin/firewall-rules/:rule_id
   * Marks a firewall rule as 'pending_delete' for revocation.
   */
  async deleteRule(req, res) {
    try {
      const { rule_id } = req.params;
      const orgId = req.user?.organization_id;
      const userId = req.user?.id || null;

      if (!rule_id || !UUID_REGEX.test(rule_id)) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: 'Valid rule_id UUID is required'
        });
      }

      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization'
        });
      }

      const result = await firewallService.deleteFirewallRule(rule_id, orgId, userId);

      if (result.notFound) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Firewall rule not found in your organization'
        });
      }

      if (!result.success) {
        return res.status(500).json({
          error: 'DELETE_FAILED',
          message: result.error || 'Failed to revoke firewall rule'
        });
      }

      return res.status(200).json({
        deleted: true,
        rule_id: result.rule_id
      });
    } catch (err) {
      console.error('[firewallController.deleteRule error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to revoke firewall rule'
      });
    }
  },

  /**
   * GET /api/v1/agents/:agent_id/protected-targets
   * Endpoint for agents to download current protected IPs and domains.
   */
  async getProtectedTargets(req, res) {
    try {
      const targets = firewallService.getProtectedTargets();
      return res.status(200).json({
        protected_ips: targets.protected_ips,
        protected_ip_ranges: targets.protected_ip_ranges,
        protected_domains: targets.protected_domains
      });
    } catch (err) {
      console.error('[firewallController.getProtectedTargets error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve protected targets'
      });
    }
  }
};

module.exports = firewallController;
