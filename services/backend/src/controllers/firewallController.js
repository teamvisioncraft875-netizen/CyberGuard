const db = require('../config/db');
const firewallService = require('../services/firewallService');
const auditService = require('../services/auditService');
const { AUDIT_ACTIONS } = require('../services/auditService');

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
  },

  /**
   * POST /api/v1/admin/agents/:agent_id/firewall-commands
   * Manually sends a firewall command (block_ip or block_domain) to a specific online agent.
   * Does NOT automatically create an agent_firewall_rules row (created only after execution).
   */
  async createManualFirewallCommand(req, res) {
    try {
      const orgId = req.user?.organization_id;
      const adminUserId = req.user?.id || null;

      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization'
        });
      }

      const { agent_id } = req.params;
      const { command_type, target_data, reason } = req.body || {};

      // 1. Validate agent_id
      if (!agent_id || !UUID_REGEX.test(agent_id)) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: 'Valid agent_id UUID is required'
        });
      }

      // 2. Validate command_type whitelist
      const ALLOWED_COMMANDS = ['block_ip', 'block_domain'];
      if (!command_type || !ALLOWED_COMMANDS.includes(command_type)) {
        return res.status(400).json({
          error: 'INVALID_COMMAND_TYPE',
          message: `command_type must be one of: ${ALLOWED_COMMANDS.join(', ')}`
        });
      }

      // 3. Validate target_data presence and required field
      if (!target_data || typeof target_data !== 'object' || Array.isArray(target_data)) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: 'target_data must be a valid JSON object'
        });
      }

      if (command_type === 'block_ip' && !target_data.ip_address && !target_data.ip) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: "target_data must contain 'ip_address' for block_ip command"
        });
      }

      if (command_type === 'block_domain' && !target_data.domain) {
        return res.status(400).json({
          error: 'INVALID_PAYLOAD',
          message: "target_data must contain 'domain' for block_domain command"
        });
      }

      // 4. Input validation (IP/domain format and protected target check)
      const validation = firewallService.validateFirewallInput(command_type, target_data);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'VALIDATION_FAILED',
          message: validation.error,
          validation_result: validation
        });
      }

      // 5. Verify agent exists, belongs to admin's organization, and check status
      const devRes = await db.query(
        `SELECT id, organization_id, status, last_heartbeat FROM public.devices WHERE id = $1;`,
        [agent_id]
      );

      if (!devRes.rows || devRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Agent ${agent_id} not found`
        });
      }

      const device = devRes.rows[0];

      // Org boundary check
      if (device.organization_id !== orgId) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Agent ${agent_id} not found in your organization`
        });
      }

      // Disabled check -> 409
      if (device.status === 'disabled') {
        return res.status(409).json({
          error: 'AGENT_DISABLED',
          message: 'Agent is disabled and cannot receive commands'
        });
      }

      // Online check -> 404
      if (device.status !== 'online') {
        return res.status(404).json({
          error: 'AGENT_OFFLINE',
          message: `Agent is ${device.status || 'offline'} and cannot receive commands`
        });
      }

      // 6. Create agent_commands row
      const insertRes = await db.query(
        `INSERT INTO public.agent_commands (
          device_id,
          organization_id,
          command_type,
          target_data,
          status,
          requested_by_id,
          can_execute,
          requires_approval,
          created_at
        ) VALUES ($1, $2, $3, $4, 'pending', $5, true, false, NOW())
        RETURNING id, device_id, organization_id, command_type, target_data, status, can_execute, created_at;`,
        [
          agent_id,
          orgId,
          command_type,
          JSON.stringify(target_data),
          adminUserId
        ]
      );

      const command = insertRes.rows[0];

      // 7. Audit log
      try {
        await auditService.log({
          organization_id: orgId,
          actor_type: 'admin',
          actor_id: adminUserId,
          action: AUDIT_ACTIONS.FIREWALL_COMMAND_CREATED || 'firewall_command_created',
          resource_type: 'agent_command',
          resource_id: command.id,
          details: {
            agent_id,
            command_type,
            target_data,
            reason: reason || 'manual testing'
          }
        });
      } catch (auditErr) {
        console.warn('[firewallController] Warning: Failed to record audit log:', auditErr.message);
      }

      return res.status(201).json({
        success: true,
        command_id: command.id,
        status: 'pending',
        agent_id,
        command
      });
    } catch (err) {
      console.error('[firewallController.createManualFirewallCommand error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to create firewall command'
      });
    }
  }
};

module.exports = firewallController;
