const agentService = require('../services/agentService');
const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VALID_COMMAND_STATUSES = new Set(['completed', 'failed', 'received_not_executed']);

/**
 * Agent Controller — Endpoints consumed by Enterprise Guard Agents and Admins.
 */
const agentController = {
  /**
   * POST /api/v1/admin/agents/tokens
   * Generates a single-use enrollment token for an enterprise organization.
   * Admin-only endpoint.
   */
  async createEnrollmentToken(req, res) {
    const { organization_id, valid_for_hours } = req.body || {};
    const targetOrgId = organization_id || req.user?.organization_id;

    if (!targetOrgId || typeof targetOrgId !== 'string' || !UUID_REGEX.test(targetOrgId)) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'Valid organization_id UUID is required'
      });
    }

    // Tenant boundary: Admin can only issue tokens for their assigned organization
    if (req.user?.organization_id && req.user.organization_id !== targetOrgId && req.user.role !== 'superadmin') {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'You cannot generate enrollment tokens for another organization'
      });
    }

    try {
      const result = await agentService.generateEnrollmentToken(targetOrgId, valid_for_hours || 24, true);
      const token = typeof result === 'string' ? result : result.token;
      const expires_at = (typeof result === 'object' && result.expires_at)
        ? result.expires_at
        : new Date(Date.now() + (valid_for_hours || 24) * 3600 * 1000).toISOString();
      const orgId = (typeof result === 'object' && result.organization_id) ? result.organization_id : targetOrgId;

      return res.status(201).json({
        token,
        expires_at,
        organization_id: orgId
      });
    } catch (err) {
      console.error('[agentController.createEnrollmentToken error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to generate agent enrollment token'
      });
    }
  },

  /**
   * POST /api/v1/agents/enroll
   * Enrolls a new enterprise device using a one-time enrollment token.
   * Plaintext credential_secret is returned ONCE and never stored or returned again.
   */
  async enroll(req, res) {
    const { enrollment_token, hostname, os, platform, linked_user_id, agent_version } = req.body || {};

    if (!enrollment_token || typeof enrollment_token !== 'string' || !enrollment_token.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'enrollment_token is required and must be a non-empty string'
      });
    }

    if (!hostname || typeof hostname !== 'string' || !hostname.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'hostname is required and must be a non-empty string'
      });
    }

    if (os !== undefined && (typeof os !== 'string' || !os.trim())) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'os must be a non-empty string'
      });
    }

    if (platform !== undefined && (typeof platform !== 'string' || !platform.trim())) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'platform must be a non-empty string'
      });
    }

    try {
      // Check if token exists and is valid
      const orgId = await agentService.validateEnrollmentToken(enrollment_token);
      if (!orgId) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'Invalid or expired enrollment token'
        });
      }

      const enrolled = await agentService.enrollDevice({
        token: enrollment_token,
        hostname: hostname.trim(),
        os: os.trim(),
        platform: platform.trim(),
        linked_user_id: linked_user_id || null,
        agent_version: agent_version || '1.0.0'
      });

      if (!enrolled) {
        return res.status(401).json({
          error: 'ENROLLMENT_FAILED',
          message: 'Failed to enroll device with provided token'
        });
      }

      return res.status(201).json({
        device_id: enrolled.device_id,
        credential_id: enrolled.credential_id,
        credential_secret: enrolled.credential_secret,
        organization_id: enrolled.organization_id
      });
    } catch (err) {
      console.error('[agentController.enroll error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Error during agent enrollment'
      });
    }
  },

  /**
   * POST /api/v1/agents/:device_id/heartbeat
   * Authenticates agent via credential_id + secret and updates online status.
   */
  async heartbeat(req, res) {
    const { device_id } = req.params;
    const credential_id = req.body?.credential_id || req.headers['x-agent-credential-id'];
    const credential_secret = req.body?.credential_secret || req.headers['x-agent-credential-secret'];
    const { agent_version, network_connections_count } = req.body || {};

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    if (!credential_id || typeof credential_id !== 'string' || !credential_id.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_id is required and must be a non-empty string'
      });
    }

    if (!credential_secret || typeof credential_secret !== 'string' || !credential_secret.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_secret is required and must be a non-empty string'
      });
    }

    try {
      const result = await agentService.recordHeartbeat(
        device_id,
        credential_id.trim(),
        credential_secret.trim(),
        { agent_version, network_connections_count }
      );

      if (!result) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'Invalid agent credentials or device disabled'
        });
      }

      return res.status(200).json({
        status: result.status,
        next_heartbeat_in_seconds: result.next_heartbeat_in_seconds,
        commands_pending: result.commands_pending
      });
    } catch (err) {
      console.error('[agentController.heartbeat error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to record heartbeat'
      });
    }
  },

  /**
   * GET /api/v1/agents/:device_id/commands
   * Fetches pending instructions queued for this device.
   */
  async getCommands(req, res) {
    const { device_id } = req.params;
    const credential_id = req.query?.credential_id || req.headers['x-agent-credential-id'] || req.body?.credential_id;
    const credential_secret = req.query?.credential_secret || req.headers['x-agent-credential-secret'] || req.body?.credential_secret;

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    if (!credential_id || typeof credential_id !== 'string' || !UUID_REGEX.test(credential_id.trim())) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_id is required and must be a valid UUID'
      });
    }

    if (!credential_secret || typeof credential_secret !== 'string' || !credential_secret.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_secret is required and must be a non-empty string'
      });
    }

    try {
      const commandsResult = await agentService.getCommandsWithProtectedTargets(device_id, credential_id.trim(), credential_secret.trim());
      if (commandsResult === null) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'Invalid agent credentials'
        });
      }

      return res.status(200).json({
        commands: commandsResult.commands,
        protected_targets: commandsResult.protected_targets
      });
    } catch (err) {
      console.error('[agentController.getCommands error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve agent commands'
      });
    }
  },

  /**
   * POST /api/v1/agents/:device_id/commands/:command_id/result
   * Reports execution result for a dispatched command.
   */
  async recordCommandResult(req, res) {
    const { device_id, command_id } = req.params;
    const credential_id = req.body?.credential_id || req.headers['x-agent-credential-id'];
    const credential_secret = req.body?.credential_secret || req.headers['x-agent-credential-secret'];
    const { status, result } = req.body || {};

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    if (!command_id || !UUID_REGEX.test(command_id)) {
      return res.status(400).json({
        error: 'INVALID_COMMAND_ID',
        message: 'Valid command UUID is required'
      });
    }

    if (!credential_id || typeof credential_id !== 'string' || !UUID_REGEX.test(credential_id.trim())) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_id is required and must be a valid UUID'
      });
    }

    if (!credential_secret || typeof credential_secret !== 'string' || !credential_secret.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'credential_secret is required and must be a non-empty string'
      });
    }

    if (!status || typeof status !== 'string' || !VALID_COMMAND_STATUSES.has(status.trim())) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: `status is required and must be one of: ${Array.from(VALID_COMMAND_STATUSES).join(', ')}`
      });
    }

    try {
      const success = await agentService.recordCommandResult(
        device_id,
        command_id,
        status.trim(),
        result || {},
        credential_id.trim(),
        credential_secret.trim()
      );

      if (!success) {
        return res.status(401).json({
          error: 'UNAUTHORIZED_OR_NOT_FOUND',
          message: 'Failed to record command result: invalid credentials or command not found'
        });
      }

      // Phase C Integration: If command is firewall-related, record/sync in agent_firewall_rules
      try {
        const cmdRes = await db.query(
          `SELECT command_type, target_data FROM public.agent_commands WHERE id = $1;`,
          [command_id]
        );
        if (cmdRes.rows && cmdRes.rows.length > 0) {
          const cmdRow = cmdRes.rows[0];
          if (['block_ip', 'block_domain', 'temporary_block_ip'].includes(cmdRow.command_type)) {
            const firewallService = require('../services/firewallService');
            const targetData = typeof cmdRow.target_data === 'string'
              ? JSON.parse(cmdRow.target_data)
              : (cmdRow.target_data || {});

            await firewallService.createFirewallRuleFromCommandResult(
              device_id,
              cmdRow.command_type,
              targetData,
              result || {},
              command_id
            );
          } else if (['delete_firewall_rule', 'unblock_ip', 'unblock_domain'].includes(cmdRow.command_type)) {
            const firewallService = require('../services/firewallService');
            const targetData = typeof cmdRow.target_data === 'string'
              ? JSON.parse(cmdRow.target_data)
              : (cmdRow.target_data || {});

            await firewallService.recordFirewallRuleDeletionResult(
              device_id,
              targetData,
              result || {},
              status.trim()
            );
          }
        }
      } catch (fwSyncErr) {
        console.warn('[agentController] Warning: Failed to sync firewall rule from command result:', fwSyncErr.message);
      }

      return res.status(200).json({
        success: true
      });
    } catch (err) {
      console.error('[agentController.recordCommandResult error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to record command result'
      });
    }
  },

  /**
   * GET /api/v1/agents/:device_id/status
   * Supports both Admin User (JWT with tenant scoping) and Agent checking status.
   */
  async getStatus(req, res) {
    const { device_id } = req.params;

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    try {
      const orgId = req.user?.organization_id || null;
      const device = await agentService.getDeviceStatus(device_id, orgId);

      if (!device) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Device not found'
        });
      }

      return res.status(200).json(device);
    } catch (err) {
      console.error('[agentController.getStatus error]', err.message);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve device status'
      });
    }
  },

  /**
   * GET /api/v1/agents/:device_id/protected-targets
   * Public endpoint for agents to fetch live protected targets list for validation.
   * No auth required so agents can retrieve live safe targets on startup and periodically.
   */
  async getProtectedTargets(req, res) {
    try {
      const firewallService = require('../services/firewallService');
      const targets = firewallService.getProtectedTargets();
      return res.status(200).json(targets);
    } catch (err) {
      console.error('[agentController.getProtectedTargets error]', err.message);
      // Graceful fallback: return safe static baseline list
      return res.status(200).json({
        protected_ips: ['127.0.0.1', '0.0.0.0', '::1', '::'],
        protected_ip_ranges: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16'],
        protected_domains: ['localhost', 'cyberguard.local'],
        updated_at: new Date().toISOString()
      });
    }
  }
};

agentController.updateCommandResult = agentController.recordCommandResult;

module.exports = agentController;
