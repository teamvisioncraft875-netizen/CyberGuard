const agentService = require('../services/agentService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Agent Controller — Endpoints consumed by Enterprise Guard Agents and Admins.
 */
const agentController = {
  /**
   * POST /api/v1/agents/enroll
   * Enrolls a new enterprise device using a one-time enrollment token.
   * Plaintext credential_secret is returned ONCE and never stored or returned again.
   */
  async enroll(req, res) {
    const { enrollment_token, hostname, os, platform, linked_user_id, agent_version } = req.body;

    if (!enrollment_token || typeof enrollment_token !== 'string' || !enrollment_token.trim()) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'enrollment_token is required'
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
        hostname: hostname || 'unknown-host',
        os: os || 'unknown-os',
        platform: platform || 'desktop',
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
      console.error('[agentController.enroll error]', err);
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
    const credential_id = req.body.credential_id || req.headers['x-agent-credential-id'];
    const credential_secret = req.body.credential_secret || req.headers['x-agent-credential-secret'];
    const { agent_version, network_connections_count } = req.body;

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    if (!credential_id || !credential_secret) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'credential_id and credential_secret are required'
      });
    }

    try {
      const result = await agentService.recordHeartbeat(
        device_id,
        credential_id,
        credential_secret,
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
      console.error('[agentController.heartbeat error]', err);
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
    const credential_id = req.query.credential_id || req.headers['x-agent-credential-id'] || req.body?.credential_id;
    const credential_secret = req.query.credential_secret || req.headers['x-agent-credential-secret'] || req.body?.credential_secret;

    if (!device_id || !UUID_REGEX.test(device_id)) {
      return res.status(400).json({
        error: 'INVALID_DEVICE_ID',
        message: 'Valid device UUID is required'
      });
    }

    if (!credential_id || !credential_secret) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'credential_id and credential_secret are required'
      });
    }

    try {
      const commands = await agentService.getCommandsForDevice(device_id, credential_id, credential_secret);
      if (commands === null) {
        return res.status(401).json({
          error: 'UNAUTHORIZED',
          message: 'Invalid agent credentials'
        });
      }

      return res.status(200).json({
        commands
      });
    } catch (err) {
      console.error('[agentController.getCommands error]', err);
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
    const credential_id = req.body.credential_id || req.headers['x-agent-credential-id'];
    const credential_secret = req.body.credential_secret || req.headers['x-agent-credential-secret'];
    const { status, result } = req.body;

    if (!device_id || !UUID_REGEX.test(device_id) || !command_id || !UUID_REGEX.test(command_id)) {
      return res.status(400).json({
        error: 'INVALID_IDENTIFIERS',
        message: 'Valid device_id and command_id UUIDs are required'
      });
    }

    if (!credential_id || !credential_secret) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'credential_id and credential_secret are required'
      });
    }

    try {
      const success = await agentService.recordCommandResult(
        device_id,
        command_id,
        status || 'completed',
        result || {},
        credential_id,
        credential_secret
      );

      if (!success) {
        return res.status(401).json({
          error: 'UNAUTHORIZED_OR_NOT_FOUND',
          message: 'Failed to record command result: invalid credentials or command not found'
        });
      }

      return res.status(200).json({
        success: true
      });
    } catch (err) {
      console.error('[agentController.recordCommandResult error]', err);
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
      console.error('[agentController.getStatus error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve device status'
      });
    }
  }
};

module.exports = agentController;
