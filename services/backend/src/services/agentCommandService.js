const db = require('../config/db');
const firewallService = require('./firewallService');
const FirewallRule = require('../models/FirewallRule');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Agent Command Service — Bridge between incident response actions/policy engine
 * and the enterprise agent command queue (public.agent_commands).
 */
const agentCommandService = {
  /**
   * Converts an approved response_action into an agent_command queued for execution.
   *
   * @param {Object} response_action - Row from public.response_actions
   * @param {string} [target_device_id] - Device UUID to receive the command
   * @returns {Promise<{ success: boolean, command_id?: string, status?: string, error?: string, command?: Object }>}
   */
  async createAgentCommandFromResponseAction(response_action, target_device_id = null) {
    if (!response_action || typeof response_action !== 'object') {
      return { success: false, error: 'Valid response_action object is required' };
    }

    const { organization_id, action_type } = response_action;
    const rawTarget = typeof response_action.target === 'string'
      ? JSON.parse(response_action.target || '{}')
      : (response_action.target || {});

    // Resolve target device ID
    let deviceId = target_device_id || response_action.target_device_id || rawTarget.target_device_id || rawTarget.device_id || null;

    // If deviceId not specified directly, attempt to resolve via user_id in target
    if (!deviceId && rawTarget.user_id && UUID_REGEX.test(rawTarget.user_id)) {
      const devRes = await db.query(
        `SELECT id FROM public.devices 
         WHERE user_id = $1 AND organization_id = $2 AND status != 'disabled' 
         ORDER BY last_heartbeat DESC NULLS LAST LIMIT 1;`,
        [rawTarget.user_id, organization_id]
      );
      if (devRes.rows && devRes.rows.length > 0) {
        deviceId = devRes.rows[0].id;
      }
    }

    if (!deviceId || !UUID_REGEX.test(deviceId)) {
      return {
        success: false,
        error: 'target_device_id_required',
        message: 'A valid target_device_id is required to queue an agent command'
      };
    }

    // Verify device exists and belongs to same organization
    const deviceCheck = await db.query(
      `SELECT id, organization_id, hostname, status FROM public.devices WHERE id = $1;`,
      [deviceId]
    );

    if (!deviceCheck.rows || deviceCheck.rows.length === 0) {
      return {
        success: false,
        error: 'device_not_found',
        message: `Target device ${deviceId} not found`
      };
    }

    const device = deviceCheck.rows[0];
    if (device.organization_id !== organization_id) {
      return {
        success: false,
        error: 'tenant_mismatch',
        message: 'Target device does not belong to the response action organization'
      };
    }

    // Map action_type to agent command_type
    const commandTypeMap = {
      'block_ip': 'block_ip',
      'block_domain': 'block_domain',
      'temporary_block_ip': 'temporary_block_ip',
      'unblock_ip': 'unblock_ip',
      'unblock_domain': 'unblock_domain',
      'collect_snapshot': 'collect_snapshot',
      'refresh_policy': 'refresh_policy'
    };

    const commandType = commandTypeMap[action_type];
    if (!commandType) {
      return {
        success: false,
        error: 'unsupported_action_type',
        message: `Action type '${action_type}' cannot be converted to an agent command`
      };
    }

    // Normalize target_data
    const targetData = {};
    if (commandType === 'block_ip' || commandType === 'temporary_block_ip' || commandType === 'unblock_ip') {
      const ip = rawTarget.ip_address || rawTarget.ip || rawTarget.target;
      if (!ip) {
        return { success: false, error: 'missing_ip_address', message: 'Target IP address missing in action payload' };
      }
      targetData.ip_address = ip;
      if (rawTarget.duration_minutes) {
        targetData.duration_minutes = rawTarget.duration_minutes;
      }
    } else if (commandType === 'block_domain' || commandType === 'unblock_domain') {
      const domain = rawTarget.domain || rawTarget.target;
      if (!domain) {
        return { success: false, error: 'missing_domain', message: 'Target domain missing in action payload' };
      }
      targetData.domain = domain;
    }

    // Defense-in-depth: Validate target input against protected targets
    let canExecute = true;
    let validationError = null;

    if (commandType === 'block_ip' || commandType === 'block_domain') {
      const validation = firewallService.validateFirewallInput(commandType, targetData);
      if (!validation.valid) {
        canExecute = false;
        validationError = validation.error;
      }
    }

    const requestedById = response_action.approved_by_id || response_action.requested_by_id || null;

    // Enqueue command in public.agent_commands
    const insertSql = `
      INSERT INTO public.agent_commands (
        device_id,
        organization_id,
        command_type,
        target_data,
        status,
        requested_by_id,
        can_execute,
        validation_error,
        requires_approval,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      RETURNING id, device_id, organization_id, command_type, target_data, status, can_execute, created_at;
    `;

    const cmdRes = await db.query(insertSql, [
      deviceId,
      organization_id,
      commandType,
      JSON.stringify(targetData),
      canExecute ? 'pending' : 'failed',
      requestedById,
      canExecute,
      validationError,
      false // Already approved through response action workflow
    ]);

    const command = cmdRes.rows[0];

    // Ensure tracking record in agent_firewall_rules if this is a firewall block command
    if ((commandType === 'block_ip' || commandType === 'block_domain') && canExecute) {
      try {
        const targetIp = targetData.ip_address || null;
        const targetDomain = targetData.domain || null;

        // Check if an existing rule entry exists
        const existingRule = await db.query(
          `SELECT id FROM public.agent_firewall_rules
           WHERE agent_id = $1 AND (target_ip = $2 OR target_domain = $3)
             AND status IN ('pending', 'active') LIMIT 1;`,
          [deviceId, targetIp, targetDomain]
        );

        if (!existingRule.rows || existingRule.rows.length === 0) {
          await FirewallRule.create({
            agent_id: deviceId,
            organization_id,
            rule_type: commandType,
            target_ip: targetIp,
            target_domain: targetDomain,
            status: 'pending',
            created_by_id: requestedById,
            result: {
              source: 'response_action',
              response_action_id: response_action.id,
              command_id: command.id,
              initiated_at: new Date().toISOString()
            }
          });
        }
      } catch (fwErr) {
        console.warn('[agentCommandService] Warning: Failed to mirror rule to agent_firewall_rules:', fwErr.message);
      }
    }

    return {
      success: true,
      command_id: command.id,
      status: command.status,
      command
    };
  },

  /**
   * Retrieves active pending or executing commands for a device.
   * Validates device credential ID.
   *
   * @param {string} device_id
   * @param {string} credential_id
   * @returns {Promise<Array<Object>|null>}
   */
  async getAgentCommandsForDevice(device_id, credential_id) {
    if (!device_id || !credential_id) return null;
    if (!UUID_REGEX.test(device_id) || !UUID_REGEX.test(credential_id)) return null;

    try {
      const devRes = await db.query(
        `SELECT id FROM public.devices WHERE id = $1 AND agent_credentials_id = $2 AND status != 'disabled';`,
        [device_id, credential_id]
      );

      if (!devRes.rows || devRes.rows.length === 0) {
        return null;
      }

      const cmdRes = await db.query(
        `SELECT id, command_type, target_data, status, can_execute, created_at
         FROM public.agent_commands
         WHERE device_id = $1 AND status IN ('pending', 'executing')
         ORDER BY created_at ASC;`,
        [device_id]
      );

      return cmdRes.rows || [];
    } catch (err) {
      console.error('[agentCommandService.getAgentCommandsForDevice Error]', err.message);
      return [];
    }
  },

  /**
   * Updates command execution status and synchronizes the rule status in agent_firewall_rules.
   *
   * @param {string} command_id
   * @param {'completed'|'failed'} status
   * @param {Object} [result={}]
   * @returns {Promise<{ success: boolean, command?: Object }>}
   */
  async updateAgentCommandStatus(command_id, status, result = {}) {
    if (!command_id || !UUID_REGEX.test(command_id)) {
      return { success: false, error: 'invalid_command_id' };
    }

    const cleanStatus = status === 'completed' ? 'completed' : 'failed';

    try {
      const updateCmdSql = `
        UPDATE public.agent_commands
        SET status = $1,
            result = $2,
            executed_at = NOW()
        WHERE id = $3
        RETURNING *;
      `;

      const cmdRes = await db.query(updateCmdSql, [
        cleanStatus,
        typeof result === 'string' ? result : JSON.stringify(result || {}),
        command_id
      ]);

      if (!cmdRes.rows || cmdRes.rows.length === 0) {
        return { success: false, error: 'command_not_found' };
      }

      const command = cmdRes.rows[0];
      const targetData = typeof command.target_data === 'string'
        ? JSON.parse(command.target_data || '{}')
        : (command.target_data || {});

      const targetIp = targetData.ip_address || targetData.ip || null;
      const targetDomain = targetData.domain || null;
      const ruleName = result.rule_name || null;

      // Synchronize with agent_firewall_rules
      if (command.command_type === 'block_ip' || command.command_type === 'block_domain') {
        const newRuleStatus = cleanStatus === 'completed' ? 'active' : 'failed';
        await db.query(
          `UPDATE public.agent_firewall_rules
           SET status = $1,
               rule_id_local = COALESCE($2, rule_id_local),
               result = result || $3::jsonb
           WHERE agent_id = $4
             AND (target_ip = $5 OR target_domain = $6)
             AND status = 'pending';`,
          [
            newRuleStatus,
            ruleName,
            JSON.stringify({ agent_execution: result, updated_at: new Date().toISOString() }),
            command.device_id,
            targetIp,
            targetDomain
          ]
        );
      }

      return { success: true, command };
    } catch (err) {
      console.error('[agentCommandService.updateAgentCommandStatus Error]', err.message);
      return { success: false, error: err.message };
    }
  }
};

module.exports = agentCommandService;
