const agentService = require('../services/agentService');

/**
 * Agent Model — Thin wrapper around agentService for Enterprise Agent v1 foundation.
 * Exposes core lifecycle and command delegation methods.
 */
const Agent = {
  /**
   * Generates a one-time enrollment token for an organization.
   */
  async generateEnrollmentToken(organization_id, valid_for_hours = 24) {
    return agentService.generateEnrollmentToken(organization_id, valid_for_hours);
  },

  /**
   * Enrolls a device with an enrollment token.
   */
  async enrollDevice(params) {
    return agentService.enrollDevice(params);
  },

  /**
   * Records a device heartbeat.
   */
  async recordHeartbeat(device_id, credential_id, credential_secret, meta) {
    return agentService.recordHeartbeat(device_id, credential_id, credential_secret, meta);
  },

  /**
   * Fetches pending commands for a device.
   */
  async getCommands(device_id, credential_id, credential_secret) {
    return agentService.getCommandsForDevice(device_id, credential_id, credential_secret);
  },

  /**
   * Records the result of an executed command.
   */
  async recordCommandResult(device_id, command_id, status, result, credential_id, credential_secret) {
    return agentService.recordCommandResult(device_id, command_id, status, result, credential_id, credential_secret);
  },

  /**
   * Retrieves device status and heartbeat age.
   */
  async getStatus(device_id, organization_id) {
    return agentService.getDeviceStatus(device_id, organization_id);
  }
};

module.exports = Agent;
