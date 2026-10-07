import apiClient from './apiClient';

/**
 * Agent Service — Client layer for Enterprise Agent Fleet Management.
 * Communicates with backend endpoints under /api/v1/admin/agents and /api/v1/agents.
 */
export const agentService = {
  /**
   * List enrolled enterprise agent devices for the authenticated admin's organization.
   * GET /api/v1/admin/agents
   *
   * @param {Object} [params]
   * @param {number} [params.limit=25] - Limit between 1 and 100
   * @param {number} [params.offset=0] - Non-negative offset
   * @param {'online'|'offline'|'disabled'|'pending'} [params.status] - Filter by device status
   * @returns {Promise<{ total: number, limit: number, offset: number, agents: Array }>}
   */
  async listAgents(params = {}) {
    const data = await apiClient.get('/admin/agents', { params });
    return data;
  },

  /**
   * Retrieve live status and telemetry for a specific agent device.
   * GET /api/v1/agents/:device_id/status
   *
   * @param {string} deviceId - UUID of the device
   * @returns {Promise<{ id: string, organization_id: string, user_id: string|null, device_name: string|null, hostname: string|null, os: string|null, platform: string|null, agent_version: string, status: string, last_heartbeat: string|null, created_at: string|null, last_heartbeat_age_seconds: number|null }>}
   */
  async getAgentStatus(deviceId) {
    const data = await apiClient.get(`/agents/${deviceId}/status`);
    return data;
  },

  /**
   * Generate a single-use cryptographically secure agent enrollment token.
   * POST /api/v1/admin/agents/tokens
   *
   * @param {Object} [payload]
   * @param {number} [payload.valid_for_hours=24] - Token validity window (default 24h, min 1)
   * @param {string} [payload.organization_id] - Optional organization UUID override
   * @returns {Promise<{ token: string, expires_at: string, organization_id: string }>}
   */
  async createEnrollmentToken(payload = {}) {
    const data = await apiClient.post('/admin/agents/tokens', payload);
    return data;
  },

  /**
   * Retrieve protected network targets safe list.
   * GET /api/v1/agents/:device_id/protected-targets
   *
   * @param {string} [deviceId='default']
   * @returns {Promise<{ protected_ips: string[], protected_ip_ranges: string[], protected_domains: string[], updated_at: string }>}
   */
  async getProtectedTargets(deviceId = 'default') {
    const data = await apiClient.get(`/agents/${deviceId}/protected-targets`);
    return data;
  },

  /**
   * Queue a low-level firewall instruction directly to an online agent.
   * POST /api/v1/admin/agents/:agent_id/firewall-commands
   *
   * @param {string} agentId
   * @param {Object} payload
   * @param {'block_ip'|'block_domain'} payload.command_type
   * @param {Object} payload.target_data
   * @param {string} [payload.reason]
   * @returns {Promise<{ success: boolean, command_id: string, status: string, agent_id: string, command: Object }>}
   */
  async sendFirewallCommand(agentId, payload) {
    const data = await apiClient.post(`/admin/agents/${agentId}/firewall-commands`, payload);
    return data;
  },
};

export default agentService;
