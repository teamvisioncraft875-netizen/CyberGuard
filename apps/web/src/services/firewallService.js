import apiClient from './apiClient';

/**
 * Firewall Service — Client layer for CyberGuard Host Firewall Administration.
 * Wraps backend endpoints mounted under /api/v1/admin/firewall-rules and /api/v1/admin/agents.
 */
export const firewallService = {
  /**
   * List organization firewall rules with optional filters and pagination.
   * GET /api/v1/admin/firewall-rules
   *
   * @param {Object} [params]
   * @param {string} [params.agent_id] - Filter rules for specific agent device UUID
   * @param {string} [params.status] - Filter by status: 'pending', 'active', 'pending_delete', 'deleted'
   * @param {string} [params.rule_type] - Filter by type: 'block_ip', 'block_domain'
   * @param {number} [params.limit=50] - Number of items to retrieve (1-100)
   * @param {number} [params.offset=0] - Offset index
   * @returns {Promise<{ total: number, limit: number, offset: number, rules: Array }>}
   */
  async listRules(params = {}) {
    const data = await apiClient.get('/admin/firewall-rules', { params });
    return data;
  },

  /**
   * Pre-flight validation of candidate IP address or domain against protected network baselines.
   * POST /api/v1/admin/firewall-rules/validate
   *
   * @param {Object} payload
   * @param {'block_ip'|'block_domain'} payload.rule_type
   * @param {Object} payload.target_data - e.g. { ip_address: '198.51.100.24' } or { domain: 'malicious.com' }
   * @returns {Promise<{ valid: boolean, error_if_invalid: string|null, error: string|null, target_ip: string|null, target_domain: string|null }>}
   */
  async validateRule({ rule_type, target_data }) {
    const data = await apiClient.post('/admin/firewall-rules/validate', {
      rule_type,
      target_data,
    });
    return data;
  },

  /**
   * Create a new host firewall rule in 'pending' status and queue agent command.
   * POST /api/v1/admin/firewall-rules
   *
   * @param {Object} payload
   * @param {string} payload.agent_id - Target agent device UUID
   * @param {'block_ip'|'block_domain'} payload.rule_type
   * @param {Object} payload.target_data - e.g. { ip_address: '198.51.100.24' } or { domain: 'c2-beacon.com' }
   * @returns {Promise<{ success: boolean, rule_id: string, status: string, rule: Object, validation_result: Object }>}
   */
  async createRule({ agent_id, rule_type, target_data }) {
    const data = await apiClient.post('/admin/firewall-rules', {
      agent_id,
      rule_type,
      target_data,
    });
    return data;
  },

  /**
   * Revoke a firewall rule by ID (transitions status to 'pending_delete' and queues agent unblock).
   * DELETE /api/v1/admin/firewall-rules/:rule_id
   *
   * @param {string} ruleId - UUID of the firewall rule
   * @returns {Promise<{ deleted: boolean, rule_id: string, status: string, agent_notified: boolean, command_id: string|null }>}
   */
  async deleteRule(ruleId) {
    const data = await apiClient.delete(`/admin/firewall-rules/${ruleId}`);
    return data;
  },

  /**
   * List enrolled enterprise agent devices for the authenticated admin's organization.
   * GET /api/v1/admin/agents
   *
   * @param {Object} [params]
   * @param {number} [params.limit=100]
   * @param {number} [params.offset=0]
   * @param {'online'|'offline'|'disabled'|'pending'} [params.status]
   * @returns {Promise<{ total: number, limit: number, offset: number, agents: Array }>}
   */
  async listAgents(params = {}) {
    const data = await apiClient.get('/admin/agents', { params });
    return data;
  },

  /**
   * Retrieve protected network targets (IPs, CIDR ranges, and domains) that cannot be blocked.
   * GET /api/v1/agents/:device_id/protected-targets
   *
   * @param {string} [deviceId='default']
   * @returns {Promise<{ protected_ips: string[], protected_ip_ranges: string[], protected_domains: string[] }>}
   */
  async getProtectedTargets(deviceId = 'default') {
    const data = await apiClient.get(`/agents/${deviceId}/protected-targets`);
    return data;
  },

  /**
   * Queue manual ad-hoc firewall instruction directly to an online agent.
   * POST /api/v1/admin/agents/:agent_id/firewall-commands
   *
   * @param {string} agentId
   * @param {Object} payload
   * @param {'block_ip'|'block_domain'} payload.command_type
   * @param {Object} payload.target_data
   * @param {string} [payload.reason]
   * @returns {Promise<{ success: boolean, command_id: string, status: string, agent_id: string, command: Object }>}
   */
  async createManualCommand(agentId, { command_type, target_data, reason }) {
    const data = await apiClient.post(`/admin/agents/${agentId}/firewall-commands`, {
      command_type,
      target_data,
      reason,
    });
    return data;
  },
};

export default firewallService;
