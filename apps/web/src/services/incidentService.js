import apiClient from './apiClient';

/**
 * Incident Management service for CYBERGUARD Gateway
 */
export const incidentService = {
  /**
   * List incidents with pagination and filtering
   * GET /api/v1/incidents
   */
  async listIncidents({ limit = 25, offset = 0, risk_level, status, threat_type } = {}) {
    const params = { limit, offset };

    if (risk_level && risk_level !== 'all') {
      params.risk_level = String(risk_level).toLowerCase();
    }
    if (status && status !== 'all') {
      params.status = status;
    }
    if (threat_type && threat_type !== 'all') {
      params.threat_type = threat_type;
    }

    const data = await apiClient.get('/incidents', { params });

    return {
      total: data?.total || 0,
      limit: data?.limit || limit,
      offset: data?.offset || offset,
      incidents: data?.incidents || data?.data || [],
    };
  },

  /**
   * Retrieve full details for a single incident
   * GET /api/v1/incidents/:id
   */
  async getIncident(id) {
    const data = await apiClient.get(`/incidents/${id}`);
    return data?.incident || data;
  },

  /**
   * Update incident triage resolution status (Admin only)
   * PATCH /api/v1/incidents/:id
   */
  async updateIncidentStatus(id, status) {
    const data = await apiClient.patch(`/incidents/${id}`, { status });
    return data?.incident || data;
  },

  /**
   * Update recommended mitigation action status (taken/dismissed)
   * PATCH /api/v1/actions/:id
   */
  async updateActionStatus(actionId, action_status) {
    const data = await apiClient.patch(`/actions/${actionId}`, { action_status });
    return data?.action || data;
  },

  /**
   * Retrieve full investigation workspace context
   * GET /api/v1/incidents/:id/workspace
   */
  async getWorkspace(id) {
    const data = await apiClient.get(`/incidents/${id}/workspace`);
    return data;
  },

  /**
   * Retrieve attack chain timeline and progression
   * GET /api/v1/incidents/:id/attack-chain
   */
  async getAttackChain(id) {
    const data = await apiClient.get(`/incidents/${id}/attack-chain`);
    return data;
  },

  /**
   * Retrieve attack chain graph visualization payload
   * GET /api/v1/incidents/:id/attack-chain/graph
   */
  async getAttackChainGraph(id) {
    const data = await apiClient.get(`/incidents/${id}/attack-chain/graph`);
    return data;
  },

  /**
   * Retrieve correlated / related incidents
   * GET /api/v1/incidents/:id/related
   */
  async getRelatedIncidents(id) {
    const data = await apiClient.get(`/incidents/${id}/related`);
    return data;
  },

  /**
   * Append an analyst note to the incident investigation
   * POST /api/v1/incidents/:id/notes
   */
  async addNote(id, note) {
    const data = await apiClient.post(`/incidents/${id}/notes`, { note });
    return data?.note || data;
  },

  /**
   * Assign incident to an analyst
   * POST /api/v1/incidents/:id/assign
   */
  async assignIncident(id, user_id) {
    const data = await apiClient.post(`/incidents/${id}/assign`, { user_id });
    return data?.incident || data;
  },

  /**
   * Escalate incident to P1 priority
   * POST /api/v1/incidents/:id/escalate
   */
  async escalateIncident(id, reason) {
    const payload = reason ? { reason } : {};
    const data = await apiClient.post(`/incidents/${id}/escalate`, payload);
    return data?.incident || data;
  },

  /**
   * Mark incident as resolved
   * POST /api/v1/incidents/:id/resolve
   */
  async resolveIncident(id) {
    const data = await apiClient.post(`/incidents/${id}/resolve`, {});
    return data?.incident || data;
  },

  /**
   * Reopen a resolved incident to open status
   * POST /api/v1/incidents/:id/reopen
   */
  async reopenIncident(id, reason) {
    const payload = reason ? { reason } : {};
    const data = await apiClient.post(`/incidents/${id}/reopen`, payload);
    return data?.incident || data;
  },
};

export default incidentService;
