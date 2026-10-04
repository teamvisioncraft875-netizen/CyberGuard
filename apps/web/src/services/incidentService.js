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
};

export default incidentService;
