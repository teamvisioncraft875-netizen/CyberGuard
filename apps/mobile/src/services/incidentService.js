import { apiClient } from './apiClient';

export const incidentService = {
  async getIncidents(params = {}) {
    const query = new URLSearchParams();
    if (params.limit !== undefined) query.append('limit', String(params.limit));
    if (params.offset !== undefined) query.append('offset', String(params.offset));
    if (params.risk_level) query.append('risk_level', params.risk_level);
    if (params.status) query.append('status', params.status);
    if (params.threat_type) query.append('threat_type', params.threat_type);

    const queryString = query.toString();
    const endpoint = `/incidents${queryString ? `?${queryString}` : ''}`;
    const response = await apiClient.get(endpoint);

    // Backend provides incidents in either response.incidents or response.data
    const list = response.incidents || response.data || [];
    return {
      incidents: list,
      total: response.total || list.length,
      limit: response.limit || 25,
      offset: response.offset || 0
    };
  },

  async getIncidentById(id) {
    if (!id) throw new Error('Incident ID is required');
    return await apiClient.get(`/incidents/${id}`);
  }
};
