import apiClient from './apiClient';

/**
 * Enterprise Attack Surface Discovery Service for CYBERGUARD SOC
 */
export const attackSurfaceService = {
  /**
   * Fetch top-level dashboard metrics (summary cards, risk distribution, category breakdown, top risky assets)
   */
  async getDashboard() {
    try {
      return await apiClient.get('/attack-surface/dashboard');
    } catch (err) {
      // Fallback to /admin prefix if needed
      return await apiClient.get('/admin/attack-surface/dashboard');
    }
  },

  /**
   * Fetch paginated and filtered exposure inventory
   */
  async getExposures({
    status = 'active',
    severity,
    port,
    rule_id,
    device_id,
    search,
    limit = 25,
    offset = 0,
  } = {}) {
    const params = { limit, offset };
    if (status && status !== 'all') params.status = status;
    if (severity && severity !== 'all') params.severity = severity.toLowerCase();
    if (port) params.port = port;
    if (rule_id && rule_id !== 'all') params.rule_id = rule_id;
    if (device_id) params.device_id = device_id;
    if (search) params.search = search;

    try {
      return await apiClient.get('/attack-surface/exposures', { params });
    } catch (err) {
      return await apiClient.get('/admin/attack-surface/exposures', { params });
    }
  },

  /**
   * Fetch full details for a single exposure finding
   */
  async getExposureById(id) {
    try {
      return await apiClient.get(`/attack-surface/exposures/${id}`);
    } catch (err) {
      return await apiClient.get(`/admin/attack-surface/exposures/${id}`);
    }
  },

  /**
   * Fetch time-series and category breakdown analytics
   */
  async getAnalytics(days = 14) {
    const params = { days };
    try {
      return await apiClient.get('/attack-surface/analytics', { params });
    } catch (err) {
      return await apiClient.get('/admin/attack-surface/analytics', { params });
    }
  },

  /**
   * Fetch paginated fleet scan history
   */
  async getScans({ limit = 20, offset = 0, device_id } = {}) {
    const params = { limit, offset };
    if (device_id) params.device_id = device_id;

    try {
      return await apiClient.get('/attack-surface/scans', { params });
    } catch (err) {
      return await apiClient.get('/admin/attack-surface/scans', { params });
    }
  },

  /**
   * Trigger fleet or asset attack surface discovery scan
   */
  async triggerScan({ device_id, target_scope = 'all', options = {} } = {}) {
    const payload = { device_id, target_scope, options };
    try {
      return await apiClient.post('/attack-surface/scan', payload);
    } catch (err) {
      return await apiClient.post('/admin/attack-surface/scan', payload);
    }
  },

  /**
   * Fetch proposed/shadow response actions
   */
  async listResponseActions({ status, incident_id, limit = 25, offset = 0 } = {}) {
    const params = { limit, offset };
    if (status && status !== 'all') params.status = status;
    if (incident_id) params.incident_id = incident_id;

    try {
      return await apiClient.get('/response-actions', { params });
    } catch (err) {
      return await apiClient.get('/admin/response-actions', { params });
    }
  },

  /**
   * Approve or reject a shadow response action (analyst decision)
   */
  async updateResponseAction(id, { action, reason }) {
    const payload = { action, reason };
    try {
      return await apiClient.patch(`/response-actions/${id}`, payload);
    } catch (err) {
      return await apiClient.patch(`/admin/attack-surface/response-actions/${id}`, payload);
    }
  },

  /**
   * Update incident status, notes, or analyst assignment
   */
  async updateIncident(id, { status, assigned_to_id, note }) {
    const payload = {};
    if (status) payload.status = status;
    if (assigned_to_id) payload.assigned_to_id = assigned_to_id;
    if (note) payload.note = note;

    try {
      return await apiClient.patch(`/incidents/${id}`, payload);
    } catch (err) {
      return await apiClient.patch(`/admin/attack-surface/incidents/${id}`, payload);
    }
  },
};

export default attackSurfaceService;
