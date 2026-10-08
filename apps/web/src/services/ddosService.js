import apiClient from './apiClient';

/**
 * DDoS Service — Client layer for DDoS Heuristic Scan & Threat Intelligence.
 * Communicates with backend endpoints under /api/v1/admin/ddos.
 */
export const ddosService = {
  /**
   * Triggers a manual DDoS heuristic detection scan.
   * POST /api/v1/admin/ddos/scan
   *
   * @param {Object} payload
   * @param {'request_spike'|'post_flood'|'login_abuse'|'ip_flooding'|'distributed_ddos'} payload.scan_type - Required scan pattern
   * @param {string} [payload.endpoint] - Optional target endpoint URL (e.g. '/api/v1/auth/login')
   * @param {number} [payload.window_minutes] - Optional time window in minutes (defaults: 15 for login_abuse, 5 for others)
   * @returns {Promise<{ metric_type: string, threats: Array<Object>, incidents_created: number }>}
   */
  async runScan(payload) {
    const data = await apiClient.post('/admin/ddos/scan', payload);
    return data;
  },

  /**
   * Retrieves paginated historical and active DDoS threat observations scoped to the organization.
   * GET /api/v1/admin/ddos/threats
   *
   * @param {Object} [params]
   * @param {'request_spike'|'post_flood'|'login_abuse'|'ip_flooding'|'distributed_ddos'} [params.scan_type] - Filter by metric type
   * @param {'request_spike'|'post_flood'|'login_abuse'|'ip_flooding'|'distributed_ddos'} [params.metric_type] - Filter alias
   * @param {number} [params.limit=50] - Items per page (1-100)
   * @param {number} [params.offset=0] - Offset index
   * @returns {Promise<{ threats: Array<Object>, total: number }>}
   */
  async getThreats(params = {}) {
    const data = await apiClient.get('/admin/ddos/threats', { params });
    return data;
  },
};

export default ddosService;
