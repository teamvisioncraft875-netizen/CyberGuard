import apiClient from './apiClient';

/**
 * Analytics and Reporting service for CYBERGUARD Gateway
 */
export const analyticsService = {
  /**
   * Aggregate KPI counts and threat distribution overview
   * GET /api/v1/analytics/overview
   */
  async getOverview() {
    const data = await apiClient.get('/analytics/overview');
    return {
      total_incidents: data?.total_incidents || 0,
      active_threats: data?.active_threats || 0,
      resolved_threats: data?.resolved_threats || 0,
      risk_breakdown: data?.risk_breakdown || {
        Safe: 0,
        Low: 0,
        Medium: 0,
        High: 0,
        Critical: 0,
      },
      category_breakdown: data?.category_breakdown || {
        phishing: 0,
        malicious_url: 0,
        deepfake: 0,
        account_takeover: 0,
        system_anomaly: 0,
      },
    };
  },

  /**
   * Daily incident volume trendline data
   * GET /api/v1/analytics/trends
   */
  async getTrends() {
    const data = await apiClient.get('/analytics/trends');
    return Array.isArray(data?.trends) ? data.trends : Array.isArray(data) ? data : [];
  },

  /**
   * MITRE ATT&CK technique distribution counts
   * GET /api/v1/analytics/mitre
   */
  async getMitre() {
    const data = await apiClient.get('/analytics/mitre');
    return Array.isArray(data?.mitre_breakdown)
      ? data.mitre_breakdown
      : Array.isArray(data)
      ? data
      : [];
  },
};

export default analyticsService;
