import { apiClient } from './apiClient';
import { incidentService } from './incidentService';

/**
 * Security Activity & Telemetry Service — Coordinates host telemetry reporting,
 * authentication threat audits, and security metrics for CYBERGUARD Mobile.
 */
export const securityActivityService = {
  /**
   * Dispatches sensor telemetry to report an authentication / session event.
   * Evaluated by backend ML anomaly detection algorithms and persisted to login_events table.
   * Route: POST /api/v1/telemetry/login-event
   *
   * @param {Object} params
   * @param {string} params.timestamp - ISO 8601 timestamp string
   * @param {string} params.deviceId - Client device identifier or fingerprint
   * @param {string} [params.location='Unknown'] - Geographic or network location string
   * @param {number} [params.failedAttempts=0] - Number of consecutive failed attempts before success
   * @param {string} [params.ipAddress] - Optional client IP address
   * @returns {Promise<{
   *   status: string,
   *   anomaly_detected: boolean,
   *   risk_level: string,
   *   risk_score?: number,
   *   explanation?: string,
   *   recommended_actions?: Array<string>,
   *   signals?: Object,
   *   incident_id?: string
   * }>}
   */
  async reportLoginEvent({ timestamp, deviceId, location, failedAttempts = 0, ipAddress }) {
    if (!timestamp || typeof timestamp !== 'string') {
      throw new Error('A valid ISO timestamp string is required');
    }
    if (!deviceId || typeof deviceId !== 'string') {
      throw new Error('A valid deviceId string is required');
    }

    const payload = {
      timestamp,
      device_id: deviceId.trim(),
      failed_attempts: Number.isInteger(Number(failedAttempts)) ? Math.max(0, Number(failedAttempts)) : 0
    };

    if (location && typeof location === 'string' && location.trim()) {
      payload.location = location.trim();
    }

    if (ipAddress && typeof ipAddress === 'string' && ipAddress.trim()) {
      payload.ip_address = ipAddress.trim();
    }

    return await apiClient.post('/telemetry/login-event', payload);
  },

  /**
   * Retrieves security activity and threat incidents scoped strictly to the authenticated user.
   * Route: GET /api/v1/incidents
   *
   * @param {Object} [params]
   * @param {number} [params.limit=25]
   * @param {number} [params.offset=0]
   * @param {string} [params.threat_type]
   * @param {string} [params.risk_level]
   * @param {string} [params.status]
   * @returns {Promise<{ incidents: Array<Object>, total: number, limit: number, offset: number }>}
   */
  async getSecurityActivity(params = {}) {
    return await incidentService.getIncidents(params);
  },

  /**
   * Retrieves aggregate security telemetry breakdown for the authenticated user.
   * Route: GET /api/v1/analytics/overview
   *
   * @returns {Promise<{
   *   total_incidents: number,
   *   active_threats: number,
   *   resolved_threats: number,
   *   risk_breakdown: { Safe: number, Low: number, Medium: number, High: number, Critical: number },
   *   category_breakdown: {
   *     phishing: number,
   *     malicious_url: number,
   *     deepfake: number,
   *     account_takeover: number,
   *     system_anomaly: number
   *   }
   * }>}
   */
  async getSecurityOverview() {
    return await apiClient.get('/analytics/overview');
  }
};
