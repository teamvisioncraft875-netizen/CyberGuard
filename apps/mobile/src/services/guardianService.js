import { apiClient } from './apiClient';

/**
 * Guardian Service — Coordinates Guardian Mode for family and dependent protection.
 * Communicates with CYBERGUARD Gateway /api/v1/guardian/* endpoints.
 */
export const guardianService = {
  /**
   * Retrieves guardian links for the authenticated user.
   * Route: GET /api/v1/guardian/links?status=...
   *
   * @param {Object} [params]
   * @param {'active'|'pending'|'revoked'|'all'} [params.status='all']
   * @returns {Promise<Array<Object>>}
   */
  async listLinks(params = {}) {
    const status = params.status || 'all';
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    const data = await apiClient.get(`/guardian/links${query}`);
    return Array.isArray(data?.links) ? data.links : Array.isArray(data) ? data : [];
  },

  /**
   * Searches for a registered user by email to establish a guardian link.
   * Route: GET /api/v1/guardian/users/search?email=...
   *
   * @param {string} email - Email address of the target user
   * @returns {Promise<{ users?: Array<Object>, user?: Object, id?: string, email?: string }>}
   */
  async searchUserByEmail(email) {
    if (!email || typeof email !== 'string' || !email.trim()) {
      throw new Error('Please enter a valid email address to search.');
    }
    const cleanEmail = email.trim();
    return await apiClient.get(`/guardian/users/search?email=${encodeURIComponent(cleanEmail)}`);
  },

  /**
   * Initiates a new guardian link invitation between a guardian and dependent.
   * Route: POST /api/v1/guardian/link
   *
   * @param {Object} payload
   * @param {string} payload.guardian_user_id - User ID acting as guardian
   * @param {string} payload.dependent_user_id - User ID acting as protected dependent
   * @returns {Promise<Object>} Created link object
   */
  async createLink({ guardian_user_id, dependent_user_id }) {
    if (!guardian_user_id || !dependent_user_id) {
      throw new Error('Both guardian_user_id and dependent_user_id are required');
    }
    if (guardian_user_id === dependent_user_id) {
      throw new Error('You cannot establish a guardian link with your own account');
    }

    return await apiClient.post('/guardian/link', {
      guardian_user_id,
      dependent_user_id
    });
  },

  /**
   * Accepts a pending guardian link invitation (dependent action).
   * Route: POST /api/v1/guardian/link/:id/accept
   *
   * @param {string} linkId - ID of the pending guardian link
   * @returns {Promise<Object>} Updated link object
   */
  async acceptLink(linkId) {
    if (!linkId) throw new Error('Valid link ID is required to accept');
    return await apiClient.post(`/guardian/link/${linkId}/accept`);
  },

  /**
   * Declines a pending guardian link invitation (dependent action).
   * Route: POST /api/v1/guardian/link/:id/decline
   *
   * @param {string} linkId - ID of the pending guardian link
   * @returns {Promise<Object>} Updated link object
   */
  async declineLink(linkId) {
    if (!linkId) throw new Error('Valid link ID is required to decline');
    return await apiClient.post(`/guardian/link/${linkId}/decline`);
  },

  /**
   * Revokes an active or pending guardian link (guardian or dependent action).
   * Route: POST /api/v1/guardian/link/:id/revoke
   *
   * @param {string} linkId - ID of the guardian link to revoke
   * @returns {Promise<Object>} Updated link object
   */
  async revokeLink(linkId) {
    if (!linkId) throw new Error('Valid link ID is required to revoke');
    return await apiClient.post(`/guardian/link/${linkId}/revoke`);
  },

  /**
   * Retrieves high and critical security alerts for active dependents.
   * Route: GET /api/v1/guardian/alerts
   *
   * @returns {Promise<Array<{
   *   alert_id: string,
   *   dependent_user_id: string,
   *   dependent_name: string,
   *   risk_level: string,
   *   threat_type: string,
   *   explanation: string,
   *   recommended_action: string,
   *   timestamp: string
   * }>>}
   */
  async getAlerts() {
    const data = await apiClient.get('/guardian/alerts');
    return Array.isArray(data) ? data : [];
  }
};
