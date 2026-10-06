import apiClient from './apiClient';

/**
 * Guardian Mode Service for family and dependent protection.
 * Communicates with CYBERGUARD Gateway /api/v1/guardian/* endpoints.
 */
export const guardianService = {
  /**
   * List guardian links for the authenticated user.
   * GET /api/v1/guardian/links?status=...
   * @param {Object} [params]
   * @param {'active' | 'pending' | 'revoked' | 'all'} [params.status]
   * @returns {Promise<Array>} Array of guardian link objects
   */
  async listLinks(params = {}) {
    const query = new URLSearchParams();
    if (params.status && params.status !== 'all') {
      query.append('status', params.status);
    } else if (params.status === 'all') {
      query.append('status', 'all');
    }
    const queryString = query.toString();
    const endpoint = `/guardian/links${queryString ? `?${queryString}` : ''}`;
    const data = await apiClient.get(endpoint);
    return Array.isArray(data?.links) ? data.links : Array.isArray(data) ? data : [];
  },

  /**
   * Search for a registered user by email to link as guardian or dependent.
   * GET /api/v1/guardian/users/search?email=...
   * @param {string} email
   * @returns {Promise<{ users: Array, user: Object, id: string, email: string }>}
   */
  async searchUserByEmail(email) {
    const data = await apiClient.get(`/guardian/users/search?email=${encodeURIComponent(email.trim())}`);
    return data;
  },

  /**
   * Create a new guardian link invitation between guardian and dependent.
   * POST /api/v1/guardian/link
   * @param {Object} payload
   * @param {string} payload.guardian_user_id
   * @param {string} payload.dependent_user_id
   * @returns {Promise<{ link_id: string, status: string, guardian_user_id: string, dependent_user_id: string, created_at: string }>}
   */
  async createLink({ guardian_user_id, dependent_user_id }) {
    const data = await apiClient.post('/guardian/link', {
      guardian_user_id,
      dependent_user_id,
    });
    return data;
  },

  /**
   * Accept a pending guardian link invitation (dependent action).
   * POST /api/v1/guardian/link/:id/accept
   * @param {string} linkId
   * @returns {Promise<{ link_id: string, status: string, ... }>}
   */
  async acceptLink(linkId) {
    const data = await apiClient.post(`/guardian/link/${linkId}/accept`);
    return data;
  },

  /**
   * Decline a pending guardian link invitation (dependent action).
   * POST /api/v1/guardian/link/:id/decline
   * @param {string} linkId
   * @returns {Promise<{ link_id: string, status: string, ... }>}
   */
  async declineLink(linkId) {
    const data = await apiClient.post(`/guardian/link/${linkId}/decline`);
    return data;
  },

  /**
   * Revoke an active or pending guardian link (guardian or dependent action).
   * POST /api/v1/guardian/link/:id/revoke
   * @param {string} linkId
   * @returns {Promise<{ id: string, link_id: string, status: string, ... }>}
   */
  async revokeLink(linkId) {
    const data = await apiClient.post(`/guardian/link/${linkId}/revoke`);
    return data;
  },

  /**
   * Retrieve high and critical security alerts for active dependents.
   * GET /api/v1/guardian/alerts
   * @returns {Promise<Array>} Array of dependent alert objects
   */
  async getAlerts() {
    const data = await apiClient.get('/guardian/alerts');
    return Array.isArray(data) ? data : [];
  },
};

export default guardianService;
