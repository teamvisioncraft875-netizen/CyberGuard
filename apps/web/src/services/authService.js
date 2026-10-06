import apiClient, { TOKEN_KEY, REFRESH_TOKEN_KEY, USER_KEY } from './apiClient';

/**
 * Authentication service for CYBERGUARD Gateway
 */
export const authService = {
  /**
   * Register a new user account
   * POST /api/v1/auth/signup
   */
  async signup(email, password, full_name, role = 'individual', organization_name = undefined) {
    const payload = {
      email,
      password,
      full_name,
      role,
    };

    if (role === 'employee' || organization_name) {
      payload.organization_name = organization_name;
    }

    const data = await apiClient.post('/auth/signup', payload);

    if (data?.token || data?.accessToken) {
      localStorage.setItem(TOKEN_KEY, data.token || data.accessToken);
    }
    if (data?.refreshToken) {
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refreshToken);
    }
    if (data?.user) {
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    }

    return data;
  },

  /**
   * Authenticate user credentials
   * POST /api/v1/auth/login
   */
  async login(email, password) {
    const data = await apiClient.post('/auth/login', {
      email,
      password,
    });

    if (data?.token || data?.accessToken) {
      localStorage.setItem(TOKEN_KEY, data.token || data.accessToken);
    }
    if (data?.refreshToken) {
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refreshToken);
    }
    if (data?.user) {
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    }

    return data;
  },

  /**
   * Retrieve currently authenticated user profile
   * GET /api/v1/auth/me
   */
  async getMe() {
    const data = await apiClient.get('/auth/me');
    const user = data?.user || data;

    if (user && typeof user === 'object') {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    }

    return user;
  },

  /**
   * Stateful server session termination with Bearer auth, followed by local credential cleanup
   * POST /api/v1/auth/logout
   */
  async logout() {
    try {
      await apiClient.post('/auth/logout');
    } catch (err) {
      console.warn('[authService.logout] Server logout failed or token already invalid:', err.message);
    } finally {
      try {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(REFRESH_TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
      } catch (_) {}

      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cyberguard:unauthorized'));
      }
    }
  },

  /**
   * Returns locally cached authentication token
   */
  getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch (_) {
      return null;
    }
  },

  /**
   * Returns locally cached refresh token
   */
  getRefreshToken() {
    try {
      return localStorage.getItem(REFRESH_TOKEN_KEY);
    } catch (_) {
      return null;
    }
  },

  /**
   * Returns locally cached user object
   */
  getCurrentUser() {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  },

  /**
   * Returns whether a session token is present
   */
  isAuthenticated() {
    return Boolean(this.getToken());
  },
};

export default authService;
