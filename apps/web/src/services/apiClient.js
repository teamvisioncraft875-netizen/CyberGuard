import axios from 'axios';

export const TOKEN_KEY = 'cyberguard_token';
export const REFRESH_TOKEN_KEY = 'cyberguard_refresh_token';
export const USER_KEY = 'cyberguard_user';

const baseURL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) ||
  'http://localhost:5000/api/v1';

/**
 * Centralized Axios API client for CYBERGUARD Gateway
 */
const apiClient = axios.create({
  baseURL,
  timeout: 15000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

// Request interceptor: attach Bearer token from localStorage
apiClient.interceptors.request.use(
  (config) => {
    try {
      const token = localStorage.getItem(TOKEN_KEY);
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    } catch (_) {}
    return config;
  },
  (error) => Promise.reject(error)
);

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Response interceptor: handle 401, 429, and normalize server errors
apiClient.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    const originalRequest = error.config;

    if (error.response) {
      const { status, data } = error.response;

      // Handle 401 Unauthorized with silent token refresh
      if (status === 401 && originalRequest && !originalRequest._retry) {
        const isAuthEndpoint =
          originalRequest.url?.includes('/auth/login') ||
          originalRequest.url?.includes('/auth/signup') ||
          originalRequest.url?.includes('/auth/refresh');

        if (isAuthEndpoint) {
          try {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(REFRESH_TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
          } catch (_) {}

          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('cyberguard:unauthorized'));
          }

          const authErr = new Error('Authentication expired or unauthorized. Please sign in again.');
          authErr.status = 401;
          authErr.code = 'UNAUTHORIZED';
          return Promise.reject(authErr);
        }

        const storedRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
        if (!storedRefreshToken) {
          try {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(REFRESH_TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
          } catch (_) {}

          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('cyberguard:unauthorized'));
          }

          const authErr = new Error('Authentication expired or unauthorized. Please sign in again.');
          authErr.status = 401;
          authErr.code = 'UNAUTHORIZED';
          return Promise.reject(authErr);
        }

        if (isRefreshing) {
          return new Promise((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          })
            .then((newToken) => {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return apiClient(originalRequest);
            })
            .catch((err) => Promise.reject(err));
        }

        originalRequest._retry = true;
        isRefreshing = true;

        try {
          const refreshRes = await axios.post(
            `${baseURL}/auth/refresh`,
            { refreshToken: storedRefreshToken },
            { withCredentials: true, timeout: 10000 }
          );

          const newToken = refreshRes.data?.token || refreshRes.data?.accessToken;
          if (!newToken) {
            throw new Error('Refresh response missing token');
          }

          localStorage.setItem(TOKEN_KEY, newToken);
          apiClient.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
          originalRequest.headers.Authorization = `Bearer ${newToken}`;

          processQueue(null, newToken);
          return apiClient(originalRequest);
        } catch (refreshErr) {
          processQueue(refreshErr, null);

          try {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(REFRESH_TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
          } catch (_) {}

          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('cyberguard:unauthorized'));
          }

          const authErr = new Error('Session expired. Please sign in again.');
          authErr.status = 401;
          authErr.code = 'UNAUTHORIZED';
          return Promise.reject(authErr);
        } finally {
          isRefreshing = false;
        }
      }

      // 429: Specific rate limiting message
      if (status === 429) {
        const rateErr = new Error('Too many requests, please wait a few minutes.');
        rateErr.status = 429;
        rateErr.code = 'RATE_LIMITED';
        return Promise.reject(rateErr);
      }

      // Extract server's error message
      const serverMsg =
        data?.message ||
        data?.error ||
        (typeof data === 'string' ? data : null);

      const apiErr = new Error(serverMsg || `Request failed with status ${status}`);
      apiErr.status = status;
      apiErr.code = data?.error || 'API_ERROR';
      apiErr.data = data;
      return Promise.reject(apiErr);
    }

    if (error.code === 'ECONNABORTED') {
      const timeoutErr = new Error('Request timed out. Please verify the gateway connection.');
      timeoutErr.status = 408;
      timeoutErr.code = 'TIMEOUT';
      return Promise.reject(timeoutErr);
    }

    return Promise.reject(error);
  }
);

export default apiClient;
