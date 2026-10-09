import { CONFIG } from '../constants/config';
import { storageService } from './storageService';

let onUnauthorizedCallback = null;
let isRefreshing = false;
let failedQueue = [];

export function setUnauthorizedHandler(callback) {
  onUnauthorizedCallback = callback;
}

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

export async function getEffectiveApiUrl() {
  try {
    const custom = await storageService.getItem(CONFIG.CUSTOM_API_URL_KEY);
    if (custom && typeof custom === 'string' && custom.trim().length > 0) {
      return custom.trim();
    }
  } catch (err) {
    console.warn('[apiClient] Failed to read custom API URL:', err.message);
  }
  return CONFIG.API_URL;
}

export async function setCustomApiUrl(url) {
  if (!url || !url.trim()) {
    await storageService.removeItem(CONFIG.CUSTOM_API_URL_KEY);
    return CONFIG.API_URL;
  }
  let clean = url.trim().replace(/\/+$/, '');
  if (!clean.endsWith('/api/v1') && !clean.includes('/api/')) {
    clean = `${clean}/api/v1`;
  }
  await storageService.setItem(CONFIG.CUSTOM_API_URL_KEY, clean);
  return clean;
}

/**
 * Enhanced fetch wrapper with JWT bearer injection and automatic 401 token refresh.
 * Enforces:
 * 1. Only TOKEN_EXPIRED error triggers refresh.
 * 2. Original requests retry only once (_retry flag prevents infinite loops).
 * 3. Concurrent 401s join a shared refresh queue.
 * 4. Failed refresh immediately clears the session and triggers logout callback.
 */
export async function apiRequest(endpoint, options = {}) {
  const baseUrl = await getEffectiveApiUrl();
  const url = endpoint.startsWith('http') ? endpoint : `${baseUrl}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const token = await storageService.getItem(CONFIG.TOKEN_KEY);
  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  const fetchOptions = {
    ...options,
    headers
  };

  try {
    const response = await fetch(url, fetchOptions);

    // If request succeeded or returned non-401 error, handle normal JSON parse
    if (response.status !== 401) {
      let data = null;
      try {
        data = await response.json();
      } catch {
        data = null;
      }

      if (!response.ok) {
        const error = new Error(data?.message || `HTTP ${response.status}: Request failed`);
        error.status = response.status;
        error.data = data;
        error.code = data?.error || 'REQUEST_FAILED';
        throw error;
      }

      return data;
    }

    // Response is 401
    let errorData = null;
    try {
      errorData = await response.json();
    } catch {
      errorData = { error: 'UNAUTHORIZED' };
    }

    const isTokenExpired = errorData?.error === 'TOKEN_EXPIRED';
    const isAuthEndpoint = endpoint.includes('/auth/refresh') || endpoint.includes('/auth/login');

    // Only TOKEN_EXPIRED triggers refresh, and only if not already retried
    if (!isTokenExpired || isAuthEndpoint || options._retry) {
      if (onUnauthorizedCallback) {
        onUnauthorizedCallback();
      }
      const error = new Error(errorData?.message || 'Authentication required');
      error.status = 401;
      error.data = errorData;
      error.code = errorData?.error || 'UNAUTHORIZED';
      throw error;
    }

    // If another request is currently refreshing the token, join queue
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      })
        .then((newToken) => {
          headers.Authorization = `Bearer ${newToken}`;
          return apiRequest(endpoint, { ...options, _retry: true, headers });
        })
        .catch((err) => Promise.reject(err));
    }

    // Start single refresh cycle
    isRefreshing = true;
    const refreshToken = await storageService.getItem(CONFIG.REFRESH_TOKEN_KEY);

    if (!refreshToken) {
      isRefreshing = false;
      await storageService.removeItem(CONFIG.TOKEN_KEY);
      await storageService.removeItem(CONFIG.REFRESH_TOKEN_KEY);
      if (onUnauthorizedCallback) onUnauthorizedCallback();
      const error = new Error('Session expired, please login again');
      error.status = 401;
      error.code = 'REFRESH_TOKEN_INVALID';
      throw error;
    }

    try {
      const refreshRes = await fetch(`${baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (!refreshRes.ok) {
        throw new Error('Refresh failed');
      }

      const refreshData = await refreshRes.json();
      const newAccessToken = refreshData.token || refreshData.accessToken;

      if (!newAccessToken) {
        throw new Error('No token returned from refresh');
      }

      await storageService.setItem(CONFIG.TOKEN_KEY, newAccessToken);
      processQueue(null, newAccessToken);
      isRefreshing = false;

      // Replay original request exactly once
      headers.Authorization = `Bearer ${newAccessToken}`;
      return await apiRequest(endpoint, { ...options, _retry: true, headers });
    } catch (refreshErr) {
      processQueue(refreshErr, null);
      isRefreshing = false;
      await storageService.removeItem(CONFIG.TOKEN_KEY);
      await storageService.removeItem(CONFIG.REFRESH_TOKEN_KEY);
      if (onUnauthorizedCallback) {
        onUnauthorizedCallback();
      }
      const finalError = new Error('Session expired, please login again');
      finalError.status = 401;
      finalError.code = 'REFRESH_TOKEN_INVALID';
      throw finalError;
    }
  } catch (err) {
    throw err;
  }
}

export const apiClient = {
  get: (endpoint, headers) => apiRequest(endpoint, { method: 'GET', headers }),
  post: (endpoint, body, headers) =>
    apiRequest(endpoint, { method: 'POST', body: JSON.stringify(body), headers }),
  patch: (endpoint, body, headers) =>
    apiRequest(endpoint, { method: 'PATCH', body: JSON.stringify(body), headers }),
  delete: (endpoint, headers) => apiRequest(endpoint, { method: 'DELETE', headers }),
  getEffectiveApiUrl,
  setCustomApiUrl
};
