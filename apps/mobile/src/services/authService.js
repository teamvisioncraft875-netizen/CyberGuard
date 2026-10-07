import { apiClient } from './apiClient';
import { storageService } from './storageService';
import { CONFIG } from '../constants/config';

export const authService = {
  async login(email, password) {
    const data = await apiClient.post('/auth/login', { email, password });
    const accessToken = data.token || data.accessToken;
    const refreshToken = data.refreshToken;
    const user = data.user;

    if (accessToken) {
      await storageService.setItem(CONFIG.TOKEN_KEY, accessToken);
    }
    if (refreshToken) {
      await storageService.setItem(CONFIG.REFRESH_TOKEN_KEY, refreshToken);
    }
    if (user) {
      await storageService.setItem(CONFIG.USER_KEY, JSON.stringify(user));
    }

    return { user, accessToken, refreshToken };
  },

  async signup(email, password, role = 'individual', organization_name = '') {
    const payload = {
      email,
      password,
      role
    };
    if (role === 'employee' && organization_name) {
      payload.organization_name = organization_name;
    }

    const data = await apiClient.post('/auth/signup', payload);
    const accessToken = data.token || data.accessToken;
    const refreshToken = data.refreshToken;
    const user = data.user;

    if (accessToken) {
      await storageService.setItem(CONFIG.TOKEN_KEY, accessToken);
    }
    if (refreshToken) {
      await storageService.setItem(CONFIG.REFRESH_TOKEN_KEY, refreshToken);
    }
    if (user) {
      await storageService.setItem(CONFIG.USER_KEY, JSON.stringify(user));
    }

    return { user, accessToken, refreshToken };
  },

  async logout() {
    try {
      await apiClient.post('/auth/logout');
    } catch (err) {
      console.warn('[authService.logout] Remote logout warning:', err.message);
    } finally {
      await storageService.removeItem(CONFIG.TOKEN_KEY);
      await storageService.removeItem(CONFIG.REFRESH_TOKEN_KEY);
      await storageService.removeItem(CONFIG.USER_KEY);
    }
  },

  async getMe() {
    const user = await apiClient.get('/auth/me');
    if (user) {
      await storageService.setItem(CONFIG.USER_KEY, JSON.stringify(user));
    }
    return user;
  },

  async getStoredSession() {
    const token = await storageService.getItem(CONFIG.TOKEN_KEY);
    const userStr = await storageService.getItem(CONFIG.USER_KEY);
    const refreshToken = await storageService.getItem(CONFIG.REFRESH_TOKEN_KEY);

    let user = null;
    if (userStr) {
      try {
        user = JSON.parse(userStr);
      } catch {
        user = null;
      }
    }

    return {
      token,
      refreshToken,
      user
    };
  }
};
