import { io } from 'socket.io-client';
import { CONFIG } from '../constants/config';
import { storageService } from './storageService';
import { getEffectiveApiUrl } from './apiClient';

let socketInstance = null;
const listeners = new Set();
const statusListeners = new Set();

const notifyStatus = (connected) => {
  statusListeners.forEach((fn) => {
    try {
      fn(connected);
    } catch (err) {
      console.warn('[socketService] Status listener error:', err.message);
    }
  });
};

export const socketService = {
  async connect() {
    if (socketInstance?.connected) {
      notifyStatus(true);
      return socketInstance;
    }

    const token = await storageService.getItem(CONFIG.TOKEN_KEY);
    if (!token) {
      notifyStatus(false);
      return null;
    }

    try {
      const apiUrl = await getEffectiveApiUrl();
      const wsUrl = apiUrl ? apiUrl.replace(/\/api\/v1\/?$/, '') : CONFIG.WS_URL;
      socketInstance = io(wsUrl, {
        auth: {
          token: `Bearer ${token}`
        },
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 2000
      });

      socketInstance.on('connect', () => {
        notifyStatus(true);
      });

      socketInstance.on('disconnect', () => {
        notifyStatus(false);
      });

      socketInstance.on('incident:new', (incident) => {
        listeners.forEach((listener) => {
          try {
            listener(incident);
          } catch (err) {
            console.warn('[socketService] Listener error:', err.message);
          }
        });
      });

      socketInstance.on('connect_error', (err) => {
        notifyStatus(false);
        console.warn('[socketService] Real-time connection degraded (retrying):', err.message);
      });

      return socketInstance;
    } catch (err) {
      notifyStatus(false);
      console.warn('[socketService.connect Error]', err.message);
      return null;
    }
  },

  disconnect() {
    if (socketInstance) {
      socketInstance.disconnect();
      socketInstance = null;
    }
    notifyStatus(false);
  },

  subscribeToIncidents(callback) {
    listeners.add(callback);
    return () => {
      listeners.delete(callback);
    };
  },

  onStatusChange(callback) {
    statusListeners.add(callback);
    callback(Boolean(socketInstance?.connected));
    return () => {
      statusListeners.delete(callback);
    };
  },

  isConnected() {
    return Boolean(socketInstance?.connected);
  }
};
