import { io } from 'socket.io-client';

let socket = null;
let currentToken = null;
const eventListeners = new Map();

/**
 * Derives gateway socket base URL from environment or fallback.
 * Strips any trailing `/api/v1` path so it connects to the root gateway server.
 */
export function getSocketBaseUrl() {
  const url =
    (typeof import.meta !== 'undefined' && import.meta.env?.VITE_WS_URL) ||
    (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) ||
    'http://localhost:5000';
  return url.replace(/\/api\/v1\/?$/, '').replace(/\/+$/, '');
}

/**
 * Initializes or updates the Socket.io client connection with the given token.
 * Only connects if token is present.
 *
 * @param {string|null} token - JWT access token
 * @returns {import('socket.io-client').Socket|null}
 */
export function connectSocket(token) {
  if (!token) {
    disconnectSocket();
    return null;
  }

  // If already connected with the identical token, reuse existing socket
  if (socket && currentToken === token && socket.connected) {
    return socket;
  }

  // If socket exists but token changed mid-session (401 silent refresh), update auth and reconnect
  if (socket && currentToken !== token) {
    currentToken = token;
    socket.auth = { token };
    if (!socket.connected) {
      socket.connect();
    } else {
      socket.disconnect().connect();
    }
    return socket;
  }

  currentToken = token;
  const baseUrl = getSocketBaseUrl();

  socket = io(baseUrl, {
    auth: { token },
    transports: ['websocket', 'polling'],
    autoConnect: true,
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 10000,
  });

  socket.on('connect', () => {
    if (typeof console !== 'undefined') {
      console.log('[CyberGuard Socket] Connected to real-time incident feed. Socket ID:', socket.id);
    }
  });

  socket.on('connect_error', (error) => {
    // Graceful degradation: log notice calmly, do not crash UI or show alarming error to user
    if (typeof console !== 'undefined') {
      console.warn('[CyberGuard Socket] Real-time connection degraded (will retry):', error.message);
    }
  });

  socket.on('disconnect', (reason) => {
    if (typeof console !== 'undefined') {
      console.log('[CyberGuard Socket] Disconnected:', reason);
    }
  });

  // Re-attach registered custom listeners
  eventListeners.forEach((callbacks, event) => {
    callbacks.forEach((cb) => {
      socket.on(event, cb);
    });
  });

  return socket;
}

/**
 * Disconnects the socket and cleans up internal state.
 */
export function disconnectSocket() {
  if (socket) {
    try {
      socket.disconnect();
    } catch (_) {}
    socket = null;
    currentToken = null;
  }
}

/**
 * Subscribes to a socket event. Returns an unsubscribe cleanup function.
 *
 * @param {string} event
 * @param {Function} callback
 * @returns {Function} Unsubscribe handler
 */
export function onSocketEvent(event, callback) {
  if (!eventListeners.has(event)) {
    eventListeners.set(event, new Set());
  }
  const callbacks = eventListeners.get(event);
  callbacks.add(callback);

  if (socket) {
    socket.on(event, callback);
  }

  return () => {
    callbacks.delete(callback);
    if (socket) {
      socket.off(event, callback);
    }
  };
}

/**
 * Returns the active socket instance (or null).
 */
export function getSocket() {
  return socket;
}

export const socketService = {
  getSocketBaseUrl,
  connectSocket,
  disconnectSocket,
  onSocketEvent,
  getSocket,
};

export default socketService;
