/**
 * CYBERGUARD — API Routes & WebSocket Event Names
 */

export const API_ROUTES = Object.freeze({
  HEALTH: '/health',
  AUTH: {
    SIGNUP: '/auth/signup',
    LOGIN: '/auth/login',
    ME: '/auth/me',
  },
  CHECK: {
    MESSAGE: '/check/message',
    URL: '/check/url',
    MEDIA: '/check/media',
  },
  INCIDENTS: {
    LIST: '/incidents',
    DETAIL: (id) => `/incidents/${id}`,
    UPDATE_STATUS: (id) => `/incidents/${id}`,
  },
  ACTIONS: {
    UPDATE_STATUS: (id) => `/actions/${id}`,
  },
  GUARDIAN: {
    LINK: '/guardian/link',
    ACCEPT: (id) => `/guardian/link/${id}/accept`,
    DECLINE: (id) => `/guardian/link/${id}/decline`,
    REVOKE: (id) => `/guardian/link/${id}/revoke`,
    ALERTS: '/guardian/alerts',
  },
  ANALYTICS: {
    OVERVIEW: '/analytics/overview',
    TRENDS: '/analytics/trends',
    MITRE: '/analytics/mitre',
  },
  TELEMETRY: {
    LOGIN_EVENT: '/telemetry/login-event',
    SYSTEM_EVENT: '/telemetry/system-event',
  },
});

export const WS_EVENTS = Object.freeze({
  INCIDENT_NEW: 'incident:new',
  SUBSCRIBE: 'subscribe',
});
