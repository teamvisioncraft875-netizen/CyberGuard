import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';
import { useAuth } from './AuthContext';
import { useToast } from '../hooks/useToast';
import { normalizeRisk } from '../utils/risk';
import {
  connectSocket,
  disconnectSocket,
  getSocket,
} from '../services/socketService';

const SocketContext = createContext(null);

function formatThreatLabel(threatType) {
  if (!threatType) return 'Threat Detected';
  return threatType
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function SocketProvider({ children }) {
  const { token, isAuthenticated } = useAuth();
  const { critical: toastCritical, warning: toastWarning, info: toastInfo } = useToast();

  const [isConnected, setIsConnected] = useState(false);
  const [unreadAlertsCount, setUnreadAlertsCount] = useState(0);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [lastIncident, setLastIncident] = useState(null);

  // Set of subscribers for page-level live reactions (e.g. IncidentsPage, DashboardPage)
  const subscribersRef = useRef(new Set());

  const onIncident = useCallback((callback) => {
    subscribersRef.current.add(callback);
    return () => {
      subscribersRef.current.delete(callback);
    };
  }, []);

  const resetUnreadCount = useCallback(() => {
    setUnreadAlertsCount(0);
  }, []);

  // Connect / reconnect / disconnect lifecycle
  useEffect(() => {
    if (!isAuthenticated || !token) {
      disconnectSocket();
      setIsConnected(false);
      return;
    }

    const socket = connectSocket(token);
    if (!socket) return;

    const handleConnect = () => setIsConnected(true);
    const handleDisconnect = () => setIsConnected(false);
    const handleConnectError = (err) => {
      setIsConnected(false);
      // Log calmly without throwing or crashing UI
      if (typeof console !== 'undefined') {
        console.warn('[SocketContext] Connection notice:', err.message);
      }
    };

    const handleIncidentNew = (payload) => {
      if (!payload || !payload.id) return;

      const normRisk = normalizeRisk(payload.risk_level);
      const threatTitle = formatThreatLabel(payload.threat_type);
      const title = `${threatTitle} (${payload.risk_score != null ? payload.risk_score : '—'}/100)`;
      const description = payload.explanation || 'New threat event recorded by CyberGuard.';

      // 1. Toast notifications per risk level contract
      if (normRisk === 'critical') {
        // Critical persists until dismissed
        toastCritical(
          {
            title: `CRITICAL: ${threatTitle}`,
            description,
          },
          {
            duration: Infinity,
          }
        );
      } else if (normRisk === 'high') {
        toastWarning(
          {
            title: `HIGH ALERT: ${threatTitle}`,
            description,
          },
          {
            duration: 8000,
          }
        );
      } else {
        // Medium, Low, Safe
        toastInfo(
          {
            title: `${normRisk === 'safe' ? 'Safe Telemetry' : 'Security Notice'}: ${threatTitle}`,
            description,
          },
          {
            duration: 5000,
          }
        );
      }

      // 2. Increment bell badge count
      setUnreadAlertsCount((prev) => prev + 1);

      // 3. Record in live alerts feed
      setLiveAlerts((prev) => [payload, ...prev.slice(0, 19)]);
      setLastIncident(payload);

      // 4. Notify registered page subscribers (IncidentsPage, DashboardPage)
      subscribersRef.current.forEach((cb) => {
        try {
          cb(payload);
        } catch (cbErr) {
          console.error('[SocketContext] Subscriber error:', cbErr);
        }
      });
    };

    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('connect_error', handleConnectError);
    socket.on('incident:new', handleIncidentNew);

    if (socket.connected) {
      setIsConnected(true);
    }

    return () => {
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('connect_error', handleConnectError);
      socket.off('incident:new', handleIncidentNew);
    };
  }, [isAuthenticated, token, toastCritical, toastWarning, toastInfo]);

  const value = {
    isConnected,
    unreadAlertsCount,
    resetUnreadCount,
    liveAlerts,
    lastIncident,
    onIncident,
    getSocket,
  };

  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>;
}

export function useSocket() {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
}

export default SocketContext;
