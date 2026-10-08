import React, { createContext, useContext, useEffect, useState } from 'react';
import { AuthContext } from './AuthContext';
import { socketService } from '../services/socketService';

export const SocketContext = createContext({
  isConnected: false,
  latestIncident: null
});

export function SocketProvider({ children }) {
  const { isAuthenticated } = useContext(AuthContext);
  const [isConnected, setIsConnected] = useState(false);
  const [latestIncident, setLatestIncident] = useState(null);

  useEffect(() => {
    let unsubscribeIncidents = null;
    let unsubscribeStatus = null;

    if (isAuthenticated) {
      unsubscribeStatus = socketService.onStatusChange((connected) => {
        setIsConnected(connected);
      });

      socketService.connect();

      unsubscribeIncidents = socketService.subscribeToIncidents((incident) => {
        setLatestIncident(incident);
      });
    } else {
      socketService.disconnect();
      setIsConnected(false);
      setLatestIncident(null);
    }

    return () => {
      if (unsubscribeIncidents) unsubscribeIncidents();
      if (unsubscribeStatus) unsubscribeStatus();
      if (!isAuthenticated) {
        socketService.disconnect();
      }
    };
  }, [isAuthenticated]);

  return (
    <SocketContext.Provider value={{ isConnected, latestIncident }}>
      {children}
    </SocketContext.Provider>
  );
}
