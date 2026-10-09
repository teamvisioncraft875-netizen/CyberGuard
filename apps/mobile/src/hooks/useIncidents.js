import { useState, useEffect, useCallback } from 'react';
import { incidentService } from '../services/incidentService';
import { useSocket } from './useSocket';

export function useIncidents(filters = {}) {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const { latestIncident } = useSocket();

  const fetchIncidents = useCallback(
    async (isPullToRefresh = false) => {
      if (isPullToRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      try {
        const result = await incidentService.getIncidents({
          limit: 30,
          offset: 0,
          risk_level: filters.risk_level,
          status: filters.status,
          threat_type: filters.threat_type
        });
        setIncidents(result.incidents);
        setTotal(result.total);
      } catch (err) {
        console.log('[useIncidents.fetchIncidents]', err.message);
        setError(err.message || 'Failed to load incidents');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [filters.risk_level, filters.status, filters.threat_type]
  );

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  // When a new incident arrives via Socket.io, prepend it to the list without duplicating
  useEffect(() => {
    if (latestIncident?.id) {
      setIncidents((prev) => {
        const exists = prev.some((item) => item.id === latestIncident.id);
        if (exists) {
          return prev.map((item) => (item.id === latestIncident.id ? latestIncident : item));
        }
        setTotal((prevTotal) => prevTotal + 1);
        return [latestIncident, ...prev];
      });
    }
  }, [latestIncident]);

  return {
    incidents,
    total,
    loading,
    refreshing,
    error,
    refetch: () => fetchIncidents(true)
  };
}
