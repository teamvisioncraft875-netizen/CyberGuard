import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  ActivityIndicator,
  RefreshControl
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useAuth } from '../../hooks/useAuth';
import { useSocket } from '../../hooks/useSocket';
import { securityActivityService } from '../../services/securityActivityService';
import { RiskBadge } from '../../components/RiskBadge';

export function SecurityActivityScreen({ navigation }) {
  const { user } = useAuth();
  const { isConnected, latestIncident } = useSocket();

  // Data states
  const [activity, setActivity] = useState([]);
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Active filter: 'all' | 'account_takeover' | 'high_critical' | 'resolved'
  const [filter, setFilter] = useState('all');

  // 1. Fetch Security Activity & Overview
  const fetchData = useCallback(async (isPullToRefresh = false) => {
    if (isPullToRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      const [activityRes, overviewRes] = await Promise.all([
        securityActivityService.getSecurityActivity({ limit: 50 }),
        securityActivityService.getSecurityOverview().catch(() => null)
      ]);

      setActivity(activityRes?.incidents || []);
      if (overviewRes) {
        setOverview(overviewRes);
      }
    } catch (err) {
      console.warn('[SecurityActivityScreen.fetchData error]', err.message);
      setError(err.message || 'Failed to load security activity telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Realtime incident reactive refresh
  useEffect(() => {
    if (latestIncident?.id) {
      fetchData();
    }
  }, [latestIncident, fetchData]);

  // 3. Filtered Activity Items
  const filteredActivity = useMemo(() => {
    if (filter === 'all') return activity;
    if (filter === 'account_takeover') {
      return activity.filter(
        (item) => item.threat_type === 'account_takeover' || item.source_type === 'login'
      );
    }
    if (filter === 'high_critical') {
      return activity.filter(
        (item) =>
          String(item.risk_level).toLowerCase() === 'high' ||
          String(item.risk_level).toLowerCase() === 'critical'
      );
    }
    if (filter === 'resolved') {
      return activity.filter((item) => item.status === 'resolved');
    }
    return activity;
  }, [activity, filter]);

  const formatTimestamp = (ts) => {
    if (!ts) return 'Unknown';
    try {
      const d = new Date(ts);
      return (
        d.toLocaleDateString() +
        ' ' +
        d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      );
    } catch {
      return String(ts);
    }
  };

  const loginEventsCount = overview?.category_breakdown?.account_takeover ?? 0;
  const activeThreatsCount = overview?.active_threats ?? activity.filter((a) => a.status === 'open').length;
  const totalIncidentsCount = overview?.total_incidents ?? activity.length;
  const resolvedCount = overview?.resolved_threats ?? activity.filter((a) => a.status === 'resolved').length;

  return (
    <SafeAreaView style={styles.safeArea}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity
          style={styles.backBtn}
          onPress={() => navigation.goBack()}
          accessibilityLabel="Back to Dashboard"
          accessibilityRole="button"
        >
          <Text style={styles.backBtnText}>← Dashboard</Text>
        </TouchableOpacity>
        <View style={styles.titleRow}>
          <Text style={styles.title}>Security Activity</Text>
          <View style={styles.badge}>
            <Text style={styles.badgeText}>TELEMETRY</Text>
          </View>
        </View>
        <Text style={styles.subtitle}>
          Session telemetry, authentication audit, and account threat events
        </Text>
      </View>

      <ScrollView
        contentContainerStyle={styles.content}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => fetchData(true)}
            tintColor={COLORS.primary}
            colors={[COLORS.primary]}
          />
        }
      >
        {/* Error Banner */}
        {error ? (
          <View style={styles.errorBox} accessibilityRole="alert">
            <Text style={styles.errorText}>{error}</Text>
            <TouchableOpacity onPress={() => fetchData()} style={styles.retryBtn}>
              <Text style={styles.retryBtnText}>Retry</Text>
            </TouchableOpacity>
          </View>
        ) : null}

        {/* Real Aggregate Metrics */}
        <View style={styles.metricsGrid}>
          <View style={styles.metricCard}>
            <Text style={styles.metricValue}>{totalIncidentsCount}</Text>
            <Text style={styles.metricLabel}>Total Events</Text>
            <Text style={styles.metricSub}>Recorded</Text>
          </View>
          <View style={styles.metricCard}>
            <Text
              style={[
                styles.metricValue,
                loginEventsCount > 0 && { color: COLORS.warning }
              ]}
            >
              {loginEventsCount}
            </Text>
            <Text style={styles.metricLabel}>Auth Threats</Text>
            <Text style={styles.metricSub}>Takeover alerts</Text>
          </View>
          <View style={styles.metricCard}>
            <Text
              style={[
                styles.metricValue,
                activeThreatsCount > 0 && { color: COLORS.critical }
              ]}
            >
              {activeThreatsCount}
            </Text>
            <Text style={styles.metricLabel}>Active</Text>
            <Text style={styles.metricSub}>Under review</Text>
          </View>
          <View style={styles.metricCard}>
            <Text style={[styles.metricValue, { color: COLORS.safe }]}>
              {resolvedCount}
            </Text>
            <Text style={styles.metricLabel}>Mitigated</Text>
            <Text style={styles.metricSub}>Resolved</Text>
          </View>
        </View>

        {/* Live Device Telemetry Sensor Card */}
        <View style={styles.sensorCard}>
          <View style={styles.sensorHeader}>
            <View>
              <Text style={styles.sensorTitle}>DEVICE TELEMETRY SENSOR</Text>
              <Text style={styles.sensorSubtitle}>
                Host authentication sensor connection & health
              </Text>
            </View>
            <View
              style={[
                styles.sensorStatusBadge,
                isConnected ? styles.sensorStatusOnline : styles.sensorStatusOffline
              ]}
            >
              <Text
                style={[
                  styles.sensorStatusText,
                  isConnected ? styles.sensorStatusTextOnline : styles.sensorStatusTextOffline
                ]}
              >
                {isConnected ? 'LIVE SENSOR' : 'REST POLLING'}
              </Text>
            </View>
          </View>

          <View style={styles.sensorInfoTable}>
            <View style={styles.sensorRow}>
              <Text style={styles.sensorRowLabel}>Authenticated User</Text>
              <Text style={styles.sensorRowValue} numberOfLines={1}>
                {user?.email || 'Active Session'}
              </Text>
            </View>
            <View style={styles.sensorRow}>
              <Text style={styles.sensorRowLabel}>Sensor Protocol</Text>
              <Text style={styles.sensorRowValue}>
                POST /api/v1/telemetry/login-event
              </Text>
            </View>
            <View style={styles.sensorRow}>
              <Text style={styles.sensorRowLabel}>Anomaly Evaluation</Text>
              <Text style={styles.sensorRowValue}>
                Isolation Forest + Heuristics
              </Text>
            </View>
          </View>

          <View style={styles.sensorStatusNotice}>
            <Text style={styles.sensorStatusNoticeText}>
              • Background authentication telemetry is evaluated by backend anomaly models upon login.
              {'\n'}• Detected anomalies are flagged and dispatched to your activity feed as Account Takeover alerts.
            </Text>
          </View>
        </View>

        {/* Filter Chips */}
        <View style={styles.filterRow}>
          {[
            { id: 'all', label: `All (${activity.length})` },
            { id: 'account_takeover', label: `Auth Threats (${loginEventsCount})` },
            { id: 'high_critical', label: 'High / Critical' },
            { id: 'resolved', label: 'Resolved' }
          ].map((tab) => (
            <TouchableOpacity
              key={tab.id}
              style={[
                styles.filterChip,
                filter === tab.id && styles.filterChipActive
              ]}
              onPress={() => setFilter(tab.id)}
            >
              <Text
                style={[
                  styles.filterChipText,
                  filter === tab.id && styles.filterChipTextActive
                ]}
              >
                {tab.label}
              </Text>
            </TouchableOpacity>
          ))}
        </View>

        {/* Loading Indicator */}
        {loading && !refreshing ? (
          <View style={styles.loadingBox}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>
              Loading security activity audit stream...
            </Text>
          </View>
        ) : null}

        {/* Activity Items List */}
        {!loading && (
          <View>
            {filteredActivity.length === 0 ? (
              <View style={styles.emptyCard}>
                <Text style={styles.emptyIcon}>🛡️</Text>
                <Text style={styles.emptyTitle}>
                  {filter === 'all'
                    ? 'No Security Events Recorded'
                    : `No events matching filter: ${filter}`}
                </Text>
                <Text style={styles.emptySubtitle}>
                  Gateway background sensors report clean host and authentication telemetry with zero unmitigated threats.
                </Text>
              </View>
            ) : (
              filteredActivity.map((event) => {
                const threatType = event.threat_type
                  ? event.threat_type.replace(/_/g, ' ').toUpperCase()
                  : 'SECURITY EVENT';
                const status = (event.status || 'open').toUpperCase();
                const score = event.risk_score ? Math.round(Number(event.risk_score)) : null;

                return (
                  <TouchableOpacity
                    key={event.id}
                    style={styles.eventCard}
                    activeOpacity={0.8}
                    onPress={() =>
                      navigation.navigate('IncidentDetail', { id: event.id })
                    }
                  >
                    <View style={styles.eventHeader}>
                      <View style={styles.eventTitleCol}>
                        <Text style={styles.eventThreatType}>{threatType}</Text>
                        <Text style={styles.eventMeta}>
                          Source: {event.source_type || 'system'} • {formatTimestamp(event.created_at)}
                        </Text>
                      </View>
                      <RiskBadge level={event.risk_level || 'Low'} size="small" />
                    </View>

                    <Text style={styles.eventExplanation} numberOfLines={2}>
                      {event.explanation || 'Security event registered by detection engine.'}
                    </Text>

                    <View style={styles.eventFooter}>
                      <View style={styles.eventStatusBadge}>
                        <Text style={styles.eventStatusText}>{status}</Text>
                      </View>
                      {score !== null && (
                        <Text style={styles.eventScore}>
                          Score: {score} / 100
                        </Text>
                      )}
                      <Text style={styles.eventDetailLink}>View Details →</Text>
                    </View>
                  </TouchableOpacity>
                );
              })
            )}
          </View>
        )}

        {/* Privacy & Architecture Note */}
        <View style={styles.archNoticeCard}>
          <Text style={styles.archNoticeHeading}>
            🔒 TELEMETRY ARCHITECTURE & PRIVACY
          </Text>
          <Text style={styles.archNoticeText}>
            • Authentication telemetry is submitted via secure HTTPS (POST /telemetry/login-event).
            {'\n'}• Records are evaluated in memory for behavioral anomalies using the AI detection engine.
            {'\n'}• Only confirmed security anomalies and high-risk events generate persisted incident records.
            {'\n'}• No passwords, raw tokens, or sensitive credentials are ever persisted in telemetry stores.
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
  },
  header: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 14,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  backBtn: {
    marginBottom: 6
  },
  backBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  badge: {
    backgroundColor: 'rgba(0, 240, 255, 0.12)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  badgeText: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 2
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.4)',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  errorText: {
    color: COLORS.critical,
    fontSize: 13,
    flex: 1,
    fontWeight: '600'
  },
  retryBtn: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    backgroundColor: COLORS.critical,
    borderRadius: 6,
    marginLeft: 10
  },
  retryBtnText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '700'
  },
  metricsGrid: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 16
  },
  metricCard: {
    flex: 1,
    backgroundColor: COLORS.card,
    borderRadius: 12,
    padding: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    alignItems: 'center'
  },
  metricValue: {
    color: COLORS.primary,
    fontSize: 18,
    fontWeight: '800'
  },
  metricLabel: {
    color: COLORS.textPrimary,
    fontSize: 11,
    fontWeight: '700',
    marginTop: 2
  },
  metricSub: {
    color: COLORS.textMuted,
    fontSize: 9,
    textAlign: 'center'
  },
  sensorCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)',
    marginBottom: 16
  },
  sensorHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12
  },
  sensorTitle: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '800',
    letterSpacing: 1
  },
  sensorSubtitle: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginTop: 2
  },
  sensorStatusBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    borderWidth: 1
  },
  sensorStatusOnline: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderColor: 'rgba(16, 185, 129, 0.4)'
  },
  sensorStatusOffline: {
    backgroundColor: 'rgba(245, 158, 11, 0.15)',
    borderColor: 'rgba(245, 158, 11, 0.4)'
  },
  sensorStatusText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  sensorStatusTextOnline: {
    color: COLORS.safe
  },
  sensorStatusTextOffline: {
    color: COLORS.warning
  },
  sensorInfoTable: {
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    padding: 10,
    gap: 6
  },
  sensorRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  sensorRowLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '600'
  },
  sensorRowValue: {
    color: COLORS.textPrimary,
    fontSize: 11,
    fontWeight: '700',
    maxWidth: '65%'
  },
  sensorStatusNotice: {
    backgroundColor: 'rgba(0, 240, 255, 0.05)',
    borderRadius: 8,
    padding: 10,
    marginTop: 10,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)'
  },
  sensorStatusNoticeText: {
    color: COLORS.textSecondary,
    fontSize: 11,
    lineHeight: 16
  },
  filterRow: {
    flexDirection: 'row',
    gap: 6,
    marginBottom: 12,
    flexWrap: 'wrap'
  },
  filterChip: {
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  filterChipActive: {
    backgroundColor: 'rgba(0, 240, 255, 0.15)',
    borderColor: COLORS.primary
  },
  filterChipText: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '700'
  },
  filterChipTextActive: {
    color: COLORS.primary
  },
  loadingBox: {
    padding: 40,
    alignItems: 'center'
  },
  loadingText: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 12
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 30,
    alignItems: 'center',
    marginTop: 4
  },
  emptyIcon: {
    fontSize: 36,
    marginBottom: 10
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 6,
    textAlign: 'center'
  },
  emptySubtitle: {
    color: COLORS.textMuted,
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 18
  },
  eventCard: {
    backgroundColor: COLORS.card,
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 10
  },
  eventHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 6
  },
  eventTitleCol: {
    flex: 1,
    marginRight: 10
  },
  eventThreatType: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '800'
  },
  eventMeta: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginTop: 2
  },
  eventExplanation: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 17,
    marginBottom: 10
  },
  eventFooter: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.05)',
    paddingTop: 8
  },
  eventStatusBadge: {
    backgroundColor: COLORS.surface,
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderRadius: 4
  },
  eventStatusText: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '800'
  },
  eventScore: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '600'
  },
  eventDetailLink: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '700'
  },
  archNoticeCard: {
    backgroundColor: 'rgba(0, 240, 255, 0.04)',
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.15)',
    marginTop: 14
  },
  archNoticeHeading: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 6
  },
  archNoticeText: {
    color: COLORS.textSecondary,
    fontSize: 11,
    lineHeight: 17
  }
});
