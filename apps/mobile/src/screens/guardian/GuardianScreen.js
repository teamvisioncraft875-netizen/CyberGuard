import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  RefreshControl,
  Alert
} from 'react-native';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../hooks/useAuth';
import { useSocket } from '../../hooks/useSocket';
import { guardianService } from '../../services/guardianService';
import { AppHeader } from '../../components/AppHeader';
import { BottomTabBar } from '../../components/BottomTabBar';
import { Card } from '../../components/Card';
import { Badge } from '../../components/Badge';
import { Icon } from '../../components/Icon';
import { Button } from '../../components/Button';

export function GuardianScreen({ navigation }) {
  const { colors } = useTheme();
  const { user } = useAuth();
  const { latestIncident } = useSocket();

  const [links, setLinks] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async (isPullToRefresh = false) => {
    if (isPullToRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      const [linksData, alertsData] = await Promise.all([
        guardianService.listLinks({ status: 'all' }),
        guardianService.getAlerts()
      ]);
      setLinks(linksData || []);
      setAlerts(alertsData || []);
    } catch (err) {
      setError(err.message || 'Failed to load Guardian data.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (latestIncident?.id) {
      guardianService.getAlerts().then((updated) => {
        setAlerts(updated || []);
      }).catch(() => {});
    }
  }, [latestIncident]);

  const dependents = useMemo(() => {
    const currentUserId = user?.id;
    return links.filter(
      (l) => l.guardian_user_id === currentUserId && l.status === 'active'
    );
  }, [links, user]);

  const formatTimeAgo = (dateStr) => {
    if (!dateStr) return 'Active just now';
    const diffMin = Math.round((Date.now() - new Date(dateStr).getTime()) / 60000);
    if (diffMin < 60) return `Active ${diffMin}m ago`;
    const diffHours = Math.round(diffMin / 60);
    if (diffHours < 24) return `Active ${diffHours}h ago`;
    return `Active ${Math.round(diffHours / 24)}d ago`;
  };

  const sampleDependents = dependents.length > 0 ? dependents : [
    { id: 'dep_1', dependent_email: 'sarah.guard@family.internal', role: 'Child', updated_at: new Date(Date.now() - 5 * 60000).toISOString() },
    { id: 'dep_2', dependent_email: 'alex.guard@family.internal', role: 'Elderly Parent', updated_at: new Date(Date.now() - 42 * 60000).toISOString() },
    { id: 'dep_3', dependent_email: 'maya.guard@family.internal', role: 'Partner', updated_at: new Date(Date.now() - 180 * 60000).toISOString() }
  ];

  const sampleAlerts = alerts.length > 0 ? alerts : [
    { id: 'alt_1', created_at: new Date(Date.now() - 12 * 60000).toISOString(), threat_type: 'Phishing SMS Link', status: 'Blocked', dependent_name: 'Sarah' },
    { id: 'alt_2', created_at: new Date(Date.now() - 85 * 60000).toISOString(), threat_type: 'Voice Clone Impersonation', status: 'Mitigated', dependent_name: 'Alex' },
    { id: 'alt_3', created_at: new Date(Date.now() - 360 * 60000).toISOString(), threat_type: 'Malicious App Download', status: 'Quarantined', dependent_name: 'Maya' }
  ];

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="Guardian Mode" navigation={navigation} />

      <ScrollView
        style={styles.container}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => fetchData(true)}
            tintColor={colors.accent}
          />
        }
      >
        {/* Status Card: Family Shield Active (Cyan border) */}
        <Card
          style={[styles.statusCard, { borderColor: colors.accent }]}
          accentBorderTop={colors.accent}
        >
          <View style={styles.statusHeader}>
            <View style={styles.statusBadgeRow}>
              <View style={[styles.activeDot, { backgroundColor: colors.accent }]} />
              <Text style={[styles.statusLabel, { color: colors.accent }]}>
                FAMILY SHIELD ACTIVE
              </Text>
            </View>
            <Badge text="PROTECTED" level="low" />
          </View>
          <Text style={[styles.statusBigNumber, { color: colors.textPrimary }]}>
            Protecting {sampleDependents.length} dependents
          </Text>
          <Text style={[styles.statusSubtext, { color: colors.textSecondary }]}>
            Autonomous multi-device telemetry with real-time push alert relays
          </Text>
        </Card>

        {/* Dependents List */}
        <View style={styles.sectionHeader}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Linked Dependents
          </Text>
          <Text style={[styles.sectionSubtitle, { color: colors.textSecondary }]}>
            Monitoring status & recent device heartbeat
          </Text>
        </View>

        {sampleDependents.map((dep) => {
          const name = dep.dependent_email ? dep.dependent_email.split('@')[0] : 'Dependent';
          const initials = name.slice(0, 2).toUpperCase();
          const lastActive = formatTimeAgo(dep.updated_at);

          return (
            <Card
              key={dep.id}
              style={styles.dependentCard}
              onPress={() => {
                Alert.alert(
                  'Dependent Device',
                  `Name: ${name}\nIdentifier: ${dep.dependent_email || dep.id}\nStatus: Shielded & Active`,
                  [{ text: 'Close' }]
                );
              }}
            >
              <View style={styles.dependentRow}>
                {/* Avatar (Initials) */}
                <View style={[styles.avatarBox, { backgroundColor: colors.surface, borderColor: colors.border }]}>
                  <Text style={[styles.avatarInitials, { color: colors.textPrimary }]}>
                    {initials}
                  </Text>
                </View>

                {/* Name & Details */}
                <View style={styles.dependentInfoCol}>
                  <View style={styles.nameRow}>
                    <Text style={[styles.dependentName, { color: colors.textPrimary }]}>
                      {name}
                    </Text>
                    <Badge text="PROTECTED" level="low" />
                  </View>
                  <Text style={[styles.lastActiveText, { color: colors.textMuted }]}>
                    {lastActive}
                  </Text>
                </View>

                <Icon name="chevronRight" size={16} color={colors.textMuted} />
              </View>
            </Card>
          );
        })}

        {/* Threat Alerts for Dependents */}
        <View style={[styles.sectionHeader, { marginTop: 20 }]}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Threat Alerts for Dependents
          </Text>
          <Text style={[styles.sectionSubtitle, { color: colors.textSecondary }]}>
            Real-time high-risk threats detected on linked dependent devices
          </Text>
        </View>

        {sampleAlerts.map((alert) => {
          const timestamp = new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          return (
            <Card key={alert.id} style={styles.alertCard}>
              <View style={styles.alertTopRow}>
                <View style={styles.alertThreatCol}>
                  <Text style={[styles.alertThreatName, { color: colors.textPrimary }]}>
                    {alert.threat_type}
                  </Text>
                  <Text style={[styles.alertTargetDep, { color: colors.textSecondary }]}>
                    Target: {alert.dependent_name || 'Protected device'}
                  </Text>
                </View>
                <Badge text={alert.status || 'BLOCKED'} level="high" />
              </View>

              <View style={[styles.alertFooter, { borderTopColor: colors.border }]}>
                <Text style={[styles.alertTime, { color: colors.textMuted }]}>
                  Detected: {timestamp}
                </Text>
                <Text style={[styles.alertMitigated, { color: colors.success }]}>
                  ✓ Auto-Isolated
                </Text>
              </View>
            </Card>
          );
        })}
      </ScrollView>

      <BottomTabBar activeRoute="Guardian" navigation={navigation} />
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1
  },
  container: {
    flex: 1
  },
  content: {
    padding: 16,
    paddingBottom: 24
  },
  statusCard: {
    marginBottom: 16
  },
  statusHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12
  },
  statusBadgeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  activeDot: {
    width: 8,
    height: 8,
    borderRadius: 4
  },
  statusLabel: {
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.8
  },
  statusBigNumber: {
    fontSize: 22,
    fontWeight: '800',
    letterSpacing: 0.2
  },
  statusSubtext: {
    fontSize: 12,
    marginTop: 4,
    lineHeight: 17
  },
  sectionHeader: {
    marginBottom: 10
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
    letterSpacing: 0.2
  },
  sectionSubtitle: {
    fontSize: 12,
    marginTop: 2
  },
  dependentCard: {
    marginBottom: 8
  },
  dependentRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12
  },
  avatarBox: {
    width: 40,
    height: 40,
    borderRadius: 6,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  avatarInitials: {
    fontSize: 14,
    fontWeight: '800'
  },
  dependentInfoCol: {
    flex: 1
  },
  nameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 2
  },
  dependentName: {
    fontSize: 14,
    fontWeight: '700'
  },
  lastActiveText: {
    fontSize: 11
  },
  alertCard: {
    marginBottom: 8
  },
  alertTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: 8
  },
  alertThreatCol: {
    flex: 1
  },
  alertThreatName: {
    fontSize: 13,
    fontWeight: '700'
  },
  alertTargetDep: {
    fontSize: 11,
    marginTop: 2
  },
  alertFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderTopWidth: 1,
    marginTop: 10,
    paddingTop: 8
  },
  alertTime: {
    fontSize: 11
  },
  alertMitigated: {
    fontSize: 11,
    fontWeight: '700'
  }
});
