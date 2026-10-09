import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Modal,
  TextInput,
  Alert
} from 'react-native';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../hooks/useAuth';
import { useIncidents } from '../../hooks/useIncidents';
import { useSocket } from '../../hooks/useSocket';
import { AppHeader } from '../../components/AppHeader';
import { BottomTabBar } from '../../components/BottomTabBar';
import { Card } from '../../components/Card';
import { Badge } from '../../components/Badge';
import { Icon } from '../../components/Icon';
import { getEffectiveApiUrl, setCustomApiUrl } from '../../services/apiClient';

export function DashboardScreen({ navigation }) {
  const { colors, isDark } = useTheme();
  const { user } = useAuth();
  const { isConnected } = useSocket();
  const { incidents, total, refreshing, refetch } = useIncidents();

  // Server settings modal state
  const [serverModalVisible, setServerModalVisible] = useState(false);
  const [currentApiUrl, setCurrentApiUrl] = useState('');
  const [inputApiUrl, setInputApiUrl] = useState('');
  const [testingPing, setTestingPing] = useState(false);

  useEffect(() => {
    getEffectiveApiUrl().then((url) => {
      setCurrentApiUrl(url);
      setInputApiUrl(url);
    });
  }, []);

  const handleOpenServerModal = async () => {
    const url = await getEffectiveApiUrl();
    setCurrentApiUrl(url);
    setInputApiUrl(url);
    setServerModalVisible(true);
  };

  const handleSaveServerUrl = async () => {
    try {
      const updated = await setCustomApiUrl(inputApiUrl);
      setCurrentApiUrl(updated);
      setServerModalVisible(false);
      Alert.alert('Configuration Saved', `Target backend updated to:\n${updated}\nRefreshing telemetry...`);
      refetch();
    } catch (e) {
      Alert.alert('Error', e.message || 'Failed to update server configuration');
    }
  };

  const handleTestPing = async () => {
    setTestingPing(true);
    try {
      let target = inputApiUrl.trim().replace(/\/+$/, '');
      if (!target.endsWith('/api/v1') && !target.includes('/api/')) {
        target = `${target}/api/v1`;
      }
      const pingUrl = `${target}/health`;
      const res = await fetch(pingUrl, { method: 'GET' });
      if (res.ok) {
        Alert.alert('Success', `Server reached successfully at ${target} (HTTP ${res.status})`);
      } else {
        Alert.alert('Response Received', `Server returned HTTP ${res.status} at ${pingUrl}`);
      }
    } catch (e) {
      Alert.alert('Connection Failed', `Could not reach ${inputApiUrl}: ${e.message}`);
    } finally {
      setTestingPing(false);
    }
  };

  const criticalHighCount = incidents.filter(
    (i) => i.risk_level === 'critical' || i.risk_level === 'high'
  ).length;

  const openCount = incidents.filter(
    (i) => !i.status || i.status === 'open' || i.status === 'investigating'
  ).length;

  const highestRisk = criticalHighCount > 0 ? 'CRITICAL' : (incidents.length > 0 ? 'ELEVATED' : 'SECURE');
  const postureColor = highestRisk === 'CRITICAL' ? colors.danger : (highestRisk === 'ELEVATED' ? colors.warning : colors.success);

  const recentIncidents = incidents.slice(0, 5);
  const username = user?.email ? user.email.split('@')[0] : 'Operator';

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader navigation={navigation} />

      <ScrollView
        style={styles.container}
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={refetch}
            tintColor={colors.accent}
            colors={[colors.textPrimary]}
          />
        }
      >
        {/* Master Console Card with Integrated Telemetry Strip (NO separate square boxes) */}
        <Card style={styles.masterCard}>
          {/* Header Row */}
          <View style={styles.masterHeaderRow}>
            <View style={styles.systemTag}>
              <View style={[styles.pulseDot, { backgroundColor: isConnected ? colors.success : colors.warning }]} />
              <Text style={[styles.systemTagText, { color: colors.textSecondary }]}>
                AUTONOMOUS DEFENSE
              </Text>
            </View>

            <TouchableOpacity
              style={[styles.connectionPill, { borderColor: colors.border, backgroundColor: colors.surface }]}
              onPress={handleOpenServerModal}
              activeOpacity={0.7}
            >
              <Text style={[styles.connectionPillText, { color: isConnected ? colors.success : colors.warning }]}>
                {isConnected ? 'LIVE' : 'CACHE'}
              </Text>
              <Icon name="settings" size={12} color={colors.textSecondary} />
            </TouchableOpacity>
          </View>

          {/* Title & Operator */}
          <Text style={[styles.masterTitle, { color: colors.textPrimary }]}>
            Security Console
          </Text>
          <Text style={[styles.masterSubtitle, { color: colors.textSecondary }]}>
            Operator: <Text style={{ color: colors.textPrimary, fontWeight: '700' }}>{username}</Text> • Active Threat Mitigation
          </Text>

          {/* Integrated Telemetry Metrics Strip */}
          <View style={[styles.telemetryStrip, { backgroundColor: colors.surface, borderColor: colors.border }]}>
            <View style={styles.telemetryCol}>
              <Text style={[styles.telemetryLabel, { color: colors.textMuted }]}>
                TELEMETRY
              </Text>
              <Text style={[styles.telemetryValue, { color: colors.textPrimary }]}>
                {total || incidents.length || 0}
              </Text>
              <Text style={[styles.telemetrySub, { color: colors.textSecondary }]}>
                Incidents Logged
              </Text>
            </View>

            <View style={[styles.telemetryDivider, { backgroundColor: colors.border }]} />

            <View style={styles.telemetryCol}>
              <Text style={[styles.telemetryLabel, { color: colors.textMuted }]}>
                ACTIVE RISKS
              </Text>
              <Text style={[styles.telemetryValue, { color: openCount > 0 ? colors.danger : colors.textPrimary }]}>
                {openCount}
              </Text>
              <Text style={[styles.telemetrySub, { color: openCount > 0 ? colors.danger : colors.textSecondary }]}>
                {openCount > 0 ? 'Pending Action' : 'Zero Threats'}
              </Text>
            </View>

            <View style={[styles.telemetryDivider, { backgroundColor: colors.border }]} />

            <View style={styles.telemetryCol}>
              <Text style={[styles.telemetryLabel, { color: colors.textMuted }]}>
                POSTURE
              </Text>
              <Text style={[styles.telemetryPosture, { color: postureColor }]}>
                {highestRisk}
              </Text>
              <Text style={[styles.telemetrySub, { color: colors.textSecondary }]}>
                Zero-Trust
              </Text>
            </View>
          </View>

          {/* Quick Gateway Bar */}
          <TouchableOpacity
            style={[styles.gatewayBar, { borderColor: colors.border }]}
            onPress={handleOpenServerModal}
            activeOpacity={0.7}
          >
            <View style={[styles.statusDot, { backgroundColor: isConnected ? colors.success : colors.warning }]} />
            <Text style={[styles.gatewayBarText, { color: colors.textMuted }]} numberOfLines={1}>
              {isConnected
                ? `Connected: ${currentApiUrl || 'Default Gateway'}`
                : 'Offline / Tap to configure server IP'}
            </Text>
            <Icon name="chevronRight" size={12} color={colors.textMuted} />
          </TouchableOpacity>
        </Card>

        {/* Threat Defense Scanners - Unified Executive List Card (NO 2x2 square boxes) */}
        <View style={styles.sectionHeaderRow}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Threat Defense Scanners
          </Text>
          <Badge text="4 MODULES" />
        </View>

        <Card style={styles.scannerListCard} padding={0}>
          {/* Row 1: URL Scanner */}
          <TouchableOpacity
            style={styles.scannerRow}
            onPress={() => navigation.navigate('UrlScanner')}
            activeOpacity={0.7}
          >
            <View style={[styles.scannerIconSquare, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="link" size={16} color={colors.textPrimary} />
            </View>
            <View style={styles.scannerRowContent}>
              <Text style={[styles.scannerRowTitle, { color: colors.textPrimary }]}>
                URL Threat Scanner
              </Text>
              <Text style={[styles.scannerRowDesc, { color: colors.textSecondary }]}>
                Analyze links, homoglyph phishing & malicious redirects
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </TouchableOpacity>

          <View style={[styles.rowDivider, { backgroundColor: colors.border }]} />

          {/* Row 2: Message Scanner */}
          <TouchableOpacity
            style={styles.scannerRow}
            onPress={() => navigation.navigate('MessageScanner')}
            activeOpacity={0.7}
          >
            <View style={[styles.scannerIconSquare, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="message" size={16} color={colors.textPrimary} />
            </View>
            <View style={styles.scannerRowContent}>
              <Text style={[styles.scannerRowTitle, { color: colors.textPrimary }]}>
                Message & SMS Analyzer
              </Text>
              <Text style={[styles.scannerRowDesc, { color: colors.textSecondary }]}>
                Detect social engineering, smishing & urgent fraud tactics
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </TouchableOpacity>

          <View style={[styles.rowDivider, { backgroundColor: colors.border }]} />

          {/* Row 3: Media Scanner */}
          <TouchableOpacity
            style={styles.scannerRow}
            onPress={() => navigation.navigate('MediaScanner')}
            activeOpacity={0.7}
          >
            <View style={[styles.scannerIconSquare, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="image" size={16} color={colors.textPrimary} />
            </View>
            <View style={styles.scannerRowContent}>
              <Text style={[styles.scannerRowTitle, { color: colors.textPrimary }]}>
                Media Deepfake Scanner
              </Text>
              <Text style={[styles.scannerRowDesc, { color: colors.textSecondary }]}>
                Forensic inspection for synthetic photos & voice clones
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </TouchableOpacity>

          <View style={[styles.rowDivider, { backgroundColor: colors.border }]} />

          {/* Row 4: Secret Scanner */}
          <TouchableOpacity
            style={styles.scannerRow}
            onPress={() => navigation.navigate('SecretScanner')}
            activeOpacity={0.7}
          >
            <View style={[styles.scannerIconSquare, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="key" size={16} color={colors.textPrimary} />
            </View>
            <View style={styles.scannerRowContent}>
              <Text style={[styles.scannerRowTitle, { color: colors.textPrimary }]}>
                Secret & Credential Discovery
              </Text>
              <Text style={[styles.scannerRowDesc, { color: colors.textSecondary }]}>
                Find leaked API keys, tokens, passwords & credentials
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </TouchableOpacity>
        </Card>

        {/* Guardian & Security Activity Full-Width Modules */}
        <View style={styles.sectionHeaderRow}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Enterprise Protection
          </Text>
        </View>

        <Card
          style={styles.actionModuleCard}
          onPress={() => navigation.navigate('Guardian')}
        >
          <View style={styles.actionRow}>
            <View style={[styles.actionIconBox, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="shield" size={18} color={colors.textPrimary} />
            </View>
            <View style={styles.actionTextCol}>
              <View style={styles.badgeLine}>
                <Text style={[styles.actionTitle, { color: colors.textPrimary }]}>
                  Guardian Family Shield
                </Text>
                <Badge text="ACTIVE LINK" />
              </View>
              <Text style={[styles.actionDescription, { color: colors.textSecondary }]}>
                Real-time threat notification relay for dependents & family contacts
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </View>
        </Card>

        <Card
          style={styles.actionModuleCard}
          onPress={() => navigation.navigate('SecurityActivity')}
        >
          <View style={styles.actionRow}>
            <View style={[styles.actionIconBox, { backgroundColor: colors.surface, borderColor: colors.border }]}>
              <Icon name="activity" size={18} color={colors.textPrimary} />
            </View>
            <View style={styles.actionTextCol}>
              <View style={styles.badgeLine}>
                <Text style={[styles.actionTitle, { color: colors.textPrimary }]}>
                  Security Activity Log
                </Text>
                <Badge text="AUDIT" />
              </View>
              <Text style={[styles.actionDescription, { color: colors.textSecondary }]}>
                Session telemetry, auth audits, and MITRE ATT&CK mitigation records
              </Text>
            </View>
            <Icon name="chevronRight" size={16} color={colors.textMuted} />
          </View>
        </Card>

        {/* Open Incident Triage Feed */}
        <View style={styles.sectionHeaderRow}>
          <Text style={[styles.sectionTitle, { color: colors.textPrimary }]}>
            Incident Triage Stream
          </Text>
          <TouchableOpacity onPress={() => navigation.navigate('IncidentList')}>
            <Text style={[styles.viewAllText, { color: colors.textSecondary }]}>
              View All Stream →
            </Text>
          </TouchableOpacity>
        </View>

        {recentIncidents.length === 0 ? (
          <Card style={styles.emptyCard}>
            <Icon name="check" size={24} color={colors.success} style={{ marginBottom: 6 }} />
            <Text style={[styles.emptyTitle, { color: colors.textPrimary }]}>
              Zero Open Incidents
            </Text>
            <Text style={[styles.emptyText, { color: colors.textMuted }]}>
              All endpoints and communication streams are verified clean. Defense shield active.
            </Text>
          </Card>
        ) : (
          recentIncidents.map((incident) => {
            const timeAgo = incident.created_at
              ? new Date(incident.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
              : 'Recent';

            return (
              <Card
                key={incident.id}
                style={styles.incidentFeedCard}
                onPress={() => navigation.navigate('IncidentDetail', { id: incident.id })}
              >
                <View style={styles.incidentCardHeader}>
                  <Text
                    style={[styles.incidentTitle, { color: colors.textPrimary }]}
                    numberOfLines={1}
                  >
                    {incident.title || `${incident.threat_type || 'Threat'} Flagged`}
                  </Text>
                  <View style={styles.incidentBadges}>
                    <Badge level={incident.risk_level} />
                    <Badge text={incident.status || 'OPEN'} status={incident.status || 'open'} />
                  </View>
                </View>

                <Text
                  style={[styles.incidentDesc, { color: colors.textSecondary }]}
                  numberOfLines={2}
                >
                  {incident.description || 'Heuristic inspection flagged anomalous telemetry patterns.'}
                </Text>

                <View style={styles.incidentFooter}>
                  <Text style={[styles.incidentMeta, { color: colors.textMuted }]}>
                    {incident.threat_type ? `${incident.threat_type.toUpperCase()} • ` : ''}{timeAgo}
                  </Text>
                  <Text style={[styles.viewDetailsText, { color: colors.textPrimary }]}>
                    Inspect Payload →
                  </Text>
                </View>
              </Card>
            );
          })
        )}
      </ScrollView>

      {/* Gateway Configuration Modal */}
      <Modal
        visible={serverModalVisible}
        transparent={true}
        animationType="fade"
        onRequestClose={() => setServerModalVisible(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={[styles.modalBox, { backgroundColor: colors.card, borderColor: colors.border }]}>
            <View style={styles.modalHeader}>
              <Text style={[styles.modalTitle, { color: colors.textPrimary }]}>
                Gateway Configuration
              </Text>
              <TouchableOpacity onPress={() => setServerModalVisible(false)}>
                <Icon name="close" size={18} color={colors.textSecondary} />
              </TouchableOpacity>
            </View>

            <Text style={[styles.modalDesc, { color: colors.textSecondary }]}>
              Configure backend API target IP and port for local testing or LAN connections:
            </Text>

            <Text style={[styles.inputLabel, { color: colors.textMuted }]}>
              TARGET API ENDPOINT
            </Text>
            <TextInput
              style={[styles.inputField, { backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }]}
              value={inputApiUrl}
              onChangeText={setInputApiUrl}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="http://10.69.135.87:5000/api/v1"
              placeholderTextColor={colors.textMuted}
            />

            <View style={styles.modalActions}>
              <TouchableOpacity
                style={[styles.secondaryBtn, { borderColor: colors.border, backgroundColor: colors.surface }]}
                onPress={handleTestPing}
                disabled={testingPing}
              >
                <Text style={[styles.secondaryBtnText, { color: colors.textPrimary }]}>
                  {testingPing ? 'Testing...' : 'Test Ping'}
                </Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[styles.primaryBtn, { backgroundColor: colors.textPrimary }]}
                onPress={handleSaveServerUrl}
              >
                <Text style={[styles.primaryBtnText, { color: colors.background }]}>
                  Save & Apply
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      <BottomTabBar activeRoute="Dashboard" navigation={navigation} />
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
    paddingBottom: 28
  },

  // Master Console Card
  masterCard: {
    padding: 18,
    marginBottom: 16
  },
  masterHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12
  },
  systemTag: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  pulseDot: {
    width: 7,
    height: 7,
    borderRadius: 3.5
  },
  systemTagText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1.2
  },
  connectionPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
    borderWidth: 1
  },
  connectionPillText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  masterTitle: {
    fontSize: 22,
    fontWeight: '800',
    letterSpacing: -0.2
  },
  masterSubtitle: {
    fontSize: 13,
    marginTop: 4,
    lineHeight: 18
  },

  // Telemetry Strip inside Master Card
  telemetryStrip: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: 16,
    borderRadius: 10,
    borderWidth: 1,
    paddingVertical: 12,
    paddingHorizontal: 10
  },
  telemetryCol: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center'
  },
  telemetryDivider: {
    width: 1,
    height: 36
  },
  telemetryLabel: {
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 0.8
  },
  telemetryValue: {
    fontSize: 22,
    fontWeight: '900',
    marginTop: 3,
    letterSpacing: -0.5
  },
  telemetryPosture: {
    fontSize: 15,
    fontWeight: '900',
    marginTop: 5,
    letterSpacing: 0.5
  },
  telemetrySub: {
    fontSize: 10,
    marginTop: 2
  },

  gatewayBar: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 12,
    paddingVertical: 6,
    gap: 8
  },
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: 3
  },
  gatewayBarText: {
    fontSize: 11,
    fontWeight: '500',
    flex: 1
  },

  // Section Headers
  sectionHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 8,
    marginBottom: 10
  },
  sectionTitle: {
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: 0.2
  },
  viewAllText: {
    fontSize: 12,
    fontWeight: '700'
  },

  // Unified Scanner List Card
  scannerListCard: {
    marginBottom: 16,
    overflow: 'hidden'
  },
  scannerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 14,
    paddingHorizontal: 16,
    gap: 12
  },
  scannerIconSquare: {
    width: 36,
    height: 36,
    borderRadius: 8,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  scannerRowContent: {
    flex: 1
  },
  scannerRowTitle: {
    fontSize: 14,
    fontWeight: '700'
  },
  scannerRowDesc: {
    fontSize: 11,
    marginTop: 2,
    lineHeight: 15
  },
  rowDivider: {
    height: 1,
    marginLeft: 64
  },

  // Action Modules
  actionModuleCard: {
    padding: 14,
    marginBottom: 10
  },
  actionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12
  },
  actionIconBox: {
    width: 36,
    height: 36,
    borderRadius: 8,
    borderWidth: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  actionTextCol: {
    flex: 1
  },
  badgeLine: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 2
  },
  actionTitle: {
    fontSize: 14,
    fontWeight: '700'
  },
  actionDescription: {
    fontSize: 11,
    lineHeight: 15
  },

  // Incident Feed Cards
  incidentFeedCard: {
    padding: 14,
    marginBottom: 10
  },
  incidentCardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6
  },
  incidentTitle: {
    fontSize: 14,
    fontWeight: '700',
    flex: 1
  },
  incidentBadges: {
    flexDirection: 'row',
    gap: 6
  },
  incidentDesc: {
    fontSize: 12,
    lineHeight: 16
  },
  incidentFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 10,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.04)'
  },
  incidentMeta: {
    fontSize: 10,
    fontWeight: '600'
  },
  viewDetailsText: {
    fontSize: 11,
    fontWeight: '700'
  },
  emptyCard: {
    alignItems: 'center',
    paddingVertical: 24,
    paddingHorizontal: 20
  },
  emptyTitle: {
    fontSize: 14,
    fontWeight: '700',
    marginBottom: 4
  },
  emptyText: {
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 17
  },

  // Modal
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.8)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20
  },
  modalBox: {
    width: '100%',
    maxWidth: 420,
    borderRadius: 14,
    borderWidth: 1,
    padding: 20
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8
  },
  modalTitle: {
    fontSize: 16,
    fontWeight: '800'
  },
  modalDesc: {
    fontSize: 12,
    lineHeight: 17,
    marginBottom: 16
  },
  inputLabel: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 6
  },
  inputField: {
    height: 44,
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    fontSize: 13,
    marginBottom: 16
  },
  modalActions: {
    flexDirection: 'row',
    gap: 10
  },
  secondaryBtn: {
    flex: 1,
    height: 42,
    borderWidth: 1,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center'
  },
  secondaryBtnText: {
    fontSize: 13,
    fontWeight: '700'
  },
  primaryBtn: {
    flex: 1,
    height: 42,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center'
  },
  primaryBtnText: {
    fontSize: 13,
    fontWeight: '800'
  }
});
