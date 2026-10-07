import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  SafeAreaView
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useAuth } from '../../hooks/useAuth';
import { useIncidents } from '../../hooks/useIncidents';
import { useSocket } from '../../hooks/useSocket';
import { CyberHeader } from '../../components/CyberHeader';
import { StatusBanner } from '../../components/StatusBanner';
import { MetricCard } from '../../components/MetricCard';
import { IncidentCard } from '../../components/IncidentCard';

export function DashboardScreen({ navigation }) {
  const { user } = useAuth();
  const { isConnected } = useSocket();
  const { incidents, total, refreshing, refetch } = useIncidents();

  // Compute metrics from actual fetched incident records
  const criticalHighCount = incidents.filter(
    (i) => i.risk_level === 'critical' || i.risk_level === 'high'
  ).length;

  const openCount = incidents.filter(
    (i) => !i.status || i.status === 'open' || i.status === 'investigating'
  ).length;

  const resolvedCount = incidents.filter((i) => i.status === 'resolved').length;

  const highestRisk = criticalHighCount > 0 ? 'CRITICAL' : (incidents.length > 0 ? 'ELEVATED' : 'SECURE');
  const postureColor = highestRisk === 'CRITICAL' ? COLORS.danger : (highestRisk === 'ELEVATED' ? COLORS.warning : COLORS.safe);

  const recentIncidents = incidents.slice(0, 5);

  return (
    <SafeAreaView style={styles.safeArea}>
      <CyberHeader
        title="Security Console"
        subtitle={`Welcome back, ${user?.email ? user.email.split('@')[0] : 'Operator'}`}
      />

      <ScrollView
        style={styles.container}
        contentContainerStyle={styles.content}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={refetch}
            tintColor={COLORS.primary}
            colors={[COLORS.primary]}
          />
        }
      >
        {/* Status / Socket Banner */}
        <StatusBanner isConnected={isConnected} totalCount={total} />

        {/* Defense Posture Metrics */}
        <View style={styles.metricsGrid}>
          <View style={styles.metricsRow}>
            <MetricCard
              label="Active Threats"
              value={openCount}
              color={openCount > 0 ? COLORS.danger : COLORS.safe}
              subtitle="Pending review"
            />
            <MetricCard
              label="High / Critical"
              value={criticalHighCount}
              color={COLORS.critical}
              subtitle="Urgent mitigation"
            />
          </View>

          <View style={styles.metricsRow}>
            <MetricCard
              label="Resolved"
              value={resolvedCount}
              color={COLORS.safe}
              subtitle="Attacks mitigated"
            />
            <MetricCard
              label="Threat Posture"
              value={highestRisk}
              color={postureColor}
              subtitle="Autonomous status"
            />
          </View>
        </View>

        {/* Threat Scanners Hub CTA */}
        <View style={styles.scannerHubCard}>
          <View style={styles.scannerHubHeader}>
            <View>
              <Text style={styles.scannerHubTitle}>Threat Defense Scanners</Text>
              <Text style={styles.scannerHubSubtitle}>
                On-demand inspection for links, messages, media, and credentials
              </Text>
            </View>
            <TouchableOpacity
              onPress={() => navigation.navigate('ScannerHome')}
              style={styles.allScannersBtn}
            >
              <Text style={styles.allScannersText}>All →</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.scannerActionRow}>
            <TouchableOpacity
              style={styles.scannerActionButton}
              activeOpacity={0.8}
              onPress={() => navigation.navigate('UrlScanner')}
            >
              <Text style={styles.scannerActionIcon}>🔗</Text>
              <View style={styles.scannerActionTextCol}>
                <Text style={styles.scannerActionTitle}>URL Scanner</Text>
                <Text style={styles.scannerActionDesc}>Malicious links</Text>
              </View>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.scannerActionButton}
              activeOpacity={0.8}
              onPress={() => navigation.navigate('MessageScanner')}
            >
              <Text style={styles.scannerActionIcon}>💬</Text>
              <View style={styles.scannerActionTextCol}>
                <Text style={styles.scannerActionTitle}>Message</Text>
                <Text style={styles.scannerActionDesc}>Phishing & fraud</Text>
              </View>
            </TouchableOpacity>
          </View>

          <View style={[styles.scannerActionRow, { marginTop: 8 }]}>
            <TouchableOpacity
              style={styles.scannerActionButton}
              activeOpacity={0.8}
              onPress={() => navigation.navigate('MediaScanner')}
            >
              <Text style={styles.scannerActionIcon}>🎙️</Text>
              <View style={styles.scannerActionTextCol}>
                <Text style={styles.scannerActionTitle}>Media Scanner</Text>
                <Text style={styles.scannerActionDesc}>Deepfake audio/img</Text>
              </View>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.scannerActionButton}
              activeOpacity={0.8}
              onPress={() => navigation.navigate('SecretScanner')}
            >
              <Text style={styles.scannerActionIcon}>🔑</Text>
              <View style={styles.scannerActionTextCol}>
                <Text style={styles.scannerActionTitle}>Secret Scanner</Text>
                <Text style={styles.scannerActionDesc}>Leaked credentials</Text>
              </View>
            </TouchableOpacity>
          </View>
        </View>

        {/* Guardian Mode Shield CTA */}
        <TouchableOpacity
          style={styles.guardianCtaCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('Guardian')}
          accessibilityLabel="Open Guardian Mode"
          accessibilityRole="button"
        >
          <View style={styles.guardianIconBox}>
            <Text style={styles.guardianIcon}>🛡️</Text>
          </View>
          <View style={styles.guardianInfo}>
            <View style={styles.guardianBadgeRow}>
              <Text style={styles.guardianTitle}>Guardian Mode</Text>
              <View style={styles.guardianActiveChip}>
                <Text style={styles.guardianActiveChipText}>FAMILY SHIELD</Text>
              </View>
            </View>
            <Text style={styles.guardianDesc}>
              Protect dependents and receive instant alerts on high-risk threats
            </Text>
          </View>
          <Text style={styles.guardianArrow}>→</Text>
        </TouchableOpacity>

        {/* Security Activity & Telemetry Tile */}
        <TouchableOpacity
          style={styles.activityCtaCard}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('SecurityActivity')}
          accessibilityLabel="Open Security Activity and Telemetry"
          accessibilityRole="button"
        >
          <View style={styles.activityIconBox}>
            <Text style={styles.activityIcon}>⚡</Text>
          </View>
          <View style={styles.activityInfo}>
            <View style={styles.activityBadgeRow}>
              <Text style={styles.activityTitle}>Security Activity</Text>
              <View style={styles.activityLiveChip}>
                <Text style={styles.activityLiveChipText}>TELEMETRY</Text>
              </View>
            </View>
            <Text style={styles.activityDesc}>
              Session telemetry, authentication audit & account threat events
            </Text>
          </View>
          <Text style={styles.activityArrow}>→</Text>
        </TouchableOpacity>

        {/* Quick Triage Feed CTA */}
        <TouchableOpacity
          style={styles.feedCta}
          activeOpacity={0.8}
          onPress={() => navigation.navigate('IncidentList')}
        >
          <View>
            <Text style={styles.feedCtaTitle}>Open Incident Triage Feed</Text>
            <Text style={styles.feedCtaSubtitle}>
              View complete chronological incident stream & filter by risk
            </Text>
          </View>
          <Text style={styles.feedCtaArrow}>→</Text>
        </TouchableOpacity>

        {/* Recent Threat Activity */}
        <View style={styles.recentSection}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>RECENT THREAT ACTIVITY</Text>
            <TouchableOpacity onPress={() => navigation.navigate('IncidentList')}>
              <Text style={styles.viewAllText}>View All ({total})</Text>
            </TouchableOpacity>
          </View>

          {recentIncidents.length === 0 ? (
            <View style={styles.emptyCard}>
              <Text style={styles.emptyIcon}>🛡️</Text>
              <Text style={styles.emptyTitle}>No Security Incidents</Text>
              <Text style={styles.emptySubtitle}>
                No threats detected for your account. CyberGuard background sensors are actively monitoring.
              </Text>
            </View>
          ) : (
            recentIncidents.map((incident) => (
              <IncidentCard
                key={incident.id}
                incident={incident}
                onPress={() => navigation.navigate('IncidentDetail', { id: incident.id })}
              />
            ))
          )}
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
  container: {
    flex: 1
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  metricsGrid: {
    marginBottom: 16
  },
  metricsRow: {
    flexDirection: 'row',
    marginBottom: 8
  },
  scannerHubCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)',
    marginBottom: 14
  },
  scannerHubHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 14
  },
  scannerHubTitle: {
    color: COLORS.primary,
    fontSize: 16,
    fontWeight: '800'
  },
  scannerHubSubtitle: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 2
  },
  allScannersBtn: {
    paddingHorizontal: 8,
    paddingVertical: 4
  },
  allScannersText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '800'
  },
  scannerActionRow: {
    flexDirection: 'row',
    gap: 8
  },
  scannerActionButton: {
    flex: 1,
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    flexDirection: 'row',
    alignItems: 'center'
  },
  scannerActionIcon: {
    fontSize: 20,
    marginRight: 8
  },
  scannerActionTextCol: {
    flex: 1
  },
  scannerActionTitle: {
    color: COLORS.textPrimary,
    fontSize: 12,
    fontWeight: '700'
  },
  scannerActionDesc: {
    color: COLORS.textMuted,
    fontSize: 10,
    marginTop: 1
  },
  feedCta: {
    backgroundColor: COLORS.card,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 12,
    padding: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 20
  },
  feedCtaTitle: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '800'
  },
  feedCtaSubtitle: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 2
  },
  feedCtaArrow: {
    color: COLORS.primary,
    fontSize: 22,
    fontWeight: '900',
    marginLeft: 10
  },
  guardianCtaCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.35)',
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16
  },
  guardianIconBox: {
    width: 44,
    height: 44,
    borderRadius: 12,
    backgroundColor: 'rgba(0, 240, 255, 0.1)',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.25)'
  },
  guardianIcon: {
    fontSize: 22
  },
  guardianInfo: {
    flex: 1
  },
  guardianBadgeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 3
  },
  guardianTitle: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '800'
  },
  guardianActiveChip: {
    backgroundColor: 'rgba(0, 240, 255, 0.12)',
    paddingHorizontal: 6,
    paddingVertical: 1,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  guardianActiveChipText: {
    color: COLORS.primary,
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  guardianDesc: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 16
  },
  guardianArrow: {
    color: COLORS.primary,
    fontSize: 22,
    fontWeight: '900',
    marginLeft: 8
  },
  activityCtaCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(168, 85, 247, 0.08)',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: 'rgba(168, 85, 247, 0.3)',
    padding: 14,
    marginBottom: 16
  },
  activityIconBox: {
    width: 44,
    height: 44,
    borderRadius: 12,
    backgroundColor: 'rgba(168, 85, 247, 0.16)',
    borderWidth: 1,
    borderColor: 'rgba(168, 85, 247, 0.35)',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12
  },
  activityIcon: {
    fontSize: 22
  },
  activityInfo: {
    flex: 1
  },
  activityBadgeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 3
  },
  activityTitle: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '800'
  },
  activityLiveChip: {
    backgroundColor: 'rgba(168, 85, 247, 0.16)',
    paddingHorizontal: 6,
    paddingVertical: 1,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(168, 85, 247, 0.4)'
  },
  activityLiveChipText: {
    color: '#a855f7',
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  activityDesc: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 16
  },
  activityArrow: {
    color: '#a855f7',
    fontSize: 22,
    fontWeight: '900',
    marginLeft: 8
  },
  recentSection: {
    marginTop: 4
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12
  },
  sectionTitle: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '800',
    letterSpacing: 1
  },
  viewAllText: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '700'
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 30,
    alignItems: 'center',
    justifyContent: 'center'
  },
  emptyIcon: {
    fontSize: 36,
    marginBottom: 10
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 4
  },
  emptySubtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 18
  }
});
