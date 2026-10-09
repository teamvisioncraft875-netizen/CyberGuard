import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  SafeAreaView
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useTheme } from '../../context/ThemeContext';
import { AppHeader } from '../../components/AppHeader';
import { ScanResultCard } from '../../components/ScanResultCard';
import { DetectedSecretList } from '../../components/DetectedSecretList';
import { RecommendationList } from '../../components/RecommendationList';
import { SignalList } from '../../components/SignalList';
import { CyberButton } from '../../components/CyberButton';

export function ScanResultScreen({ route, navigation }) {
  const { result, scanType = 'Security', targetSummary } = route.params || {};

  if (!result) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyTitle}>No Scan Result Available</Text>
          <TouchableOpacity
            style={styles.returnBtn}
            onPress={() => navigation.navigate('ScannerHome')}
          >
            <Text style={styles.returnBtnText}>Return to Scanners</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  // Only link if the backend explicitly provides a verified incident_id
  const hasVerifiedIncident = Boolean(result.incident_id);
  const actions = result.recommended_actions || [];
  const signals = result.signals || {};

  const { colors } = useTheme();

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader
        title="Threat Analysis Report"
        showBack={true}
        onBack={() => navigation.navigate('ScannerHome')}
        navigation={navigation}
      />

      <ScrollView contentContainerStyle={styles.content}>
        {/* Main Verdict Card */}
        <ScanResultCard result={result} scanType={scanType} />

        {/* Identified Exposed Secrets (Only if detected_secrets is present) */}
        {result.detected_secrets && result.detected_secrets.length > 0 ? (
          <DetectedSecretList detectedSecrets={result.detected_secrets} />
        ) : null}

        {/* Verified Incident Linking (Only rendered if explicit incident_id is present) */}
        {hasVerifiedIncident ? (
          <TouchableOpacity
            style={styles.incidentLinkCard}
            activeOpacity={0.8}
            onPress={() => navigation.navigate('IncidentDetail', { id: result.incident_id })}
          >
            <View style={styles.incidentLinkInfo}>
              <Text style={styles.incidentLinkTitle}>INCIDENT RECORD GENERATED</Text>
              <Text style={styles.incidentLinkSubtitle}>
                ID: {result.incident_id} • Recorded in personal incident stream
              </Text>
            </View>
            <Text style={styles.incidentLinkArrow}>→</Text>
          </TouchableOpacity>
        ) : null}

        {/* Countermeasures & Recommended Actions */}
        <RecommendationList actions={actions} />

        {/* Detection Signals */}
        <SignalList signals={signals} />

        {/* Bottom Actions */}
        <View style={styles.bottomActions}>
          <CyberButton
            title="Scan Another Target"
            onPress={() => navigation.navigate('ScannerHome')}
            variant="secondary"
          />
        </View>
      </ScrollView>
    </View>
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
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 12,
    marginTop: 2
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  incidentLinkCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.35)',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  incidentLinkInfo: {
    flex: 1,
    marginRight: 10
  },
  incidentLinkTitle: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '800',
    letterSpacing: 0.8,
    marginBottom: 2
  },
  incidentLinkSubtitle: {
    color: COLORS.textSecondary,
    fontSize: 11
  },
  incidentLinkArrow: {
    color: COLORS.primary,
    fontSize: 22,
    fontWeight: '900'
  },
  bottomActions: {
    marginTop: 8
  },
  emptyContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 16
  },
  returnBtn: {
    backgroundColor: COLORS.surface,
    paddingHorizontal: 18,
    paddingVertical: 10,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  returnBtnText: {
    color: COLORS.primary,
    fontSize: 14,
    fontWeight: '700'
  }
});
