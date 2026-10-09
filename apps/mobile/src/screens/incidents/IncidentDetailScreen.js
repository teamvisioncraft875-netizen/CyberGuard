import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  ActivityIndicator,
  SafeAreaView
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useTheme } from '../../context/ThemeContext';
import { AppHeader } from '../../components/AppHeader';
import { incidentService } from '../../services/incidentService';
import { RiskBadge } from '../../components/RiskBadge';
import { formatThreatType, getRiskColor } from '../../utils/riskHelpers';
import { formatDate } from '../../utils/formatters';

export function IncidentDetailScreen({ route, navigation }) {
  const { id } = route.params || {};
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadIncident() {
      if (!id) return;
      setLoading(true);
      setError(null);
      try {
        const data = await incidentService.getIncidentById(id);
        setIncident(data);
      } catch (err) {
        console.warn('[IncidentDetailScreen.loadIncident]', err.message);
        setError(err.message || 'Failed to retrieve incident details');
      } finally {
        setLoading(false);
      }
    }

    loadIncident();
  }, [id]);

  if (loading) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color={COLORS.primary} />
          <Text style={styles.loadingText}>Fetching Incident Forensics...</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (error || !incident) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.errorContainer}>
          <Text style={styles.errorIcon}>⚠️</Text>
          <Text style={styles.errorTitle}>Incident Not Found</Text>
          <Text style={styles.errorSubtitle}>
            {error || 'The requested incident record could not be loaded.'}
          </Text>
          <TouchableOpacity
            style={styles.retryBtn}
            onPress={() => navigation.goBack()}
          >
            <Text style={styles.retryBtnText}>Return to Incident Feed</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  const riskScore = incident.risk_score != null ? Math.round(Number(incident.risk_score)) : null;
  const riskColor = getRiskColor(incident.risk_level);
  const actions = incident.recommended_actions || [];
  const signals = incident.detection_signals || incident.signals || {};
  const mitreList = incident.mitre_mappings || [];

  const { colors } = useTheme();

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="Incident Detail" showBack={true} navigation={navigation} />

      <ScrollView contentContainerStyle={styles.content}>
        {/* Threat Overview Banner */}
        <View style={[styles.card, { borderLeftColor: riskColor, borderLeftWidth: 4 }]}>
          <View style={styles.bannerRow}>
            <View>
              <Text style={styles.threatTypeLabel}>
                {formatThreatType(incident.threat_type)}
              </Text>
              <Text style={styles.timestampText}>
                Detected {formatDate(incident.created_at)}
              </Text>
            </View>
            <RiskBadge level={incident.risk_level || 'Safe'} size="medium" />
          </View>

          {/* Risk Score Meter */}
          {riskScore !== null && (
            <View style={styles.scoreRow}>
              <View style={styles.scoreGauge}>
                <Text style={styles.scoreLabel}>ANALYZED RISK SCORE</Text>
                <Text style={[styles.scoreValue, { color: riskColor }]}>
                  {riskScore} <Text style={styles.scoreMax}>/ 100</Text>
                </Text>
              </View>
              <View style={styles.statusBox}>
                <Text style={styles.statusBoxLabel}>STATUS</Text>
                <Text style={styles.statusBoxValue}>
                  {incident.status ? incident.status.toUpperCase() : 'OPEN'}
                </Text>
              </View>
            </View>
          )}
        </View>

        {/* Threat Explanation / Narrative */}
        <View style={styles.card}>
          <Text style={styles.sectionHeading}>INCIDENT EXPLANATION</Text>
          <Text style={styles.explanationText}>
            {incident.explanation || 'No detailed analysis narrative provided.'}
          </Text>
        </View>

        {/* Recommended Countermeasures */}
        {actions.length > 0 && (
          <View style={styles.card}>
            <Text style={styles.sectionHeading}>RECOMMENDED ACTIONS</Text>
            {actions.map((act, index) => {
              const actText = typeof act === 'string' ? act : (act.action_type || act.action_text || 'Remediation step');
              return (
                <View key={index} style={styles.actionItem}>
                  <View style={styles.actionBullet}>
                    <Text style={styles.bulletNumber}>{index + 1}</Text>
                  </View>
                  <Text style={styles.actionText}>{actText}</Text>
                </View>
              );
            })}
          </View>
        )}

        {/* MITRE ATT&CK Mapping */}
        {mitreList.length > 0 && (
          <View style={styles.card}>
            <Text style={styles.sectionHeading}>MITRE ATT&CK CONTEXT</Text>
            {mitreList.map((m, idx) => (
              <View key={idx} style={styles.mitreChip}>
                <Text style={styles.mitreId}>{m.technique_id}</Text>
                <Text style={styles.mitreName}>{m.technique_name}</Text>
              </View>
            ))}
          </View>
        )}

        {/* Forensics / Signals */}
        {typeof signals === 'object' && Object.keys(signals).length > 0 && (
          <View style={styles.card}>
            <Text style={styles.sectionHeading}>DETECTION SIGNALS & TELEMETRY</Text>
            {Array.isArray(signals) ? (
              signals.map((sig, i) => (
                <View key={i} style={styles.signalRow}>
                  <Text style={styles.signalKey}>
                    {sig.signal_type || `Signal ${i + 1}`}
                  </Text>
                  <Text style={styles.signalVal}>
                    {typeof sig.signal_value === 'object'
                      ? JSON.stringify(sig.signal_value)
                      : String(sig.signal_value || '')}
                  </Text>
                </View>
              ))
            ) : (
              Object.entries(signals).map(([key, val]) => (
                <View key={key} style={styles.signalRow}>
                  <Text style={styles.signalKey}>{key}</Text>
                  <Text style={styles.signalVal}>
                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                  </Text>
                </View>
              ))
            )}
          </View>
        )}

        {/* Metadata Footer */}
        <View style={styles.metaBox}>
          <Text style={styles.metaText}>
            Source: {incident.source_type || 'Automated sensor'} • Status: {incident.status || 'open'}
          </Text>
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
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  backBtn: {},
  backBtnText: {
    color: COLORS.primary,
    fontSize: 14,
    fontWeight: '700'
  },
  headerId: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '600',
    maxWidth: 180
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center'
  },
  loadingText: {
    color: COLORS.textSecondary,
    fontSize: 13,
    marginTop: 12
  },
  errorContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24
  },
  errorIcon: {
    fontSize: 40,
    marginBottom: 12
  },
  errorTitle: {
    color: COLORS.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 6
  },
  errorSubtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    textAlign: 'center',
    marginBottom: 20
  },
  retryBtn: {
    backgroundColor: COLORS.surface,
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  retryBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  bannerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 14
  },
  threatTypeLabel: {
    color: COLORS.textPrimary,
    fontSize: 17,
    fontWeight: '800',
    marginBottom: 4
  },
  timestampText: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  scoreRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    backgroundColor: COLORS.background,
    borderRadius: 8,
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  scoreGauge: {},
  scoreLabel: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '700',
    marginBottom: 2
  },
  scoreValue: {
    fontSize: 22,
    fontWeight: '900'
  },
  scoreMax: {
    color: COLORS.textMuted,
    fontSize: 13,
    fontWeight: '500'
  },
  statusBox: {
    alignItems: 'flex-end',
    justifyContent: 'center'
  },
  statusBoxLabel: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '700',
    marginBottom: 2
  },
  statusBoxValue: {
    color: COLORS.textPrimary,
    fontSize: 13,
    fontWeight: '800'
  },
  sectionHeading: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 10
  },
  explanationText: {
    color: COLORS.textSecondary,
    fontSize: 14,
    lineHeight: 22
  },
  actionItem: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 10
  },
  actionBullet: {
    width: 20,
    height: 20,
    borderRadius: 10,
    backgroundColor: COLORS.primaryMuted,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 10,
    marginTop: 2
  },
  bulletNumber: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800'
  },
  actionText: {
    color: COLORS.textPrimary,
    fontSize: 13,
    lineHeight: 18,
    flex: 1
  },
  mitreChip: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.background,
    padding: 10,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 8
  },
  mitreId: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '800',
    marginRight: 8
  },
  mitreName: {
    color: COLORS.textSecondary,
    fontSize: 12,
    flex: 1
  },
  signalRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.04)'
  },
  signalKey: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '600',
    flex: 1
  },
  signalVal: {
    color: COLORS.textSecondary,
    fontSize: 12,
    fontWeight: '500',
    flex: 1,
    textAlign: 'right'
  },
  metaBox: {
    alignItems: 'center',
    paddingVertical: 10
  },
  metaText: {
    color: COLORS.textMuted,
    fontSize: 11
  }
});
