import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { COLORS } from '../constants/colors';
import { RiskBadge } from './RiskBadge';
import { getRiskColor } from '../utils/riskHelpers';

export function ScanResultCard({ result, scanType = 'URL' }) {
  if (!result) return null;

  const riskLevel = result.risk_level || 'Safe';
  const riskColor = getRiskColor(riskLevel);
  const isCached = Boolean(result.cached);

  const hasScore = result.risk_score !== undefined && result.risk_score !== null;
  const hasConfidence = result.confidence_score !== undefined && result.confidence_score !== null;

  return (
    <View style={[styles.card, { borderLeftColor: riskColor }]}>
      <View style={styles.header}>
        <View style={styles.titleContainer}>
          <Text style={styles.scanTypeLabel}>
            {scanType.toUpperCase()} SCAN RESULT
          </Text>
          {isCached && (
            <View style={styles.cachedChip}>
              <Text style={styles.cachedText}>CACHED THREAT INTEL</Text>
            </View>
          )}
        </View>
        <RiskBadge level={riskLevel} size="medium" />
      </View>

      {/* Optional real metrics returned by backend (e.g. Media deepfake results) */}
      {(hasScore || hasConfidence) && (
        <View style={styles.metricsRow}>
          {hasScore && (
            <View style={styles.metricItem}>
              <Text style={styles.metricLabel}>RISK SCORE</Text>
              <Text style={[styles.metricValue, { color: riskColor }]}>
                {Math.round(Number(result.risk_score))}
                <Text style={styles.metricMax}> / 100</Text>
              </Text>
            </View>
          )}
          {hasConfidence && (
            <View style={styles.metricItem}>
              <Text style={styles.metricLabel}>ANALYSIS CONFIDENCE</Text>
              <Text style={styles.metricValue}>
                {Math.round(Number(result.confidence_score) <= 1 ? Number(result.confidence_score) * 100 : Number(result.confidence_score))}%
              </Text>
            </View>
          )}
        </View>
      )}

      <Text style={styles.explanationLabel}>ANALYSIS VERDICT</Text>
      <Text style={styles.explanationText}>
        {result.explanation || 'No detailed analysis narrative was provided.'}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 18,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderLeftWidth: 4
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 14
  },
  titleContainer: {
    flex: 1,
    marginRight: 10
  },
  scanTypeLabel: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '800',
    marginBottom: 4
  },
  cachedChip: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(0, 240, 255, 0.08)',
    paddingHorizontal: 7,
    paddingVertical: 2,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)'
  },
  cachedText: {
    color: COLORS.primary,
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 0.5
  },
  metricsRow: {
    flexDirection: 'row',
    backgroundColor: COLORS.background,
    borderRadius: 8,
    padding: 12,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    gap: 16
  },
  metricItem: {
    flex: 1
  },
  metricLabel: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '700',
    marginBottom: 2
  },
  metricValue: {
    color: COLORS.textPrimary,
    fontSize: 18,
    fontWeight: '900'
  },
  metricMax: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '500'
  },
  explanationLabel: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 6
  },
  explanationText: {
    color: COLORS.textSecondary,
    fontSize: 14,
    lineHeight: 22
  }
});
