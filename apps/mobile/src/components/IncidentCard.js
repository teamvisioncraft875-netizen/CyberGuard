import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { COLORS } from '../constants/colors';
import { RiskBadge } from './RiskBadge';
import { formatThreatType, getRiskColor } from '../utils/riskHelpers';
import { formatDate, truncate } from '../utils/formatters';

export function IncidentCard({ incident, onPress }) {
  if (!incident) return null;

  const riskScore = incident.risk_score != null ? Math.round(Number(incident.risk_score)) : null;
  const riskColor = getRiskColor(incident.risk_level);

  return (
    <TouchableOpacity
      activeOpacity={0.75}
      style={[styles.card, { borderLeftColor: riskColor }]}
      onPress={onPress}
    >
      <View style={styles.header}>
        <View style={styles.titleRow}>
          <Text style={styles.threatType}>{formatThreatType(incident.threat_type)}</Text>
          <Text style={styles.time}>{formatDate(incident.created_at)}</Text>
        </View>
        <RiskBadge level={incident.risk_level || 'Safe'} size="small" />
      </View>

      <Text style={styles.explanation} numberOfLines={2}>
        {incident.explanation || 'No threat context provided.'}
      </Text>

      <View style={styles.footer}>
        <View style={styles.scoreContainer}>
          <Text style={styles.scoreLabel}>RISK SCORE:</Text>
          <Text style={[styles.scoreValue, { color: riskColor }]}>
            {riskScore !== null ? `${riskScore}/100` : 'N/A'}
          </Text>
        </View>
        <View style={styles.statusBadge}>
          <Text style={styles.statusText}>
            {incident.status ? incident.status.toUpperCase() : 'OPEN'}
          </Text>
        </View>
      </View>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 12,
    padding: 14,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderLeftWidth: 4
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8
  },
  titleRow: {
    flex: 1,
    marginRight: 8
  },
  threatType: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700',
    marginBottom: 2
  },
  time: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  explanation: {
    color: COLORS.textSecondary,
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 10
  },
  footer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.05)'
  },
  scoreContainer: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  scoreLabel: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '700',
    marginRight: 4
  },
  scoreValue: {
    fontSize: 12,
    fontWeight: '800'
  },
  statusBadge: {
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4
  },
  statusText: {
    color: COLORS.textMuted,
    fontSize: 10,
    fontWeight: '700'
  }
});
