import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { COLORS } from '../constants/colors';

export function SignalList({ signals = {} }) {
  if (!signals || typeof signals !== 'object') return null;

  const entries = Array.isArray(signals)
    ? signals.map((s, idx) => ({ key: s.signal_name || `Signal ${idx + 1}`, value: s.signal_value }))
    : Object.entries(signals).map(([key, value]) => ({ key, value }));

  if (entries.length === 0) return null;

  const formatKey = (rawKey) => {
    return rawKey
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (char) => char.toUpperCase());
  };

  const formatValue = (val) => {
    if (val === null || val === undefined) return 'None';
    if (typeof val === 'boolean') return val ? 'Detected' : 'Not detected';
    if (Array.isArray(val)) return val.join(', ');
    if (typeof val === 'object') return JSON.stringify(val);
    return String(val);
  };

  return (
    <View style={styles.card}>
      <Text style={styles.heading}>DETECTION SIGNALS & TELEMETRY</Text>
      {entries.map(({ key, value }, index) => (
        <View key={index} style={styles.row}>
          <Text style={styles.keyText}>{formatKey(key)}</Text>
          <Text style={styles.valueText}>{formatValue(value)}</Text>
        </View>
      ))}
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
    borderColor: COLORS.border
  },
  heading: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 12
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 7,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.05)'
  },
  keyText: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '600',
    flex: 1
  },
  valueText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    fontWeight: '500',
    flex: 1,
    textAlign: 'right'
  }
});
