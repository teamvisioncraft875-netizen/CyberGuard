import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { COLORS } from '../constants/colors';

export function RecommendationList({ actions = [] }) {
  if (!actions || actions.length === 0) return null;

  return (
    <View style={styles.card}>
      <Text style={styles.heading}>RECOMMENDED ACTIONS</Text>
      {actions.map((act, index) => {
        const text = typeof act === 'string' ? act : (act.action_type || act.action_text || 'Remediation step');
        return (
          <View key={index} style={styles.actionRow}>
            <View style={styles.numberBadge}>
              <Text style={styles.numberText}>{index + 1}</Text>
            </View>
            <Text style={styles.actionText}>{text}</Text>
          </View>
        );
      })}
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
    marginBottom: 14
  },
  actionRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 12
  },
  numberBadge: {
    width: 22,
    height: 22,
    borderRadius: 11,
    backgroundColor: COLORS.primaryMuted,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 10,
    marginTop: 1,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.25)'
  },
  numberText: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800'
  },
  actionText: {
    color: COLORS.textPrimary,
    fontSize: 13,
    lineHeight: 19,
    flex: 1
  }
});
