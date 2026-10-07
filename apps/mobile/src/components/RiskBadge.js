import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { getRiskColor, getRiskMutedBg } from '../utils/riskHelpers';

export function RiskBadge({ level = 'Safe', size = 'medium' }) {
  const color = getRiskColor(level);
  const bgColor = getRiskMutedBg(level);
  const isSmall = size === 'small';

  return (
    <View style={[styles.badge, { backgroundColor: bgColor }, isSmall && styles.badgeSmall]}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Text style={[styles.text, { color }, isSmall && styles.textSmall]}>
        {String(level).toUpperCase()}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 9999,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)'
  },
  badgeSmall: {
    paddingHorizontal: 7,
    paddingVertical: 2
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    marginRight: 6
  },
  text: {
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8
  },
  textSmall: {
    fontSize: 10
  }
});
