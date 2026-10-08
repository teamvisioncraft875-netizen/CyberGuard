import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { COLORS } from '../constants/colors';

export function StatusBanner({ isConnected = true, totalCount = 0 }) {
  return (
    <View style={styles.banner}>
      <View style={styles.left}>
        <View
          style={[
            styles.pulseDot,
            { backgroundColor: isConnected ? COLORS.safe : COLORS.warning }
          ]}
        />
        <Text style={styles.statusText}>
          {isConnected ? 'GUARD SHIELD ACTIVE' : 'RECONNECTING TELEMETRY'}
        </Text>
      </View>
      <View style={styles.right}>
        <Text style={styles.statLabel}>
          INCIDENTS: <Text style={styles.statVal}>{totalCount}</Text>
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  banner: {
    backgroundColor: COLORS.cardSecondary,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 16
  },
  left: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  pulseDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 8
  },
  statusText: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 0.8
  },
  right: {},
  statLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '600'
  },
  statVal: {
    color: COLORS.primary,
    fontWeight: '700'
  }
});
