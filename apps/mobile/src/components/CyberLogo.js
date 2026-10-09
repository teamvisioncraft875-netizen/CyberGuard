import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useTheme } from '../context/ThemeContext';

export function CyberLogo({ size = 32, showText = true, onPress }) {
  const { colors } = useTheme();

  const Container = onPress ? TouchableOpacity : View;

  return (
    <Container
      style={styles.container}
      onPress={onPress}
      activeOpacity={0.8}
      accessibilityLabel="CYBERGUARD Home"
      accessibilityRole={onPress ? 'button' : 'none'}
    >
      {/* Precision Monochrome Shield Icon */}
      <View
        style={[
          styles.shieldBox,
          {
            width: size,
            height: size,
            borderColor: colors.borderActive || '#444444',
            backgroundColor: colors.surface
          }
        ]}
      >
        <View style={[styles.innerCore, { backgroundColor: colors.textPrimary }]} />
      </View>

      {showText && (
        <View style={styles.textCol}>
          <Text style={[styles.brandText, { color: colors.textPrimary }]}>
            CYBERGUARD
          </Text>
          <Text style={[styles.subText, { color: colors.textSecondary }]}>
            ENTERPRISE DEFENSE
          </Text>
        </View>
      )}
    </Container>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10
  },
  shieldBox: {
    borderRadius: 8,
    borderWidth: 1.5,
    justifyContent: 'center',
    alignItems: 'center',
    position: 'relative'
  },
  innerCore: {
    width: 7,
    height: 7,
    borderRadius: 2,
    transform: [{ rotate: '45deg' }]
  },
  textCol: {
    justifyContent: 'center'
  },
  brandText: {
    fontSize: 14,
    fontWeight: '900',
    letterSpacing: 1.8,
    lineHeight: 16
  },
  subText: {
    fontSize: 8,
    fontWeight: '800',
    letterSpacing: 1.2,
    lineHeight: 10,
    marginTop: 2
  }
});
