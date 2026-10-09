import React from 'react';
import { View, StyleSheet, TouchableOpacity, Platform } from 'react-native';
import { useTheme } from '../context/ThemeContext';

export function Card({
  children,
  style,
  onPress,
  variant = 'default',
  borderColor,
  accentBorderTop,
  accentBorderLeft,
  activeOpacity = 0.75,
  padding = 16
}) {
  const { colors, isDark } = useTheme();

  const Container = onPress ? TouchableOpacity : View;

  // Variant border and surface adjustments
  let variantBorder = borderColor || colors.border;
  let variantBg = colors.card;

  if (variant === 'danger') {
    variantBorder = colors.danger;
  } else if (variant === 'warning') {
    variantBorder = colors.warning;
  } else if (variant === 'success') {
    variantBorder = colors.success;
  } else if (variant === 'elevated') {
    variantBg = isDark ? colors.cardElevated : '#FFFFFF';
  }

  return (
    <Container
      style={[
        styles.card,
        {
          backgroundColor: variantBg,
          borderColor: variantBorder,
          padding
        },
        accentBorderTop && {
          borderTopWidth: 2,
          borderTopColor: accentBorderTop
        },
        accentBorderLeft && {
          borderLeftWidth: 3,
          borderLeftColor: accentBorderLeft
        },
        isDark ? styles.darkShadow : styles.lightShadow,
        style
      ]}
      onPress={onPress}
      activeOpacity={activeOpacity}
      accessibilityRole={onPress ? 'button' : 'none'}
    >
      {/* Subtle top edge highlight line in dark mode */}
      {isDark && !accentBorderTop && (
        <View
          pointerEvents="none"
          style={[styles.topHighlight, { backgroundColor: 'rgba(255, 255, 255, 0.03)' }]}
        />
      )}
      {children}
    </Container>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: 14,
    borderWidth: 1,
    marginBottom: 12,
    position: 'relative',
    overflow: 'hidden'
  },
  topHighlight: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: 1
  },
  darkShadow: {
    ...Platform.select({
      ios: {
        shadowColor: '#000000',
        shadowOffset: { width: 0, height: 3 },
        shadowOpacity: 0.6,
        shadowRadius: 6
      },
      android: {
        elevation: 2
      }
    })
  },
  lightShadow: {
    ...Platform.select({
      ios: {
        shadowColor: '#000000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.05,
        shadowRadius: 6
      },
      android: {
        elevation: 1
      }
    })
  }
});
