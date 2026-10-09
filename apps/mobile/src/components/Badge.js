import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { useTheme } from '../context/ThemeContext';

export function Badge({
  text,
  level, // 'critical' | 'high' | 'medium' | 'low' | 'safe'
  status, // 'active' | 'inactive' | 'pending' | 'open' | 'resolved'
  variant = 'subtle', // 'subtle' | 'solid'
  style,
  textStyle
}) {
  const { colors, isDark } = useTheme();

  const normalized = (level || status || text || '').toLowerCase();

  let baseColor = colors.textSecondary;
  let bg = colors.surface;
  let borderColor = colors.border;

  if (normalized === 'critical' || normalized === 'high') {
    baseColor = colors.danger;
    bg = colors.dangerBg;
    borderColor = colors.danger;
  } else if (normalized === 'medium' || normalized === 'warning') {
    baseColor = colors.warning;
    bg = colors.warningBg;
    borderColor = colors.warning;
  } else if (normalized === 'safe' || normalized === 'active' || normalized === 'resolved' || normalized === 'secure' || normalized === 'armed') {
    baseColor = colors.success;
    bg = colors.successBg;
    borderColor = colors.success;
  } else if (normalized === 'open' || normalized === 'investigating' || normalized === 'alert') {
    baseColor = '#E5E5E5';
    bg = '#222222';
    borderColor = '#444444';
  }

  const labelText = (text || level || status || '').toUpperCase();
  const isSolid = variant === 'solid';

  return (
    <View
      style={[
        styles.badge,
        isSolid
          ? { backgroundColor: baseColor }
          : {
              backgroundColor: bg,
              borderColor: borderColor,
              borderWidth: 1
            },
        style
      ]}
    >
      <Text
        style={[
          styles.text,
          {
            color: isSolid ? (isDark ? '#000000' : '#FFFFFF') : baseColor
          },
          textStyle
        ]}
      >
        {labelText}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    alignSelf: 'flex-start',
    justifyContent: 'center',
    alignItems: 'center'
  },
  text: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.6
  }
});

export default Badge;
