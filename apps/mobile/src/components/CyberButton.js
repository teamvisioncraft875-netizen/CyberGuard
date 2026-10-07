import React from 'react';
import { TouchableOpacity, Text, StyleSheet, ActivityIndicator } from 'react-native';
import { COLORS } from '../constants/colors';

export function CyberButton({
  title,
  onPress,
  loading = false,
  variant = 'primary',
  disabled = false,
  style,
  textStyle
}) {
  const isPrimary = variant === 'primary';
  const isDanger = variant === 'danger';

  let btnBg = COLORS.primary;
  let textColor = COLORS.textInverse;

  if (isDanger) {
    btnBg = COLORS.danger;
    textColor = COLORS.textPrimary;
  } else if (!isPrimary) {
    btnBg = COLORS.surface;
    textColor = COLORS.textPrimary;
  }

  return (
    <TouchableOpacity
      activeOpacity={0.8}
      style={[
        styles.button,
        { backgroundColor: btnBg },
        disabled && styles.disabled,
        style
      ]}
      onPress={onPress}
      disabled={disabled || loading}
    >
      {loading ? (
        <ActivityIndicator color={textColor} size="small" />
      ) : (
        <Text style={[styles.text, { color: textColor }, textStyle]}>
          {title}
        </Text>
      )}
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    height: 48,
    borderRadius: 10,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20
  },
  disabled: {
    opacity: 0.5
  },
  text: {
    fontSize: 15,
    fontWeight: '700',
    letterSpacing: 0.5
  }
});
