import React from 'react';
import {
  TouchableOpacity,
  Text,
  ActivityIndicator,
  StyleSheet,
  View
} from 'react-native';
import { useTheme } from '../context/ThemeContext';

export function Button({
  title,
  label,
  onPress,
  variant = 'primary', // 'primary' | 'secondary' | 'danger' | 'ghost'
  loading = false,
  disabled = false,
  icon = null,
  style,
  textStyle
}) {
  const { colors, isDark } = useTheme();
  const textContent = title || label;

  let bg = colors.textPrimary;
  let textColor = colors.background;
  let borderWidth = 0;
  let borderColor = 'transparent';

  if (variant === 'secondary') {
    bg = colors.surface;
    textColor = colors.textPrimary;
    borderWidth = 1;
    borderColor = colors.border;
  } else if (variant === 'danger') {
    bg = colors.danger;
    textColor = '#FFFFFF';
  } else if (variant === 'ghost') {
    bg = 'transparent';
    textColor = colors.textPrimary;
  }

  return (
    <TouchableOpacity
      style={[
        styles.button,
        {
          backgroundColor: bg,
          borderColor,
          borderWidth,
          opacity: disabled || loading ? 0.6 : 1
        },
        style
      ]}
      onPress={onPress}
      disabled={disabled || loading}
      activeOpacity={0.8}
      accessibilityRole="button"
    >
      {loading ? (
        <ActivityIndicator
          size="small"
          color={textColor}
        />
      ) : (
        <View style={styles.contentRow}>
          {icon && <View style={styles.iconBox}>{icon}</View>}
          <Text style={[styles.text, { color: textColor }, textStyle]}>
            {textContent}
          </Text>
        </View>
      )}
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    height: 46,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 16
  },
  contentRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8
  },
  iconBox: {
    justifyContent: 'center',
    alignItems: 'center'
  },
  text: {
    fontSize: 14,
    fontWeight: '800',
    letterSpacing: 0.2
  }
});

export default Button;
