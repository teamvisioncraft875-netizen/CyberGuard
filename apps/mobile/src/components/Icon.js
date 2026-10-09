import React from 'react';
import { Text, StyleSheet, View } from 'react-native';

const ICON_MAP = {
  // Navigation & Branding
  shield: '🛡',
  home: '⌂',
  scan: '⌕',
  activity: '⚡',
  guardian: '🛡',
  settings: '⚙',
  user: '👤',

  // System & Header
  sun: '☼',
  moon: '☾',
  copilot: '✦',
  chat: '💬',
  close: '✕',
  x: '✕',
  refresh: '↻',
  filter: '⚲',

  // Actions & Directions
  arrowRight: '→',
  arrowLeft: '←',
  chevronRight: '›',
  chevronLeft: '‹',
  external: '↗',
  share: '⤤',
  copy: '⧉',

  // Status & Threats
  check: '✓',
  alert: '⚠',
  info: 'ℹ',

  // Scanners
  link: '↗',
  message: '💬',
  image: '▣',
  audio: '♪',
  key: '🔑'
};

export function Icon({ name, size = 20, color = '#FFFFFF', style }) {
  const glyph = ICON_MAP[name] || '•';

  return (
    <View style={[styles.container, { width: size, height: size }, style]}>
      <Text
        style={[
          styles.glyph,
          {
            fontSize: size * 0.82,
            color,
            lineHeight: size
          }
        ]}
      >
        {glyph}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    justifyContent: 'center',
    alignItems: 'center'
  },
  glyph: {
    textAlign: 'center',
    includeFontPadding: false
  }
});
