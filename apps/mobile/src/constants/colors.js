/**
 * Backwards-compatible export mapping to THEME_DARK by default.
 * Pure black and grey palette with zero blue/cyan colors.
 */
import { THEME_DARK } from './theme';

export const COLORS = {
  background: THEME_DARK.background,
  card: THEME_DARK.card,
  cardSecondary: THEME_DARK.surface,
  surface: THEME_DARK.surface,
  border: THEME_DARK.border,
  borderHighlight: THEME_DARK.borderActive,

  primary: THEME_DARK.accent,
  primaryMuted: THEME_DARK.accentMuted,
  primaryHover: '#E5E5E5',

  safe: THEME_DARK.success,
  safeMuted: THEME_DARK.successBg,
  low: '#A3A3A3',
  lowMuted: 'rgba(163, 163, 163, 0.12)',
  medium: THEME_DARK.warning,
  mediumMuted: THEME_DARK.warningBg,
  high: THEME_DARK.danger,
  highMuted: THEME_DARK.dangerBg,
  critical: THEME_DARK.critical,
  criticalMuted: THEME_DARK.criticalBg,

  textPrimary: THEME_DARK.textPrimary,
  textSecondary: THEME_DARK.textSecondary,
  textMuted: THEME_DARK.textMuted,
  textInverse: THEME_DARK.textInverse,

  success: THEME_DARK.success,
  warning: THEME_DARK.warning,
  danger: THEME_DARK.danger,
  info: '#A3A3A3'
};

export default COLORS;
