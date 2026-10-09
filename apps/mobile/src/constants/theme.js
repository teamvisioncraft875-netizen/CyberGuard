/**
 * CYBERGUARD Enterprise Design System - Theme Tokens
 * Pure Black & Grey Monochrome Palette.
 * Strict enterprise directive: NO blue/cyan colors allowed.
 */

export const THEME_DARK = {
  mode: 'dark',
  // Deep Pure Matte Black & Charcoal Surfaces
  background: '#080808',     // Purest deep black canvas
  card: '#121212',           // Rich matte charcoal card surface
  cardElevated: '#181818',   // Slightly elevated interactive card
  surface: '#1A1A1A',        // Secondary surface / input field
  border: '#262626',         // Minimal neutral dark grey border
  borderActive: '#444444',   // Active border highlight
  hover: '#1F1F1F',          // Touch active state

  // Typography Tokens
  textPrimary: '#FFFFFF',    // High-emphasis white headlines
  textBody: '#E5E5E5',       // High-contrast readable body text
  textSecondary: '#A3A3A3',  // Refined medium grey labels
  textMuted: '#666666',      // Low-emphasis timestamps and captions
  textInverse: '#080808',    // Inverted text on solid white buttons

  // Monochromatic White & Silver Accents (NO BLUE / NO CYAN)
  accent: '#FFFFFF',         // Crisp pure white action accent
  accentMuted: 'rgba(255, 255, 255, 0.08)',
  accentGlow: 'rgba(255, 255, 255, 0.15)',

  // Functional Severity Indicators (Functional alerts only)
  success: '#22C55E',        // Confirmed safe / Active shield green
  successBg: 'rgba(34, 197, 94, 0.12)',
  
  warning: '#F59E0B',        // Medium severity / Warning amber
  warningBg: 'rgba(245, 158, 11, 0.12)',
  
  danger: '#EF4444',         // High / Critical threat red
  dangerBg: 'rgba(239, 68, 68, 0.14)',

  critical: '#DC2626',       // Critical severity red
  criticalBg: 'rgba(220, 38, 38, 0.18)',

  neutral: '#525252',        // Inactive / unclassified grey
  neutralBg: 'rgba(82, 82, 82, 0.12)',

  // Shadows
  shadow: {
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.6,
    shadowRadius: 8,
    elevation: 3
  }
};

export const THEME_LIGHT = {
  mode: 'light',
  background: '#F5F5F5',     // Executive grey canvas
  card: '#FFFFFF',           // Crisp white card surface
  cardElevated: '#FFFFFF',
  surface: '#EEEEEE',        // Muted secondary surface
  border: '#E0E0E0',         // Clean grey border
  borderActive: '#222222',   // Sharp active border
  hover: '#EAEAEA',

  textPrimary: '#111111',    // Near black
  textBody: '#222222',       // Dark grey body
  textSecondary: '#555555',  // Medium grey
  textMuted: '#888888',      // Light muted grey
  textInverse: '#FFFFFF',

  accent: '#111111',         // High-contrast black accent
  accentMuted: 'rgba(0, 0, 0, 0.06)',
  accentGlow: 'rgba(0, 0, 0, 0.12)',

  success: '#16A34A',
  successBg: 'rgba(22, 163, 74, 0.10)',

  warning: '#D97706',
  warningBg: 'rgba(217, 119, 6, 0.10)',

  danger: '#DC2626',
  dangerBg: 'rgba(220, 38, 38, 0.10)',

  critical: '#B91C1C',
  criticalBg: 'rgba(185, 28, 28, 0.12)',

  neutral: '#737373',
  neutralBg: 'rgba(115, 115, 115, 0.10)',

  shadow: {
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 6,
    elevation: 2
  }
};

export const TYPOGRAPHY = {
  h1: { fontSize: 24, fontWeight: '800', lineHeight: 30 },
  h2: { fontSize: 18, fontWeight: '700', lineHeight: 24 },
  h3: { fontSize: 15, fontWeight: '700', lineHeight: 20 },
  body: { fontSize: 13, lineHeight: 18 },
  caption: { fontSize: 11, lineHeight: 15 },
  mono: { fontFamily: 'monospace', fontSize: 11 }
};

export const SPACING = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24
};

export const RADIUS = {
  sm: 6,
  md: 10,
  lg: 14,
  full: 9999
};
