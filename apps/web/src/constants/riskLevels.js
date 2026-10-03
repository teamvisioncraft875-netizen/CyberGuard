/**
 * CYBERGUARD — Risk Level Constants & Dual-Theme Visual Encodings
 *
 * Authoritative 5-tier calibrated risk tiers used across threat scanners,
 * incident feeds, triage drawers, and analytics KPI cards.
 * Calibrated for optimal contrast and legibility in both Light and Dark themes.
 */

export const RISK_LEVELS = Object.freeze({
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

/**
 * Visual styling and metadata for each risk tier in both Light and Dark themes.
 */
export const RISK_CONFIG = Object.freeze({
  safe: {
    key: 'safe',
    label: 'Safe',
    scoreRange: [0, 19],
    badgeClass: 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800/40',
    dotClass: 'bg-emerald-600 dark:bg-emerald-400',
    glowClass: '',
    textClass: 'text-emerald-700 dark:text-emerald-400',
    borderClass: 'border-emerald-300 dark:border-emerald-800/40',
    bgClass: 'bg-emerald-50 dark:bg-emerald-950/40',
    description: 'Verified benign origin. No threat cues detected.',
  },
  low: {
    key: 'low',
    label: 'Low',
    scoreRange: [20, 39],
    badgeClass: 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 border-sky-300 dark:border-sky-800/40',
    dotClass: 'bg-sky-600 dark:bg-sky-400',
    glowClass: '',
    textClass: 'text-sky-700 dark:text-sky-400',
    borderClass: 'border-sky-300 dark:border-sky-800/40',
    bgClass: 'bg-sky-50 dark:bg-sky-950/40',
    description: 'Minor anomaly or unfamiliar sender without malicious intent.',
  },
  medium: {
    key: 'medium',
    label: 'Medium',
    scoreRange: [40, 69],
    badgeClass: 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-800/40',
    dotClass: 'bg-amber-600 dark:bg-amber-400',
    glowClass: '',
    textClass: 'text-amber-700 dark:text-amber-400',
    borderClass: 'border-amber-300 dark:border-amber-800/40',
    bgClass: 'bg-amber-50 dark:bg-amber-950/40',
    description: 'Suspicious behavioral or lexical cues observed. Review recommended.',
  },
  high: {
    key: 'high',
    label: 'High',
    scoreRange: [70, 89],
    badgeClass: 'bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 border-orange-300 dark:border-orange-800/40',
    dotClass: 'bg-orange-600 dark:bg-orange-400',
    glowClass: '',
    textClass: 'text-orange-700 dark:text-orange-400',
    borderClass: 'border-orange-300 dark:border-orange-800/40',
    bgClass: 'bg-orange-50 dark:bg-orange-950/40',
    description: 'Strong threat indicators. Proactive containment alert issued.',
  },
  critical: {
    key: 'critical',
    label: 'Critical',
    scoreRange: [90, 100],
    badgeClass: 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-800/50',
    dotClass: 'bg-rose-600 dark:bg-rose-500',
    glowClass: '',
    textClass: 'text-rose-700 dark:text-rose-400',
    borderClass: 'border-rose-300 dark:border-rose-800/50',
    bgClass: 'bg-rose-50 dark:bg-rose-950/50',
    description: 'Active confirmed attack or credential harvesting. Immediate intervention required.',
  },
});

/**
 * Normalizes any risk string (e.g. "Critical", "CRITICAL", "critical") to standard config
 * @param {string} rawLevel
 * @returns {typeof RISK_CONFIG['safe']}
 */
export function getRiskConfig(rawLevel) {
  if (!rawLevel) return RISK_CONFIG.low;
  const key = String(rawLevel).toLowerCase().trim();
  return RISK_CONFIG[key] || RISK_CONFIG.low;
}
