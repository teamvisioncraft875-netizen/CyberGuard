/**
 * CYBERGUARD — Calibrated 5-Tier Risk Normalization & Calculation Utilities
 */

import { RISK_LEVELS, RISK_CONFIG } from '../constants/riskLevels';

export const RISK_PRIORITY = Object.freeze({
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  safe: 1,
});

/**
 * Normalizes ANY raw string/input to one of the 5 canonical risk levels:
 * 'safe' | 'low' | 'medium' | 'high' | 'critical'
 *
 * Handles casing, aliases, and P-codes:
 * - 'p0', 'p0 critical', 'crit' -> 'critical'
 * - 'p1', 'p1 high' -> 'high'
 * - 'warn', 'warning' -> 'medium'
 * - 'info', 'informational' -> 'low'
 * - 'clean', 'benign', 'verified' -> 'safe'
 *
 * @param {string | any} input
 * @returns {'safe' | 'low' | 'medium' | 'high' | 'critical'}
 */
export function normalizeRisk(input) {
  if (!input) return RISK_LEVELS.LOW;

  const str = String(input).trim().toLowerCase();

  // Exact matches
  if (str === 'critical' || str === 'crit' || str === 'p0' || str.includes('p0')) {
    return RISK_LEVELS.CRITICAL;
  }
  if (str === 'high' || str === 'p1' || str.includes('p1')) {
    return RISK_LEVELS.HIGH;
  }
  if (str === 'medium' || str === 'med' || str === 'warn' || str === 'warning' || str === 'p2' || str.includes('p2')) {
    return RISK_LEVELS.MEDIUM;
  }
  if (str === 'low' || str === 'info' || str === 'informational' || str === 'p3' || str.includes('p3')) {
    return RISK_LEVELS.LOW;
  }
  if (str === 'safe' || str === 'clean' || str === 'benign' || str === 'verified' || str === 'p4' || str.includes('p4')) {
    return RISK_LEVELS.SAFE;
  }

  // Fallback
  return RISK_CONFIG[str] ? str : RISK_LEVELS.LOW;
}

/**
 * Determines 5-tier risk category from a numeric score [0..100]
 * @param {number | string} score
 * @returns {'safe' | 'low' | 'medium' | 'high' | 'critical'}
 */
export function riskFromScore(score) {
  const num = typeof score === 'number' ? score : Number(score);
  if (isNaN(num)) return RISK_LEVELS.LOW;

  const clamped = Math.max(0, Math.min(100, Math.round(num)));

  if (clamped >= 90) return RISK_LEVELS.CRITICAL;
  if (clamped >= 70) return RISK_LEVELS.HIGH;
  if (clamped >= 40) return RISK_LEVELS.MEDIUM;
  if (clamped >= 20) return RISK_LEVELS.LOW;
  return RISK_LEVELS.SAFE;
}

/**
 * Compares two risk levels by severity.
 * Returns positive if a > b (a is more severe), negative if a < b, 0 if equal.
 * Useful for Array.prototype.sort().
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareRisk(a, b) {
  const priorityA = RISK_PRIORITY[normalizeRisk(a)] || 0;
  const priorityB = RISK_PRIORITY[normalizeRisk(b)] || 0;
  return priorityB - priorityA; // descending by severity
}

/**
 * Returns full visual and descriptive configuration for a risk level
 * @param {string} rawLevel
 * @returns {object}
 */
export function getRiskConfig(rawLevel) {
  const normalized = normalizeRisk(rawLevel);
  return RISK_CONFIG[normalized] || RISK_CONFIG.low;
}
