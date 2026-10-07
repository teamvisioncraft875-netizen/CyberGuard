import { COLORS } from '../constants/colors';

export function getRiskColor(level) {
  if (!level) return COLORS.textMuted;
  const normalized = String(level).toLowerCase().trim();
  switch (normalized) {
    case 'critical':
      return COLORS.critical;
    case 'high':
      return COLORS.high;
    case 'medium':
      return COLORS.medium;
    case 'low':
      return COLORS.low;
    case 'safe':
      return COLORS.safe;
    default:
      return COLORS.textMuted;
  }
}

export function getRiskMutedBg(level) {
  if (!level) return 'rgba(100, 116, 139, 0.12)';
  const normalized = String(level).toLowerCase().trim();
  switch (normalized) {
    case 'critical':
      return COLORS.criticalMuted;
    case 'high':
      return COLORS.highMuted;
    case 'medium':
      return COLORS.mediumMuted;
    case 'low':
      return COLORS.lowMuted;
    case 'safe':
      return COLORS.safeMuted;
    default:
      return 'rgba(100, 116, 139, 0.12)';
  }
}

export function formatThreatType(threatType) {
  if (!threatType) return 'Unclassified Threat';
  switch (threatType.toLowerCase()) {
    case 'phishing':
      return 'Phishing Message';
    case 'malicious_url':
      return 'Malicious URL';
    case 'deepfake':
      return 'Synthetic / Deepfake Media';
    case 'exposed_secret':
      return 'Exposed Credential / Secret';
    case 'account_takeover':
      return 'Suspicious Authentication';
    case 'technical_threat':
      return 'Host Telemetry Anomaly';
    case 'ddos_attack':
      return 'Volumetric Traffic Attack';
    default:
      return threatType
        .split('_')
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
  }
}

export function getThreatIcon(threatType) {
  if (!threatType) return 'shield-alert';
  switch (threatType.toLowerCase()) {
    case 'phishing':
      return 'email-alert';
    case 'malicious_url':
      return 'link-variant-off';
    case 'deepfake':
      return 'face-recognition';
    case 'exposed_secret':
      return 'key-alert';
    case 'account_takeover':
      return 'account-lock-alert';
    case 'technical_threat':
      return 'server-network-off';
    default:
      return 'shield-alert';
  }
}
