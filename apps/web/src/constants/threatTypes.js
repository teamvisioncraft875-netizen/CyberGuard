/**
 * CYBERGUARD — Threat Type Constants & MITRE ATT&CK Mappings
 */

export const THREAT_TYPES = Object.freeze({
  PHISHING: 'phishing',
  MALICIOUS_URL: 'malicious_url',
  DEEPFAKE: 'deepfake',
  IMPERSONATION: 'impersonation',
  ACCOUNT_TAKEOVER: 'account_takeover',
  TECHNICAL_THREAT: 'technical_threat',
  SYSTEM_ANOMALY: 'system_anomaly',
});

export const THREAT_METADATA = Object.freeze({
  phishing: {
    label: 'Phishing Message',
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    sourceType: 'email/sms/social',
    iconName: 'MailWarning',
  },
  malicious_url: {
    label: 'Malicious URL / Domain',
    techniqueId: 'T1204',
    techniqueName: 'User Execution - Malicious URL',
    sourceType: 'url',
    iconName: 'Globe',
  },
  deepfake: {
    label: 'Synthetic Media / Deepfake',
    techniqueId: 'T1586.002',
    techniqueName: 'Compromise Accounts: Synthetic Persona',
    sourceType: 'image/audio',
    iconName: 'Camera',
  },
  impersonation: {
    label: 'Brand / Persona Impersonation',
    techniqueId: 'T1585',
    techniqueName: 'Establish Accounts / Impersonation',
    sourceType: 'social',
    iconName: 'UserX',
  },
  account_takeover: {
    label: 'Account Takeover / Credential Stuffing',
    techniqueId: 'T1110',
    techniqueName: 'Brute Force / Credential Stuffing',
    sourceType: 'login',
    iconName: 'KeyRound',
  },
  technical_threat: {
    label: 'Protocol / Process Anomaly',
    techniqueId: 'T1071',
    techniqueName: 'Application Layer Protocol Anomaly',
    sourceType: 'system',
    iconName: 'Cpu',
  },
  system_anomaly: {
    label: 'Host System Deviation',
    techniqueId: 'T1071',
    techniqueName: 'Host Telemetry Surge',
    sourceType: 'system',
    iconName: 'Activity',
  },
});

export function getThreatMetadata(type) {
  if (!type) return THREAT_METADATA.phishing;
  const key = String(type).toLowerCase().trim();
  return THREAT_METADATA[key] || {
    label: key.replace(/_/g, ' ').toUpperCase(),
    techniqueId: 'T1071',
    techniqueName: 'Cyber Threat',
    sourceType: 'unknown',
    iconName: 'AlertTriangle',
  };
}
