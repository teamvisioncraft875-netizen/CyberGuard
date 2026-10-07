const crypto = require('crypto');
const db = require('../config/db');

/**
 * Deduplication Windows (in minutes) per threat type
 */
const DEDUP_WINDOWS = Object.freeze({
  phishing: 30,
  malicious_url: 60,
  url: 60,
  login_anomaly: 15,
  credential_abuse: 15,
  system_threat: 30,
  technical_threat: 30,
  malware: 30,
  threat_intel: 60,
  default: 30
});

/**
 * Returns the configured deduplication window in minutes for a threat type.
 *
 * @param {string} threatType
 * @returns {number}
 */
function getDedupWindow(threatType) {
  if (!threatType) return DEDUP_WINDOWS.default;
  const key = String(threatType).toLowerCase().trim();
  return DEDUP_WINDOWS[key] || DEDUP_WINDOWS.default;
}

/**
 * Normalizes a URL: trim, lowercase, remove protocol, and strip trailing slashes.
 *
 * @param {string} rawUrl
 * @returns {string}
 */
function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  let cleaned = rawUrl.trim().toLowerCase();
  // Strip protocol (http://, https://, hxxp://, etc.)
  cleaned = cleaned.replace(/^[a-z0-9_-]+:\/\//i, '');
  // Strip defanged brackets e.g. [.]
  cleaned = cleaned.replace(/\[\.\]/g, '.');
  // Strip trailing slashes
  cleaned = cleaned.replace(/\/+$/, '');
  return cleaned;
}

/**
 * Splits a normalized URL or domain/path string into { fqdn, path }.
 *
 * @param {string} rawUrl
 * @returns {{ fqdn: string, path: string }}
 */
function extractFqdnAndPath(rawUrl) {
  const norm = normalizeUrl(rawUrl);
  if (!norm) return { fqdn: '', path: '' };
  const slashIdx = norm.indexOf('/');
  if (slashIdx === -1) {
    return { fqdn: norm, path: '' };
  }
  return {
    fqdn: norm.slice(0, slashIdx),
    path: norm.slice(slashIdx).replace(/\/+$/, '')
  };
}

/**
 * Normalizes a string: trim and lowercase.
 *
 * @param {*} val
 * @returns {string}
 */
function normalizeString(val) {
  if (val === null || val === undefined) return '';
  return String(val).trim().toLowerCase();
}

/**
 * Deterministically stringifies signals or arbitrary objects with sorted keys.
 *
 * @param {*} obj
 * @returns {string}
 */
function deterministicStringify(obj) {
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return String(obj);

  if (Array.isArray(obj)) {
    return '[' + obj.map(deterministicStringify).sort().join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map((k) => `"${k}":${deterministicStringify(obj[k])}`);
  return '{' + entries.join(',') + '}';
}

/**
 * Incident Deduplication Service
 * Computes deterministic SHA-256 fingerprints, searches sliding-window duplicates,
 * and consolidates recurring incidents.
 */
class IncidentDeduplicationService {
  /**
   * Generates a 64-character SHA256 hex digest fingerprint for an incident.
   *
   * @param {Object} incident
   * @returns {string} 64-character SHA-256 hex digest
   */
  generateFingerprint(incident = {}) {
    const orgId = normalizeString(incident.organization_id || incident.organizationId || 'global');
    const threatType = normalizeString(incident.threat_type || incident.threatType || 'unknown');
    const signals = incident.signals || {};
    const details = incident.details || {};

    let canonicalString = '';

    switch (threatType) {
      case 'phishing': {
        const senderDomain = normalizeString(
          incident.sender_domain || signals.sender_domain || details.sender_domain ||
          (incident.sender_email ? incident.sender_email.split('@')[1] : '') ||
          (signals.sender_email ? String(signals.sender_email).split('@')[1] : '')
        );

        const targetUrl = normalizeUrl(
          incident.target_url || incident.url || signals.target_url || signals.url || details.target_url || details.url
        );

        const emailSubject = normalizeString(
          incident.email_subject || incident.subject || signals.email_subject || signals.subject || details.email_subject || details.subject
        );

        canonicalString = [orgId, 'phishing', senderDomain, targetUrl, emailSubject].join('|');
        break;
      }

      case 'malicious_url':
      case 'url': {
        const rawUrl = incident.url || incident.target_url || signals.url || signals.target_url || details.url || '';
        const parsed = extractFqdnAndPath(rawUrl);
        const fqdn = normalizeString(incident.fqdn || signals.fqdn || details.fqdn || parsed.fqdn);
        const path = normalizeString(incident.path || signals.path || details.path || parsed.path);

        canonicalString = [orgId, 'malicious_url', fqdn, path].join('|');
        break;
      }

      case 'login_anomaly':
      case 'credential_abuse': {
        const userId = normalizeString(incident.user_id || incident.userId || signals.user_id || details.user_id);
        const sourceIp = normalizeString(
          incident.source_ip || incident.ip_address || signals.source_ip || signals.ip_address || details.source_ip || details.ip_address
        );

        canonicalString = [orgId, 'login_anomaly', userId, sourceIp].join('|');
        break;
      }

      case 'system_threat':
      case 'technical_threat':
      case 'malware': {
        const deviceId = normalizeString(incident.device_id || incident.deviceId || signals.device_id || details.device_id);
        const processName = normalizeString(
          incident.process_name || signals.process_name || details.process_name || details.rule_id || signals.rule_name || signals.rule_id
        );
        const binarySha = normalizeString(
          incident.binary_sha256 || incident.sha256 || signals.binary_sha256 || signals.sha256 || details.binary_sha256 || details.sha256
        );

        canonicalString = [orgId, 'system_threat', deviceId, processName, binarySha].join('|');
        break;
      }

      case 'threat_intel': {
        const indicatorType = normalizeString(incident.indicator_type || signals.indicator_type || details.indicator_type);
        const indicatorValue = normalizeString(incident.indicator_value || signals.indicator_value || details.indicator_value);

        canonicalString = [orgId, 'threat_intel', indicatorType, indicatorValue].join('|');
        break;
      }

      default: {
        const signalsRepresentation = deterministicStringify(signals);
        canonicalString = [orgId, threatType, signalsRepresentation].join('|');
        break;
      }
    }

    return crypto.createHash('sha256').update(canonicalString).digest('hex');
  }

  /**
   * Checks if an active duplicate incident exists within the configured time window.
   *
   * @param {Object} params
   * @param {string|null} params.organizationId
   * @param {string} params.fingerprint
   * @param {number} [params.windowMinutes]
   * @param {import('pg').PoolClient} [params.client=null]
   * @returns {Promise<{ isDuplicate: boolean, incident: Object|null }>}
   */
  async checkDuplicate({ organizationId = null, fingerprint, windowMinutes = 30, client = null }) {
    if (!fingerprint) {
      return { isDuplicate: false, incident: null };
    }

    const dbClient = client || db;
    const window = Math.max(1, parseInt(windowMinutes, 10) || 30);
    const orgParam = organizationId || null;

    const sql = `
      SELECT *
      FROM public.incidents
      WHERE (
        ($1::uuid IS NULL AND organization_id IS NULL)
        OR ($1::uuid IS NOT NULL AND organization_id = $1::uuid)
      )
      AND fingerprint = $2
      AND status = 'open'
      AND last_seen_at >= NOW() - ($3 || ' minutes')::interval
      ORDER BY last_seen_at DESC
      LIMIT 1;
    `;

    const res = await dbClient.query(sql, [orgParam, fingerprint, window]);
    const existing = res.rows[0] || null;

    return {
      isDuplicate: Boolean(existing),
      incident: existing
    };
  }

  /**
   * Consolidates an existing incident: increments occurrence_count and refreshes last_seen_at.
   *
   * @param {Object} params
   * @param {string} params.incidentId
   * @param {import('pg').PoolClient} [params.client=null]
   * @returns {Promise<Object>} Updated incident record
   */
  async consolidateIncident({ incidentId, client = null }) {
    if (!incidentId) {
      throw new Error('incidentId is required to consolidate incident');
    }

    const dbClient = client || db;
    const sql = `
      UPDATE public.incidents
      SET occurrence_count = occurrence_count + 1,
          last_seen_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const res = await dbClient.query(sql, [incidentId]);
    return res.rows[0] || null;
  }

  getDedupWindow(threatType) {
    return getDedupWindow(threatType);
  }
}

const incidentDeduplicationService = new IncidentDeduplicationService();

module.exports = incidentDeduplicationService;
module.exports.getDedupWindow = getDedupWindow;
module.exports.normalizeUrl = normalizeUrl;
