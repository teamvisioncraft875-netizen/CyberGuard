const net = require('net');

/**
 * CYBERGUARD IOC Extractor & Normalizer
 * Extracts and normalizes Indicators of Compromise (IPv4, IPv6, Domains, URLs, MD5, SHA1, SHA256)
 * with automatic defanging support and deduplication.
 */

// Regex definitions with strict boundaries to avoid false overlaps
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;

// URL Regex supporting http, https, and defanged hxxp, hxxps
const URL_REGEX = /(?:https?|hxxps?):\/\/[^\s"'<>)`]+(?:\.[^\s"'<>)`]+)*/gi;

// Domain Regex (FQDN with 2+ labels and valid TLD format)
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b/g;

// Hash Regexes with lookaround boundaries so 64-char SHA256 doesn't match SHA1 or MD5
const SHA256_REGEX = /(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])/g;
const SHA1_REGEX = /(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])/g;
const MD5_REGEX = /(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])/g;

// Non-domain common code file extensions to filter out false positives
const CODE_EXTENSIONS = new Set([
  'js', 'ts', 'jsx', 'tsx', 'json', 'css', 'scss', 'html', 'htm',
  'py', 'pyc', 'sh', 'bash', 'sql', 'md', 'txt', 'log', 'png',
  'jpg', 'jpeg', 'gif', 'svg', 'ico', 'pdf', 'zip', 'tar', 'gz'
]);

/**
 * Refangs common security-defanged strings:
 * - "hxxp://" -> "http://"
 * - "hxxps://" -> "https://"
 * - "example[.]com" -> "example.com"
 * - "1[.]1[.]1[.]1" -> "1.1.1.1"
 * - "example(.)com" -> "example.com"
 *
 * @param {string} str
 * @returns {string}
 */
function refang(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/\bhxxps:\/\//gi, 'https://')
    .replace(/\bhxxp:\/\//gi, 'http://')
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\[:\]/g, ':');
}

/**
 * Normalizes an IOC object or pair into canonical format.
 *
 * @param {Object|string} iocOrType - Either { type, value } or type string
 * @param {string} [rawValue] - Value if first argument is type string
 * @returns {{ type: string, value: string }|null}
 */
function normalizeIOC(iocOrType, rawValue) {
  let type;
  let value;

  if (typeof iocOrType === 'object' && iocOrType !== null) {
    type = iocOrType.type;
    value = iocOrType.value;
  } else {
    type = iocOrType;
    value = rawValue;
  }

  if (!type || typeof type !== 'string' || !value || typeof value !== 'string') {
    return null;
  }

  const cleanType = type.trim().toLowerCase();
  let cleanVal = refang(value.trim());

  // 1. IP (IPv4)
  if (cleanType === 'ip' || cleanType === 'ipv4') {
    if (net.isIPv4(cleanVal)) {
      return { type: 'ip', value: cleanVal };
    }
    return null;
  }

  // 2. IPv6
  if (cleanType === 'ipv6') {
    if (net.isIPv6(cleanVal)) {
      return { type: 'ipv6', value: cleanVal.toLowerCase() };
    }
    return null;
  }

  // 3. URL
  if (cleanType === 'url') {
    // Strip trailing punctuation often caught in prose: ., ), >, ], etc.
    cleanVal = cleanVal.replace(/[.,;!?>\])'"]+$/, '');
    try {
      const parsed = new URL(cleanVal);
      // Remove fragment (#frag) as it does not change the network indicator
      parsed.hash = '';
      return {
        type: 'url',
        value: parsed.toString()
      };
    } catch {
      // Fallback normalization
      return {
        type: 'url',
        value: cleanVal
      };
    }
  }

  // 4. Domain
  if (cleanType === 'domain') {
    let domain = cleanVal
      .toLowerCase()
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .split(':')[0]
      .replace(/^[.@]+/, '')
      .replace(/[.,;!?>\])'"]+$/, '');

    if (domain && !net.isIP(domain) && domain.includes('.')) {
      const parts = domain.split('.');
      const tld = parts[parts.length - 1];
      if (tld && !CODE_EXTENSIONS.has(tld)) {
        return { type: 'domain', value: domain };
      }
    }
    return null;
  }

  // 5. Hashes: md5, sha1, sha256
  if (cleanType === 'md5') {
    const hash = cleanVal.toLowerCase();
    if (/^[a-f0-9]{32}$/.test(hash)) {
      return { type: 'md5', value: hash };
    }
    return null;
  }

  if (cleanType === 'sha1') {
    const hash = cleanVal.toLowerCase();
    if (/^[a-f0-9]{40}$/.test(hash)) {
      return { type: 'sha1', value: hash };
    }
    return null;
  }

  if (cleanType === 'sha256') {
    const hash = cleanVal.toLowerCase();
    if (/^[a-f0-9]{64}$/.test(hash)) {
      return { type: 'sha256', value: hash };
    }
    return null;
  }

  return null;
}

/**
 * Extracts and deduplicates all valid IOCs from arbitrary text.
 * Supports IPv4, IPv6, Domains, URLs, MD5, SHA1, and SHA256.
 *
 * @param {string} text - Raw input text or payload
 * @returns {Array<{ type: string, value: string }>}
 */
function extractIOCs(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const refanged = refang(text);
  const resultsMap = new Map();

  const addIoc = (rawType, rawValue) => {
    const norm = normalizeIOC(rawType, rawValue);
    if (norm && norm.type && norm.value) {
      const dedupKey = `${norm.type}:${norm.value}`;
      if (!resultsMap.has(dedupKey)) {
        resultsMap.set(dedupKey, norm);
      }
    }
  };

  // 1. URLs
  const urlMatches = refanged.match(URL_REGEX) || [];
  for (const rawUrl of urlMatches) {
    addIoc('url', rawUrl);
    // Also extract the domain from the URL
    try {
      const cleanUrl = rawUrl.replace(/[.,;!?>\])'"]+$/, '');
      const parsed = new URL(cleanUrl);
      if (parsed.hostname && !net.isIP(parsed.hostname)) {
        addIoc('domain', parsed.hostname);
      } else if (parsed.hostname && net.isIPv4(parsed.hostname)) {
        addIoc('ip', parsed.hostname);
      } else if (parsed.hostname && net.isIPv6(parsed.hostname)) {
        addIoc('ipv6', parsed.hostname);
      }
    } catch {}
  }

  // 2. IPv4
  const ipv4Matches = refanged.match(IPV4_REGEX) || [];
  for (const rawIp of ipv4Matches) {
    addIoc('ip', rawIp);
  }

  // 3. IPv6 (tokens containing colons)
  const tokens = refanged.split(/[\s,;'"()<>\[\]{}]+/);
  for (const token of tokens) {
    if (token.includes(':') && net.isIPv6(token)) {
      addIoc('ipv6', token);
    }
  }

  // 4. Domains (standalone)
  const domainMatches = refanged.match(DOMAIN_REGEX) || [];
  for (const rawDomain of domainMatches) {
    if (!net.isIP(rawDomain)) {
      addIoc('domain', rawDomain);
    }
  }

  // 5. SHA256 (64 hex characters)
  const sha256Matches = refanged.match(SHA256_REGEX) || [];
  for (const rawSha256 of sha256Matches) {
    addIoc('sha256', rawSha256);
  }

  // 6. SHA1 (40 hex characters)
  const sha1Matches = refanged.match(SHA1_REGEX) || [];
  for (const rawSha1 of sha1Matches) {
    addIoc('sha1', rawSha1);
  }

  // 7. MD5 (32 hex characters)
  const md5Matches = refanged.match(MD5_REGEX) || [];
  for (const rawMd5 of md5Matches) {
    addIoc('md5', rawMd5);
  }

  return Array.from(resultsMap.values());
}

module.exports = {
  extractIOCs,
  normalizeIOC,
  refang
};
