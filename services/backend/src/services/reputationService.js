const redis = require('../config/redis');
const { normalizeIOC } = require('../utils/iocExtractor');

const CACHE_TTL_SECONDS = 86400; // 24 hours
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 2;
const CIRCUIT_BREAKER_THRESHOLD = 5;
const CIRCUIT_BREAKER_COOLDOWN_MS = 60000; // 60s cooldown

/**
 * CYBERGUARD External Threat Intelligence & Reputation Service
 * Orchestrates multi-provider reputation lookups (AbuseIPDB, VirusTotal, Google Safe Browsing),
 * enforces strict 24-hour Redis caching (rep:<type>:<value>), canonical response normalization,
 * request timeouts, exponential backoff retries, and per-provider circuit breakers.
 */
class ReputationService {
  constructor(options = {}) {
    this.fetchFn = options.fetchFn || globalThis.fetch;
    this.fallbackCache = new Map();

    // Circuit breaker state per provider
    this.circuitBreakers = {
      abuseipdb: { failures: 0, state: 'CLOSED', nextAttemptAt: 0 },
      virustotal: { failures: 0, state: 'CLOSED', nextAttemptAt: 0 },
      safebrowsing: { failures: 0, state: 'CLOSED', nextAttemptAt: 0 }
    };

    // Reputation provider analytics metrics
    this.metrics = {
      virustotal_queries: 0,
      abuseipdb_queries: 0,
      safebrowsing_queries: 0,
      cache_hits: 0,
      cache_misses: 0,
      total_query_time_ms: 0,
      total_queries: 0
    };
  }

  // ==========================================
  // CONFIGURATION & PROVIDER KEYS
  // ==========================================

  getAbuseIpDbKey() {
    return process.env.ABUSEIPDB_API_KEY || null;
  }

  getVirusTotalKey() {
    return process.env.VIRUSTOTAL_API_KEY || null;
  }

  getSafeBrowsingKey() {
    return process.env.SAFE_BROWSING_API_KEY || null;
  }

  // ==========================================
  // CIRCUIT BREAKER LOGIC
  // ==========================================

  isCircuitOpen(provider) {
    const cb = this.circuitBreakers[provider];
    if (!cb) return false;

    if (cb.state === 'OPEN') {
      if (Date.now() >= cb.nextAttemptAt) {
        cb.state = 'HALF_OPEN';
        return false;
      }
      return true;
    }
    return false;
  }

  recordSuccess(provider) {
    const cb = this.circuitBreakers[provider];
    if (!cb) return;
    cb.failures = 0;
    cb.state = 'CLOSED';
  }

  recordFailure(provider) {
    const cb = this.circuitBreakers[provider];
    if (!cb) return;
    cb.failures++;
    if (cb.failures >= CIRCUIT_BREAKER_THRESHOLD || cb.state === 'HALF_OPEN') {
      cb.state = 'OPEN';
      cb.nextAttemptAt = Date.now() + CIRCUIT_BREAKER_COOLDOWN_MS;
      console.warn(`[reputationService] Circuit breaker OPEN for ${provider}. Cooling down for ${CIRCUIT_BREAKER_COOLDOWN_MS / 1000}s`);
    }
  }

  resetCircuitBreaker(provider) {
    if (provider && this.circuitBreakers[provider]) {
      this.circuitBreakers[provider] = { failures: 0, state: 'CLOSED', nextAttemptAt: 0 };
    } else {
      for (const p of Object.keys(this.circuitBreakers)) {
        this.circuitBreakers[p] = { failures: 0, state: 'CLOSED', nextAttemptAt: 0 };
      }
    }
  }

  // ==========================================
  // CACHE LAYER (rep:<type>:<value>)
  // ==========================================

  getCacheKey(type, value) {
    const norm = normalizeIOC(type, value);
    const resolvedType = norm ? norm.type : type;
    const resolvedVal = norm ? norm.value : value;
    const prefix = resolvedType === 'ipv4' || resolvedType === 'ipv6' ? 'ip' : resolvedType;
    return `rep:${prefix}:${resolvedVal}`;
  }

  async getCachedReputation(type, value) {
    const cacheKey = this.getCacheKey(type, value);
    try {
      if (redis.isConnected()) {
        const cached = await redis.get(cacheKey);
        if (cached) {
          this.metrics.cache_hits++;
          const parsed = JSON.parse(cached);
          parsed._cached = true;
          return parsed;
        }
      } else {
        const entry = this.fallbackCache.get(cacheKey);
        if (entry) {
          if (entry.expiresAt && Date.now() > entry.expiresAt) {
            this.fallbackCache.delete(cacheKey);
            this.metrics.cache_misses++;
            return null;
          }
          this.metrics.cache_hits++;
          const parsed = JSON.parse(entry.payload);
          parsed._cached = true;
          return parsed;
        }
      }
      this.metrics.cache_misses++;
      return null;
    } catch (err) {
      console.warn(`[reputationService.getCachedReputation] Cache read error for ${cacheKey}:`, err.message);
      this.metrics.cache_misses++;
      return null;
    }
  }

  async setCachedReputation(type, value, data, ttlSeconds = CACHE_TTL_SECONDS) {
    if (!data) return;
    const cacheKey = this.getCacheKey(type, value);
    const payload = JSON.stringify(data);

    try {
      if (redis.isConnected()) {
        await redis.set(cacheKey, payload, { EX: ttlSeconds });
      } else {
        this.fallbackCache.set(cacheKey, {
          payload,
          expiresAt: Date.now() + ttlSeconds * 1000
        });
      }
    } catch (err) {
      console.warn(`[reputationService.setCachedReputation] Cache write error for ${cacheKey}:`, err.message);
      this.fallbackCache.set(cacheKey, {
        payload,
        expiresAt: Date.now() + ttlSeconds * 1000
      });
    }
  }

  // ==========================================
  // RETRY & TIMEOUT HTTP DISPATCHER
  // ==========================================

  async dispatchWithRetry(provider, url, options = {}, retries = MAX_RETRIES) {
    if (this.isCircuitOpen(provider)) {
      return null;
    }

    const providerKey = `${provider}_queries`;
    if (this.metrics[providerKey] !== undefined) {
      this.metrics[providerKey]++;
    }

    const startTime = Date.now();
    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    let attempt = 0;
    let lastError = null;

    while (attempt <= retries) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(new Error(`Request timeout of ${timeoutMs}ms exceeded`)), timeoutMs);

        const response = await this.fetchFn(url, {
          ...options,
          signal: controller.signal
        });
        clearTimeout(timer);

        const elapsed = Date.now() - startTime;
        this.metrics.total_query_time_ms += elapsed;
        this.metrics.total_queries++;

        if (response.ok) {
          this.recordSuccess(provider);
          return await response.json();
        }

        // If rate-limited or server error (5xx), retry
        if (response.status === 429 || response.status >= 500) {
          throw new Error(`Provider ${provider} responded with HTTP ${response.status}`);
        }

        // Client errors (400, 401, 404): non-retryable
        this.recordSuccess(provider);
        return null;
      } catch (err) {
        lastError = err;
        attempt++;
        if (attempt <= retries) {
          // Exponential backoff: 50ms, 100ms
          await new Promise((res) => setTimeout(res, 50 * Math.pow(2, attempt - 1)));
        }
      }
    }

    const elapsed = Date.now() - startTime;
    this.metrics.total_query_time_ms += elapsed;
    this.metrics.total_queries++;

    this.recordFailure(provider);
    console.warn(`[reputationService] ${provider} lookup failed after ${retries + 1} attempts:`, lastError?.message);
    return null;
  }

  /**
   * Returns reputation provider metrics and cache performance.
   *
   * @returns {{
   *   virustotal_queries: number,
   *   abuseipdb_queries: number,
   *   safebrowsing_queries: number,
   *   cache_hits: number,
   *   cache_misses: number,
   *   avg_provider_response_time: number
   * }}
   */
  getMetrics() {
    return {
      virustotal_queries: this.metrics.virustotal_queries,
      abuseipdb_queries: this.metrics.abuseipdb_queries,
      safebrowsing_queries: this.metrics.safebrowsing_queries,
      cache_hits: this.metrics.cache_hits,
      cache_misses: this.metrics.cache_misses,
      avg_provider_response_time: this.metrics.total_queries > 0
        ? Math.round(this.metrics.total_query_time_ms / this.metrics.total_queries)
        : 0
    };
  }

  // ==========================================
  // PROVIDER ADAPTERS
  // ==========================================

  /**
   * AbuseIPDB Adapter
   * Checks IP address reputation.
   */
  async checkAbuseIpDb(ip) {
    const apiKey = this.getAbuseIpDbKey();
    if (!apiKey) return null;

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const data = await this.dispatchWithRetry('abuseipdb', url, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    if (!data || !data.data) return null;
    const d = data.data;

    const abuseScore = d.abuseConfidenceScore || 0;
    const isMalicious = abuseScore >= 20;

    return {
      source: 'abuseipdb',
      reputation_score: abuseScore,
      malicious: isMalicious,
      confidence: abuseScore,
      categories: d.usageType ? [d.usageType] : (isMalicious ? ['abuse_reported'] : []),
      last_seen: d.lastReportedAt || null,
      raw: d
    };
  }

  /**
   * VirusTotal Adapter
   * Checks IP, Domain, URL, or File Hash reputation.
   */
  async checkVirusTotal(type, value) {
    const apiKey = this.getVirusTotalKey();
    if (!apiKey) return null;

    let endpoint = '';
    const norm = normalizeIOC(type, value);
    const targetType = norm ? norm.type : type;
    const targetVal = norm ? norm.value : value;

    if (targetType === 'ip' || targetType === 'ipv4' || targetType === 'ipv6') {
      endpoint = `ip_addresses/${encodeURIComponent(targetVal)}`;
    } else if (targetType === 'domain') {
      endpoint = `domains/${encodeURIComponent(targetVal)}`;
    } else if (targetType === 'url') {
      const base64Url = Buffer.from(targetVal).toString('base64').replace(/=/g, '');
      endpoint = `urls/${base64Url}`;
    } else if (['md5', 'sha1', 'sha256'].includes(targetType)) {
      endpoint = `files/${encodeURIComponent(targetVal)}`;
    } else {
      return null;
    }

    const url = `https://www.virustotal.com/api/v3/${endpoint}`;
    const data = await this.dispatchWithRetry('virustotal', url, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      }
    });

    if (!data || !data.data || !data.data.attributes) return null;
    const attrs = data.data.attributes;
    const stats = attrs.last_analysis_stats || {};

    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const harmlessCount = stats.harmless || 0;
    const undetectedCount = stats.undetected || 0;
    const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

    const isMalicious = maliciousCount >= 1;
    // Calculate normalized reputation score (0-100)
    let score = 0;
    if (totalEngines > 0) {
      score = Math.min(100, Math.round(((maliciousCount * 1.0 + suspiciousCount * 0.5) / Math.max(totalEngines, 10)) * 100));
      if (maliciousCount >= 3) score = Math.max(score, 85);
      else if (maliciousCount >= 1) score = Math.max(score, 60);
    }

    const categories = [];
    if (attrs.categories && typeof attrs.categories === 'object') {
      categories.push(...Object.values(attrs.categories));
    }
    if (isMalicious && categories.length === 0) {
      categories.push('malware');
    }

    return {
      source: 'virustotal',
      reputation_score: score,
      malicious: isMalicious,
      confidence: totalEngines >= 30 ? 95 : totalEngines >= 10 ? 80 : 50,
      categories: [...new Set(categories)],
      last_seen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      raw: data
    };
  }

  /**
   * Google Safe Browsing Adapter
   * Checks URL or Domain for threats.
   */
  async checkSafeBrowsing(urlOrDomain) {
    const apiKey = this.getSafeBrowsingKey();
    if (!apiKey) return null;

    const targetUrl = urlOrDomain.startsWith('http') ? urlOrDomain : `http://${urlOrDomain}/`;
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;

    const body = {
      client: {
        clientId: 'cyberguard-backend',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: targetUrl }]
      }
    };

    const data = await this.dispatchWithRetry('safebrowsing', endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!data) return null;

    const matches = Array.isArray(data.matches) ? data.matches : [];
    const isMalicious = matches.length > 0;
    const categories = matches.map((m) => m.threatType);

    return {
      source: 'safebrowsing',
      reputation_score: isMalicious ? 95 : 0,
      malicious: isMalicious,
      confidence: 90,
      categories: [...new Set(categories)],
      last_seen: isMalicious ? new Date().toISOString() : null,
      raw: data
    };
  }

  // ==========================================
  // PUBLIC LOOKUP METHODS (CACHE-FIRST)
  // ==========================================

  /**
   * Looks up IP reputation (AbuseIPDB + VirusTotal fallback).
   *
   * @param {string} ip
   * @param {Object} [options={}]
   * @returns {Promise<Object|null>} Normalized reputation result
   */
  async lookupIP(ip, options = {}) {
    const norm = normalizeIOC('ip', ip);
    if (!norm) return null;

    // 1. Check Redis Cache
    if (!options.bypassCache) {
      const cached = await this.getCachedReputation('ip', norm.value);
      if (cached) return cached;
    }

    // 2. Query AbuseIPDB
    let result = await this.checkAbuseIpDb(norm.value);

    // 3. Fallback / supplementary query to VirusTotal if AbuseIPDB was not configured or clean
    if (!result || (!result.malicious && this.getVirusTotalKey())) {
      const vtResult = await this.checkVirusTotal('ip', norm.value);
      if (vtResult && (vtResult.malicious || !result)) {
        result = vtResult;
      }
    }

    // 4. Cache and return
    if (result) {
      await this.setCachedReputation('ip', norm.value, result);
    }
    return result;
  }

  /**
   * Looks up Domain reputation (VirusTotal + Google Safe Browsing).
   *
   * @param {string} domain
   * @param {Object} [options={}]
   * @returns {Promise<Object|null>} Normalized reputation result
   */
  async lookupDomain(domain, options = {}) {
    const norm = normalizeIOC('domain', domain);
    if (!norm) return null;

    // 1. Check Redis Cache
    if (!options.bypassCache) {
      const cached = await this.getCachedReputation('domain', norm.value);
      if (cached) return cached;
    }

    // 2. Query Google Safe Browsing
    let result = await this.checkSafeBrowsing(norm.value);

    // 3. Fallback / supplement with VirusTotal
    if (!result || (!result.malicious && this.getVirusTotalKey())) {
      const vtResult = await this.checkVirusTotal('domain', norm.value);
      if (vtResult && (vtResult.malicious || !result)) {
        result = vtResult;
      }
    }

    // 4. Cache and return
    if (result) {
      await this.setCachedReputation('domain', norm.value, result);
    }
    return result;
  }

  /**
   * Looks up URL reputation (Google Safe Browsing + VirusTotal).
   *
   * @param {string} url
   * @param {Object} [options={}]
   * @returns {Promise<Object|null>} Normalized reputation result
   */
  async lookupURL(url, options = {}) {
    const norm = normalizeIOC('url', url);
    if (!norm) return null;

    // 1. Check Redis Cache
    if (!options.bypassCache) {
      const cached = await this.getCachedReputation('url', norm.value);
      if (cached) return cached;
    }

    // 2. Query Google Safe Browsing
    let result = await this.checkSafeBrowsing(norm.value);

    // 3. Query VirusTotal if Safe Browsing did not detect or is unconfigured
    if (!result || (!result.malicious && this.getVirusTotalKey())) {
      const vtResult = await this.checkVirusTotal('url', norm.value);
      if (vtResult && (vtResult.malicious || !result)) {
        result = vtResult;
      }
    }

    // 4. Cache and return
    if (result) {
      await this.setCachedReputation('url', norm.value, result);
    }
    return result;
  }

  /**
   * Looks up File Hash reputation (VirusTotal).
   *
   * @param {string} hash
   * @param {Object} [options={}]
   * @returns {Promise<Object|null>} Normalized reputation result
   */
  async lookupHash(hash, options = {}) {
    const norm = normalizeIOC(hash.length === 32 ? 'md5' : hash.length === 40 ? 'sha1' : 'sha256', hash);
    if (!norm) return null;

    // 1. Check Redis Cache
    if (!options.bypassCache) {
      const cached = await this.getCachedReputation('hash', norm.value);
      if (cached) return cached;
    }

    // 2. Query VirusTotal
    const result = await this.checkVirusTotal(norm.type, norm.value);

    // 3. Cache and return
    if (result) {
      await this.setCachedReputation('hash', norm.value, result);
    }
    return result;
  }

  /**
   * Generic dispatcher by IOC type.
   *
   * @param {string} type
   * @param {string} value
   * @param {Object} [options={}]
   * @returns {Promise<Object|null>}
   */
  async lookupIOC(type, value, options = {}) {
    const norm = normalizeIOC(type, value);
    if (!norm) return null;

    if (norm.type === 'ip' || norm.type === 'ipv4' || norm.type === 'ipv6') {
      return await this.lookupIP(norm.value, options);
    }
    if (norm.type === 'domain') {
      return await this.lookupDomain(norm.value, options);
    }
    if (norm.type === 'url') {
      return await this.lookupURL(norm.value, options);
    }
    if (['md5', 'sha1', 'sha256'].includes(norm.type)) {
      return await this.lookupHash(norm.value, options);
    }
    return null;
  }

  /**
   * Universal lookup convenience helper.
   */
  async lookup(value, type = 'ip', options = {}) {
    return this.lookupIOC(type, value, options);
  }
}

const reputationService = new ReputationService();

module.exports = reputationService;
