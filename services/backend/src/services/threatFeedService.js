const fs = require('fs');
const path = require('path');
const db = require('../config/db');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');
const threatIntelService = require('./threatIntelService');
const { extractIOCs, normalizeIOC } = require('../utils/iocExtractor');

const CIRCUIT_BREAKER_THRESHOLD = 5;
const DEFAULT_RETRY_BACKOFF_MINUTES = 15;

/**
 * CYBERGUARD Threat Feed Service
 * Ingests, parses, normalizes, and schedules threat intelligence feeds
 * (JSON, CSV, Plain Text) with multi-tenant isolation, circuit-breaking,
 * and automated health metric tracking.
 */
class ThreatFeedService {
  /**
   * Fetches raw content from a URL or local file path.
   *
   * @param {string} urlOrPath
   * @param {Object} [authConfig={}]
   * @returns {Promise<string>}
   */
  async fetchFeedContent(urlOrPath, authConfig = {}) {
    if (!urlOrPath || typeof urlOrPath !== 'string') {
      throw new Error('Valid feed URL or file path is required');
    }

    const cleanPath = urlOrPath.trim();

    // 1. Support local file reading for offline/test/air-gapped feeds
    if (cleanPath.startsWith('file://')) {
      const filePath = cleanPath.replace(/^file:\/\//, '');
      return await fs.promises.readFile(filePath, 'utf8');
    }

    if (fs.existsSync(cleanPath) && (cleanPath.startsWith('/') || cleanPath.startsWith('./') || cleanPath.startsWith('../') || /^[a-zA-Z]:\\/.test(cleanPath))) {
      return await fs.promises.readFile(cleanPath, 'utf8');
    }

    // 2. Fetch over HTTP/HTTPS
    const headers = {
      'User-Agent': 'CYBERGUARD-ThreatIntel/1.0',
      'Accept': 'application/json, text/csv, text/plain, */*'
    };

    if (authConfig.api_key) {
      if (authConfig.header_name) {
        headers[authConfig.header_name] = authConfig.api_key;
      } else {
        headers['Authorization'] = `Bearer ${authConfig.api_key}`;
      }
    }

    const response = await fetch(cleanPath, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(30000)
    });

    if (!response.ok) {
      throw new Error(`Feed HTTP request failed with status ${response.status}: ${response.statusText}`);
    }

    return await response.text();
  }

  /**
   * Parses raw feed content into normalized IOC indicator objects based on feed type.
   *
   * @param {string} rawContent
   * @param {string} feedType - 'json_custom' | 'abuseipdb' | 'otx' | 'csv' | 'text' | string
   * @returns {Array<{ type: string, value: string, severity?: string, confidence?: number, threat_actor?: string, tags?: string[] }>}
   */
  parseFeed(rawContent, feedType = 'text') {
    if (!rawContent || typeof rawContent !== 'string') {
      return [];
    }

    const type = String(feedType || '').toLowerCase();

    if (type.includes('json') || type === 'abuseipdb' || type === 'virustotal' || type === 'otx' || type === 'misp') {
      try {
        return this.parseJsonFeed(rawContent);
      } catch (jsonErr) {
        // Fall back to line-by-line text parsing if JSON parsing fails
        return this.parseTextFeed(rawContent);
      }
    }

    if (type.includes('csv')) {
      return this.parseCsvFeed(rawContent);
    }

    return this.parseTextFeed(rawContent);
  }

  /**
   * Parses JSON formatted threat feeds (AbuseIPDB, OTX, or generic indicator lists).
   *
   * @param {string} content
   * @returns {Array<Object>}
   */
  parseJsonFeed(content) {
    const parsed = JSON.parse(content);
    const indicators = [];

    // Case 1: Root array of objects or strings
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (typeof item === 'string') {
          const extracted = extractIOCs(item);
          indicators.push(...extracted);
        } else if (item && typeof item === 'object') {
          const val = item.indicator || item.ioc || item.value || item.ip || item.ipAddress || item.domain || item.url || item.hash || item.sha256 || item.md5;
          const iocType = item.type || item.indicator_type;
          if (val) {
            const norm = normalizeIOC(iocType || 'ip', String(val)) || extractIOCs(String(val))[0];
            if (norm) {
              indicators.push({
                ...norm,
                severity: item.severity || 'medium',
                confidence: item.confidence ?? item.confidence_score ?? item.abuseConfidenceScore ?? 50,
                threat_actor: item.threat_actor || item.actor || null,
                tags: Array.isArray(item.tags) ? item.tags : []
              });
            }
          }
        }
      }
      return indicators;
    }

    // Case 2: AbuseIPDB response structure: { data: [ { ipAddress, abuseConfidenceScore, ... } ] }
    if (parsed.data && Array.isArray(parsed.data)) {
      for (const item of parsed.data) {
        const ip = item.ipAddress || item.ip;
        if (ip) {
          const norm = normalizeIOC('ip', ip);
          if (norm) {
            indicators.push({
              ...norm,
              severity: (item.abuseConfidenceScore || 0) >= 80 ? 'critical' : ((item.abuseConfidenceScore || 0) >= 50 ? 'high' : 'medium'),
              confidence: item.abuseConfidenceScore ?? 50,
              tags: ['abuseipdb']
            });
          }
        }
      }
      return indicators;
    }

    // Case 3: Object with indicators or results array
    const candidateList = parsed.indicators || parsed.results || parsed.iocs || parsed.records;
    if (Array.isArray(candidateList)) {
      for (const item of candidateList) {
        if (typeof item === 'string') {
          indicators.push(...extractIOCs(item));
        } else if (item && typeof item === 'object') {
          const val = item.indicator || item.ioc || item.value || item.ip || item.domain || item.url || item.hash;
          if (val) {
            const norm = normalizeIOC(item.type || 'ip', String(val)) || extractIOCs(String(val))[0];
            if (norm) {
              indicators.push({
                ...norm,
                severity: item.severity || 'medium',
                confidence: item.confidence ?? item.confidence_score ?? 50,
                tags: Array.isArray(item.tags) ? item.tags : []
              });
            }
          }
        }
      }
      return indicators;
    }

    // Fallback: extract any IOCs present in the serialized text
    return extractIOCs(content);
  }

  /**
   * Parses CSV formatted threat feeds.
   *
   * @param {string} content
   * @returns {Array<Object>}
   */
  parseCsvFeed(content) {
    const lines = content.split(/\r?\n/);
    const indicators = [];
    let headerMap = null;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('//')) {
        continue;
      }

      const cols = line.split(/[,;\t]/).map((c) => c.trim().replace(/^["']|["']$/g, ''));

      // Detect header row
      if (!headerMap && cols.some((c) => /^(indicator|ioc|ip|domain|url|hash|value)$/i.test(c))) {
        headerMap = {};
        cols.forEach((col, idx) => {
          const key = col.toLowerCase();
          if (key === 'indicator' || key === 'ioc' || key === 'ip' || key === 'value' || key === 'domain' || key === 'url' || key === 'hash') {
            headerMap.indicator = idx;
          }
          if (key === 'type' || key === 'indicator_type') headerMap.type = idx;
          if (key === 'severity') headerMap.severity = idx;
          if (key === 'confidence' || key === 'confidence_score') headerMap.confidence = idx;
          if (key === 'actor' || key === 'threat_actor') headerMap.actor = idx;
        });
        continue;
      }

      if (headerMap && headerMap.indicator !== undefined) {
        const val = cols[headerMap.indicator];
        const declaredType = headerMap.type !== undefined ? cols[headerMap.type] : null;
        if (val) {
          const norm = (declaredType ? normalizeIOC(declaredType, val) : null) || extractIOCs(val)[0];
          if (norm) {
            indicators.push({
              ...norm,
              severity: headerMap.severity !== undefined ? cols[headerMap.severity] : 'medium',
              confidence: headerMap.confidence !== undefined ? parseInt(cols[headerMap.confidence], 10) || 50 : 50,
              threat_actor: headerMap.actor !== undefined ? cols[headerMap.actor] : null
            });
          }
        }
      } else {
        // Fallback row-by-row extraction from col 0 or entire line
        const iocs = extractIOCs(line);
        indicators.push(...iocs);
      }
    }

    return indicators;
  }

  /**
   * Parses line-delimited plain text threat feeds.
   *
   * @param {string} content
   * @returns {Array<Object>}
   */
  parseTextFeed(content) {
    const lines = content.split(/\r?\n/);
    const indicators = [];

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('//')) {
        continue;
      }
      const extracted = extractIOCs(line);
      indicators.push(...extracted);
    }

    return indicators;
  }

  /**
   * Synchronizes a single threat feed by ID.
   *
   * @param {string} feedId
   * @returns {Promise<{ success: boolean, feed_id: string, feed_name: string, indicator_count: number, duration_ms: number, error?: string }>}
   */
  async syncFeed(feedId) {
    const startTime = Date.now();

    // 1. Fetch feed metadata
    const feedRes = await db.query(
      `SELECT id, organization_id, feed_name, feed_slug, feed_type, feed_url,
              auth_config, polling_frequency_minutes, confidence_weight,
              is_enabled, last_sync_at, next_sync_due_at, sync_status,
              consecutive_failures, last_error
       FROM public.threat_feeds
       WHERE id = $1;`,
      [feedId]
    );

    if (!feedRes.rows || feedRes.rows.length === 0) {
      throw new Error(`Threat feed with ID ${feedId} not found`);
    }

    const feed = feedRes.rows[0];

    if (!feed.is_enabled) {
      return {
        success: false,
        feed_id: feed.id,
        feed_name: feed.feed_name,
        indicator_count: 0,
        duration_ms: 0,
        error: 'Feed is disabled'
      };
    }

    if (feed.sync_status === 'circuit_broken') {
      return {
        success: false,
        feed_id: feed.id,
        feed_name: feed.feed_name,
        indicator_count: 0,
        duration_ms: 0,
        error: 'Feed is circuit-broken due to excessive consecutive failures'
      };
    }

    // 2. Log sync started and mark in_progress
    auditLog({
      organization_id: feed.organization_id || null,
      actor_type: 'system',
      action: AUDIT_ACTIONS.FEED_SYNC_STARTED,
      resource_type: 'threat_feed',
      resource_id: String(feed.id),
      details: {
        feed_id: feed.id,
        feed_name: feed.feed_name,
        feed_type: feed.feed_type
      }
    });

    await db.query(
      `UPDATE public.threat_feeds
       SET sync_status = 'in_progress', updated_at = NOW()
       WHERE id = $1;`,
      [feed.id]
    );

    try {
      // 3. Fetch feed content
      const rawContent = await this.fetchFeedContent(feed.feed_url, feed.auth_config);

      // 4. Parse content
      const parsedIndicators = this.parseFeed(rawContent, feed.feed_type);

      // 5. In-memory deduplication across this batch
      const deduplicatedMap = new Map();
      const weight = parseFloat(feed.confidence_weight) || 1.0;

      for (const item of parsedIndicators) {
        const norm = normalizeIOC(item.type, item.value);
        if (!norm) continue;

        const key = `${norm.type}:${norm.value}`;
        const rawConf = typeof item.confidence === 'number' ? item.confidence : 50;
        const adjustedConfidence = Math.min(100, Math.max(0, Math.round(rawConf * weight)));

        if (!deduplicatedMap.has(key)) {
          deduplicatedMap.set(key, {
            type: norm.type,
            value: norm.value,
            severity: item.severity || 'medium',
            confidence_score: adjustedConfidence,
            threat_actor: item.threat_actor || null,
            malware_family: item.malware_family || null,
            tags: Array.isArray(item.tags) ? item.tags : [feed.feed_slug]
          });
        } else {
          // If duplicate in feed, keep highest confidence
          const existing = deduplicatedMap.get(key);
          existing.confidence_score = Math.max(existing.confidence_score, adjustedConfidence);
        }
      }

      const uniqueList = Array.from(deduplicatedMap.values());

      // 6. Ingest indicators into threat_indicators
      for (const item of uniqueList) {
        await threatIntelService.recordIndicator({
          type: item.type,
          value: item.value,
          organization_id: feed.organization_id || null,
          feed_id: feed.id,
          severity: item.severity,
          confidence_score: item.confidence_score,
          threat_actor: item.threat_actor,
          malware_family: item.malware_family,
          tags: item.tags,
          ttl_days: 30
        });
      }

      const durationMs = Date.now() - startTime;
      const pollingInterval = feed.polling_frequency_minutes || 60;

      // 7. Update feed health on success
      await db.query(
        `UPDATE public.threat_feeds
         SET sync_status = 'success',
             last_sync_at = NOW(),
             next_sync_due_at = NOW() + ($1 || ' minutes')::interval,
             consecutive_failures = 0,
             last_error = NULL,
             updated_at = NOW()
         WHERE id = $2;`,
        [pollingInterval, feed.id]
      );

      // 8. Log sync completed
      auditLog({
        organization_id: feed.organization_id || null,
        actor_type: 'system',
        action: AUDIT_ACTIONS.FEED_SYNC_COMPLETED,
        resource_type: 'threat_feed',
        resource_id: String(feed.id),
        details: {
          feed_id: feed.id,
          feed_name: feed.feed_name,
          indicator_count: uniqueList.length,
          duration_ms: durationMs,
          error_message: null
        }
      });

      return {
        success: true,
        feed_id: feed.id,
        feed_name: feed.feed_name,
        indicator_count: uniqueList.length,
        duration_ms: durationMs
      };
    } catch (err) {
      const durationMs = Date.now() - startTime;
      const newFailures = (feed.consecutive_failures || 0) + 1;
      const newStatus = newFailures >= CIRCUIT_BREAKER_THRESHOLD ? 'circuit_broken' : 'failed';

      await db.query(
        `UPDATE public.threat_feeds
         SET sync_status = $1,
             consecutive_failures = $2,
             last_error = $3,
             next_sync_due_at = NOW() + ($4 || ' minutes')::interval,
             updated_at = NOW()
         WHERE id = $5;`,
        [newStatus, newFailures, err.message, DEFAULT_RETRY_BACKOFF_MINUTES, feed.id]
      );

      auditLog({
        organization_id: feed.organization_id || null,
        actor_type: 'system',
        action: AUDIT_ACTIONS.FEED_SYNC_FAILED,
        resource_type: 'threat_feed',
        resource_id: String(feed.id),
        details: {
          feed_id: feed.id,
          feed_name: feed.feed_name,
          indicator_count: 0,
          duration_ms: durationMs,
          error_message: err.message
        }
      });

      return {
        success: false,
        feed_id: feed.id,
        feed_name: feed.feed_name,
        indicator_count: 0,
        duration_ms: durationMs,
        error: err.message
      };
    }
  }

  /**
   * Finds all active feeds whose next_sync_due_at <= NOW() and synchronizes them.
   *
   * @returns {Promise<Array<Object>>}
   */
  async syncDueFeeds() {
    const dueQuery = `
      SELECT id, feed_name, next_sync_due_at
      FROM public.threat_feeds
      WHERE is_enabled = true
        AND sync_status != 'circuit_broken'
        AND next_sync_due_at <= NOW()
      ORDER BY next_sync_due_at ASC;
    `;
    const { rows: dueFeeds } = await db.query(dueQuery);

    if (!dueFeeds || dueFeeds.length === 0) {
      return [];
    }

    const results = [];
    for (const feed of dueFeeds) {
      try {
        const result = await this.syncFeed(feed.id);
        results.push(result);
      } catch (feedErr) {
        results.push({
          success: false,
          feed_id: feed.id,
          feed_name: feed.feed_name,
          error: feedErr.message
        });
      }
    }

    return results;
  }

  /**
   * Retrieves overall feed health breakdown.
   *
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object>}
   */
  async getFeedHealth(organizationId = null) {
    let whereClause = '';
    const params = [];

    if (organizationId) {
      whereClause = 'WHERE organization_id IS NULL OR organization_id = $1';
      params.push(organizationId);
    }

    const queryText = `
      SELECT id, organization_id, feed_name, feed_slug, feed_type,
             is_enabled, sync_status, consecutive_failures,
             last_sync_at, next_sync_due_at, last_error
      FROM public.threat_feeds
      ${whereClause}
      ORDER BY feed_name ASC;
    `;
    const res = await db.query(queryText, params);
    const feeds = res.rows || [];

    const activeFeeds = feeds.filter((f) => f.is_enabled);
    const failedFeeds = feeds.filter((f) => f.sync_status === 'failed');
    const circuitBrokenFeeds = feeds.filter((f) => f.sync_status === 'circuit_broken');

    return {
      total_feeds: feeds.length,
      active_feeds: activeFeeds.length,
      failed_feeds: failedFeeds.length,
      circuit_broken_feeds: circuitBrokenFeeds.length,
      feeds
    };
  }

  /**
   * Retrieves statistical summary metrics for threat intelligence feeds.
   *
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object>}
   */
  async getFeedStatistics(organizationId = null) {
    const health = await this.getFeedHealth(organizationId);

    // Latest sync timestamp across feeds
    let lastSync = null;
    for (const f of health.feeds) {
      if (f.last_sync_at) {
        if (!lastSync || new Date(f.last_sync_at) > new Date(lastSync)) {
          lastSync = f.last_sync_at;
        }
      }
    }

    // Ingested indicators count
    let indicatorCount = 0;
    try {
      let countQuery;
      let countParams;
      if (organizationId) {
        countQuery = `SELECT COUNT(*)::int AS total FROM public.threat_indicators WHERE organization_id IS NULL OR organization_id = $1;`;
        countParams = [organizationId];
      } else {
        countQuery = `SELECT COUNT(*)::int AS total FROM public.threat_indicators;`;
        countParams = [];
      }
      const countRes = await db.query(countQuery, countParams);
      indicatorCount = countRes.rows[0]?.total || 0;
    } catch {}

    const totalFeeds = health.total_feeds;
    const failedCount = health.failed_feeds + health.circuit_broken_feeds;
    const successfulCount = Math.max(0, totalFeeds - failedCount);
    const successRate = totalFeeds > 0 ? Math.round((successfulCount / totalFeeds) * 100) : 100;

    return {
      active_feeds: health.active_feeds,
      failed_feeds: health.failed_feeds,
      circuit_broken_feeds: health.circuit_broken_feeds,
      last_sync: lastSync,
      indicators_ingested: indicatorCount,
      sync_success_rate: successRate
    };
  }
}

const threatFeedService = new ThreatFeedService();

module.exports = threatFeedService;
