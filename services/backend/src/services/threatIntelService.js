const db = require('../config/db');
const redis = require('../config/redis');
const { extractIOCs, normalizeIOC } = require('../utils/iocExtractor');

const DEFAULT_CACHE_TTL_SECONDS = 86400; // 24 hours

/**
 * CYBERGUARD Threat Intelligence Service (Foundation Phase)
 * Manages IOC extraction, canonical normalization, high-performance Redis caching,
 * and database lookups across global and tenant-isolated indicator catalogs.
 */
class ThreatIntelService {
  constructor() {
    // In-memory fallback cache when Redis is disconnected or in lightweight environments
    this.fallbackCache = new Map();
  }

  /**
   * Extracts and deduplicates all supported IOCs from arbitrary text.
   *
   * @param {string} text
   * @returns {Array<{ type: string, value: string }>}
   */
  extractIOCs(text) {
    return extractIOCs(text);
  }

  /**
   * Normalizes an IOC object or pair into canonical format.
   *
   * @param {Object|string} iocOrType - Either { type, value } or type string
   * @param {string} [rawValue]
   * @returns {{ type: string, value: string }|null}
   */
  normalizeIOC(iocOrType, rawValue) {
    return normalizeIOC(iocOrType, rawValue);
  }

  /**
   * Generates a deterministic Redis cache key for an IOC.
   *
   * @param {string} type
   * @param {string} value
   * @param {string|null} [organizationId=null]
   * @returns {string}
   */
  getCacheKey(type, value, organizationId = null) {
    const norm = normalizeIOC(type, value);
    if (!norm) return `ti:invalid:${type}:${value}`;
    const orgSuffix = organizationId ? `:${organizationId}` : ':global';
    return `ti:${norm.type}:${norm.value}${orgSuffix}`;
  }

  /**
   * Caches an IOC lookup result in Redis with a configurable TTL.
   * Seamlessly falls back to memory cache if Redis is unavailable.
   *
   * @param {string} type
   * @param {string} value
   * @param {Object|null} result
   * @param {number} [ttlSeconds=86400]
   * @param {string|null} [organizationId=null]
   * @returns {Promise<boolean>}
   */
  async cacheIOC(type, value, result, ttlSeconds = DEFAULT_CACHE_TTL_SECONDS, organizationId = null) {
    const cacheKey = this.getCacheKey(type, value, organizationId);
    const payload = JSON.stringify(result);

    try {
      if (redis.isConnected()) {
        await redis.set(cacheKey, payload, { EX: ttlSeconds });
      } else {
        this.fallbackCache.set(cacheKey, {
          payload,
          expiresAt: Date.now() + ttlSeconds * 1000
        });
      }
      return true;
    } catch (err) {
      // Fall back to in-memory cache
      this.fallbackCache.set(cacheKey, {
        payload,
        expiresAt: Date.now() + ttlSeconds * 1000
      });
      return true;
    }
  }

  /**
   * Retrieves a cached IOC from Redis (or fallback in-memory cache).
   *
   * @param {string} type
   * @param {string} value
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object|null>}
   */
  async getCachedIOC(type, value, organizationId = null) {
    const cacheKey = this.getCacheKey(type, value, organizationId);

    try {
      if (redis.isConnected()) {
        const cached = await redis.get(cacheKey);
        if (cached) {
          return JSON.parse(cached);
        }
      }

      // Check fallback in-memory cache
      const item = this.fallbackCache.get(cacheKey);
      if (!item) return null;
      if (item.expiresAt && Date.now() > item.expiresAt) {
        this.fallbackCache.delete(cacheKey);
        return null;
      }
      return JSON.parse(item.payload);
    } catch (err) {
      console.warn(`[threatIntelService.getCachedIOC] Warning reading cache (${cacheKey}):`, err.message);
      return null;
    }
  }

  /**
   * Looks up an IOC against the Redis cache and PostgreSQL threat_indicators table.
   * Enforces multi-tenant scoping: matches indicators where organization_id matches
   * or global indicators where organization_id IS NULL.
   *
   * @param {string} type
   * @param {string} value
   * @param {Object} [options={}]
   * @param {string|null} [options.organizationId=null]
   * @param {boolean} [options.bypassCache=false]
   * @returns {Promise<Object|null>}
   */
  async lookupIOC(type, value, options = {}) {
    const { organizationId = null, bypassCache = false } = options;
    const norm = normalizeIOC(type, value);
    if (!norm) return null;

    // 1. Check Cache
    if (!bypassCache) {
      // Check tenant-scoped cache first if organizationId provided
      if (organizationId) {
        const tenantCached = await this.getCachedIOC(norm.type, norm.value, organizationId);
        if (tenantCached) {
          return { ...tenantCached, _cached: true };
        }
      }

      // Check global cache
      const globalCached = await this.getCachedIOC(norm.type, norm.value, null);
      if (globalCached) {
        return { ...globalCached, _cached: true };
      }
    }

    // 2. Query Database
    try {
      const queryText = `
        SELECT id, organization_id, feed_id, indicator_type, indicator_value,
               threat_actor, malware_family, severity, confidence_score, tags,
               observation_count, first_seen_at, last_seen_at, expires_at, is_active, metadata
        FROM public.threat_indicators
        WHERE (indicator_type = $1 OR ($1 = 'ip' AND indicator_type IN ('ip', 'ipv4')))
          AND indicator_value = $2
          AND is_active = true
          AND (organization_id IS NULL OR organization_id = $3)
        ORDER BY (organization_id IS NOT NULL) DESC, confidence_score DESC
        LIMIT 1;
      `;
      const res = await db.query(queryText, [norm.type, norm.value, organizationId]);

      if (res.rows && res.rows.length > 0) {
        const indicator = res.rows[0];
        // Cache result for future requests
        await this.cacheIOC(norm.type, norm.value, indicator, DEFAULT_CACHE_TTL_SECONDS, indicator.organization_id);
        return indicator;
      }

      return null;
    } catch (err) {
      console.error('[threatIntelService.lookupIOC] Database lookup error:', err.message);
      return null;
    }
  }

  /**
   * Looks up a batch of IOCs using a Redis-first strategy and a single SQL query for cache misses.
   *
   * @param {Array<{ type: string, value: string }>} iocs
   * @param {Object} [options={}]
   * @param {string|null} [options.organizationId=null]
   * @param {boolean} [options.bypassCache=false]
   * @param {Object|null} [options.client=null]
   * @returns {Promise<Map<string, Object>>} Map keyed by `${norm.type}:${norm.value}` -> indicator
   */
  async lookupBatchIOCs(iocs, options = {}) {
    const { organizationId = null, bypassCache = false, client = null } = options;
    const dbClient = client || db;
    const results = new Map();

    if (!Array.isArray(iocs) || iocs.length === 0) {
      return results;
    }

    // 1. Normalize and deduplicate input items
    const normalizedMap = new Map();
    for (const item of iocs) {
      if (!item) continue;
      const type = item.type || item.indicator_type;
      const val = item.value || item.indicator_value;
      const norm = normalizeIOC(type, val);
      if (norm) {
        const key = `${norm.type}:${norm.value}`;
        if (!normalizedMap.has(key)) {
          normalizedMap.set(key, norm);
        }
      }
    }

    if (normalizedMap.size === 0) {
      return results;
    }

    const missingIOCs = [];

    // 2. Check Cache first
    if (!bypassCache) {
      for (const [key, norm] of normalizedMap.entries()) {
        let cached = null;
        if (organizationId) {
          cached = await this.getCachedIOC(norm.type, norm.value, organizationId);
        }
        if (!cached) {
          cached = await this.getCachedIOC(norm.type, norm.value, null);
        }

        if (cached) {
          results.set(key, { ...cached, _cached: true });
        } else {
          missingIOCs.push(norm);
        }
      }
    } else {
      missingIOCs.push(...normalizedMap.values());
    }

    if (missingIOCs.length === 0) {
      return results;
    }

    // 3. Batch DB Lookup for cache misses
    try {
      const distinctValues = Array.from(new Set(missingIOCs.map((i) => i.value)));
      const queryText = `
        SELECT ti.id, ti.organization_id, ti.feed_id, ti.indicator_type, ti.indicator_value,
               ti.threat_actor, ti.malware_family, ti.severity, ti.confidence_score, ti.tags,
               ti.observation_count, ti.first_seen_at, ti.last_seen_at, ti.expires_at, ti.is_active, ti.metadata,
               tf.feed_name, tf.feed_slug
        FROM public.threat_indicators ti
        LEFT JOIN public.threat_feeds tf ON tf.id = ti.feed_id
        WHERE ti.is_active = true
          AND (ti.organization_id IS NULL OR ti.organization_id = $1)
          AND ti.indicator_value = ANY($2::text[])
        ORDER BY (ti.organization_id IS NOT NULL) DESC, ti.confidence_score DESC;
      `;

      const res = await dbClient.query(queryText, [organizationId, distinctValues]);
      if (res.rows && res.rows.length > 0) {
        for (const row of res.rows) {
          const normType = (row.indicator_type === 'ipv4' || row.indicator_type === 'ipv6') ? 'ip' : row.indicator_type;
          const key = `${normType}:${row.indicator_value}`;

          if (!results.has(key)) {
            results.set(key, row);
            await this.cacheIOC(normType, row.indicator_value, row, DEFAULT_CACHE_TTL_SECONDS, row.organization_id);
          }
        }
      }
    } catch (err) {
      console.error('[threatIntelService.lookupBatchIOCs] Batch lookup error:', err.message);
    }

    return results;
  }

  /**
   * Ingests or updates an indicator in the threat_indicators table.
   *
   * @param {Object} data
   * @param {string} data.type
   * @param {string} data.value
   * @param {string|null} [data.organization_id=null]
   * @param {string|null} [data.feed_id=null]
   * @param {string} [data.severity='medium']
   * @param {number} [data.confidence_score=50]
   * @param {string|null} [data.threat_actor=null]
   * @param {string|null} [data.malware_family=null]
   * @param {Array<string>} [data.tags=[]]
   * @param {Object} [data.metadata={}]
   * @param {number} [data.ttl_days=30]
   * @param {Object|null} [client=null] - Optional PG client for transactions
   * @returns {Promise<Object>}
   */
  async recordIndicator(data, client = null) {
    const dbClient = client || db;
    const norm = normalizeIOC(data.type, data.value);
    if (!norm) {
      throw new Error(`Invalid IOC: type=${data.type}, value=${data.value}`);
    }

    const orgId = data.organization_id || null;
    const feedId = data.feed_id || null;
    const severity = data.severity || 'medium';
    const confidenceScore = Number.isInteger(data.confidence_score) ? data.confidence_score : 50;
    const threatActor = data.threat_actor || null;
    const malwareFamily = data.malware_family || null;
    const tags = Array.isArray(data.tags) ? data.tags : [];
    const metadata = data.metadata || {};
    const ttlDays = data.ttl_days || 30;

    let queryText;
    let params;

    if (orgId) {
      queryText = `
        INSERT INTO public.threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value,
          severity, confidence_score, threat_actor, malware_family,
          tags, metadata, expires_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW() + ($11 || ' days')::interval, NOW())
        ON CONFLICT (organization_id, indicator_type, indicator_value) WHERE organization_id IS NOT NULL
        DO UPDATE SET
          confidence_score = GREATEST(threat_indicators.confidence_score, EXCLUDED.confidence_score),
          severity = EXCLUDED.severity,
          last_seen_at = NOW(),
          observation_count = threat_indicators.observation_count + 1,
          expires_at = NOW() + ($11 || ' days')::interval,
          is_active = true,
          updated_at = NOW()
        RETURNING *;
      `;
      params = [orgId, feedId, norm.type, norm.value, severity, confidenceScore, threatActor, malwareFamily, tags, metadata, ttlDays];
    } else {
      queryText = `
        INSERT INTO public.threat_indicators (
          organization_id, feed_id, indicator_type, indicator_value,
          severity, confidence_score, threat_actor, malware_family,
          tags, metadata, expires_at, updated_at
        ) VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + ($10 || ' days')::interval, NOW())
        ON CONFLICT (indicator_type, indicator_value) WHERE organization_id IS NULL
        DO UPDATE SET
          confidence_score = GREATEST(threat_indicators.confidence_score, EXCLUDED.confidence_score),
          severity = EXCLUDED.severity,
          last_seen_at = NOW(),
          observation_count = threat_indicators.observation_count + 1,
          expires_at = NOW() + ($10 || ' days')::interval,
          is_active = true,
          updated_at = NOW()
        RETURNING *;
      `;
      params = [feedId, norm.type, norm.value, severity, confidenceScore, threatActor, malwareFamily, tags, metadata, ttlDays];
    }

    const res = await dbClient.query(queryText, params);
    const indicator = res.rows[0];

    // Invalidate / update cache
    await this.cacheIOC(norm.type, norm.value, indicator, DEFAULT_CACHE_TTL_SECONDS, orgId);

    return indicator;
  }

  /**
   * Retrieves high-level threat intelligence dashboard metrics for the SOC dashboard.
   *
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object>} Dashboard overview object
   */
  async getThreatDashboard(organizationId = null) {
    const orgId = organizationId || null;

    // 1. Indicators metrics
    const indMetricsQuery = `
      SELECT
        COUNT(*)::int AS total_indicators,
        COUNT(*) FILTER (WHERE is_active = true AND (expires_at IS NULL OR expires_at > NOW()))::int AS active_indicators,
        COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at <= NOW())::int AS expired_indicators,
        COUNT(*) FILTER (WHERE severity IN ('high', 'critical') AND is_active = true)::int AS malicious_indicators,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int AS indicators_last_24h
      FROM public.threat_indicators
      WHERE ($1::uuid IS NULL AND organization_id IS NULL)
         OR ($1::uuid IS NOT NULL AND (organization_id IS NULL OR organization_id = $1));
    `;
    const indRes = await db.query(indMetricsQuery, [orgId]);
    const indMetrics = indRes.rows[0] || {
      total_indicators: 0,
      active_indicators: 0,
      expired_indicators: 0,
      malicious_indicators: 0,
      indicators_last_24h: 0
    };

    // 2. Matches last 24h
    const matchMetricsQuery = `
      SELECT COUNT(*)::int AS matches_last_24h
      FROM public.incident_ioc_matches
      WHERE matched_at >= NOW() - INTERVAL '24 hours'
        AND ($1::uuid IS NULL OR organization_id = $1);
    `;
    const matchRes = await db.query(matchMetricsQuery, [orgId]);
    const matchesLast24h = matchRes.rows[0]?.matches_last_24h || 0;

    // 3. Top indicator types
    const typesQuery = `
      SELECT indicator_type, COUNT(*)::int AS count
      FROM public.threat_indicators
      WHERE ($1::uuid IS NULL AND organization_id IS NULL)
         OR ($1::uuid IS NOT NULL AND (organization_id IS NULL OR organization_id = $1))
      GROUP BY indicator_type
      ORDER BY count DESC
      LIMIT 5;
    `;
    const typesRes = await db.query(typesQuery, [orgId]);
    const topIndicatorTypes = typesRes.rows || [];

    // 4. Feed metrics (from threatFeedService)
    const feedHealth = await this.getFeedHealth(orgId);
    const totalFeeds = feedHealth.total_feeds || 0;
    const failedFeeds = (feedHealth.failed_feeds || 0) + (feedHealth.circuit_broken_feeds || 0);
    const healthyFeeds = Math.max(0, (feedHealth.active_feeds || 0) - failedFeeds);

    return {
      total_indicators: indMetrics.total_indicators,
      active_indicators: indMetrics.active_indicators,
      expired_indicators: indMetrics.expired_indicators,
      malicious_indicators: indMetrics.malicious_indicators,
      total_feeds: totalFeeds,
      healthy_feeds: healthyFeeds,
      failed_feeds: failedFeeds,
      indicators_last_24h: indMetrics.indicators_last_24h,
      matches_last_24h: matchesLast24h,
      top_indicator_types: topIndicatorTypes
    };
  }

  /**
   * Retrieves paginated indicators with multi-field filtering and tenant scoping.
   *
   * @param {Object} [filters={}]
   * @returns {Promise<Object>} { total, limit, offset, indicators }
   */
  async getIndicators(filters = {}) {
    const {
      organization_id = null,
      organizationId = null,
      type = null,
      indicator_type = null,
      severity = null,
      is_active = null,
      search = null,
      q = null,
      sort_by = 'created_at',
      sort_order = 'DESC',
      limit = 50,
      offset = 0
    } = filters;

    const orgId = organization_id || organizationId || null;
    const resolvedType = type || indicator_type || null;
    const resolvedSearch = search || q || null;

    const conditions = [];
    const params = [];

    // Tenant scoping: global indicators + tenant-specific indicators
    params.push(orgId);
    conditions.push(`($${params.length}::uuid IS NULL AND ti.organization_id IS NULL OR $${params.length}::uuid IS NOT NULL AND (ti.organization_id IS NULL OR ti.organization_id = $${params.length}))`);

    // Type filter
    if (resolvedType) {
      params.push(resolvedType.toLowerCase());
      conditions.push(`ti.indicator_type = $${params.length}`);
    }

    // Severity filter
    if (severity) {
      params.push(severity.toLowerCase());
      conditions.push(`ti.severity = $${params.length}`);
    }

    // is_active filter
    if (is_active !== null && is_active !== undefined) {
      const activeBool = is_active === true || is_active === 'true';
      params.push(activeBool);
      conditions.push(`ti.is_active = $${params.length}`);
    }

    // Search filter
    if (resolvedSearch && typeof resolvedSearch === 'string' && resolvedSearch.trim()) {
      params.push(`%${resolvedSearch.trim()}%`);
      conditions.push(`(
        ti.indicator_value ILIKE $${params.length}
        OR ti.threat_actor ILIKE $${params.length}
        OR ti.malware_family ILIKE $${params.length}
      )`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Count query
    const countRes = await db.query(
      `SELECT COUNT(*)::int AS total FROM public.threat_indicators ti ${whereClause};`,
      params
    );
    const total = countRes.rows[0]?.total || 0;

    // Sorting whitelist
    const ALLOWED_SORT_COLS = {
      created_at: 'ti.created_at',
      updated_at: 'ti.updated_at',
      confidence_score: 'ti.confidence_score',
      severity: 'ti.severity',
      indicator_value: 'ti.indicator_value'
    };
    const sortCol = ALLOWED_SORT_COLS[sort_by] || 'ti.created_at';
    const sortDirection = String(sort_order).toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // Pagination clamp
    const safeLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 50));
    const safeOffset = Math.max(0, parseInt(offset, 10) || 0);

    params.push(safeLimit);
    const limitPlaceholder = `$${params.length}`;
    params.push(safeOffset);
    const offsetPlaceholder = `$${params.length}`;

    const queryText = `
      SELECT ti.id, ti.organization_id, ti.feed_id, ti.indicator_type, ti.indicator_value,
             ti.severity, ti.confidence_score, ti.threat_actor, ti.malware_family,
             ti.tags, ti.observation_count, ti.first_seen_at, ti.last_seen_at,
             ti.expires_at, ti.is_active, ti.metadata, ti.created_at, ti.updated_at,
             tf.feed_name, tf.feed_slug
      FROM public.threat_indicators ti
      LEFT JOIN public.threat_feeds tf ON tf.id = ti.feed_id
      ${whereClause}
      ORDER BY ${sortCol} ${sortDirection}
      LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder};
    `;

    const res = await db.query(queryText, params);

    return {
      total,
      limit: safeLimit,
      offset: safeOffset,
      indicators: res.rows || []
    };
  }

  /**
   * Retrieves an indicator by its unique UUID with tenant scoping.
   *
   * @param {string} id
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object|null>}
   */
  async getIndicatorById(id, organizationId = null) {
    const orgId = organizationId || null;
    const queryText = `
      SELECT ti.id, ti.organization_id, ti.feed_id, ti.indicator_type, ti.indicator_value,
             ti.severity, ti.confidence_score, ti.threat_actor, ti.malware_family,
             ti.tags, ti.observation_count, ti.first_seen_at, ti.last_seen_at,
             ti.expires_at, ti.is_active, ti.metadata, ti.created_at, ti.updated_at,
             tf.feed_name, tf.feed_slug
      FROM public.threat_indicators ti
      LEFT JOIN public.threat_feeds tf ON tf.id = ti.feed_id
      WHERE ti.id = $1
        AND ($2::uuid IS NULL AND ti.organization_id IS NULL OR $2::uuid IS NOT NULL AND (ti.organization_id IS NULL OR ti.organization_id = $2));
    `;
    const res = await db.query(queryText, [id, orgId]);
    return res.rows[0] || null;
  }

  /**
   * Retrieves feed health summary.
   *
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object>}
   */
  async getFeedHealth(organizationId = null) {
    const threatFeedService = require('./threatFeedService');
    return await threatFeedService.getFeedHealth(organizationId);
  }

  /**
   * Retrieves feed statistics summary.
   *
   * @param {string|null} [organizationId=null]
   * @returns {Promise<Object>}
   */
  async getFeedStatistics(organizationId = null) {
    const threatFeedService = require('./threatFeedService');
    return await threatFeedService.getFeedStatistics(organizationId);
  }

  /**
   * Retrieves recent incident IOC matches with analyst metadata and tenant isolation.
   *
   * @param {string|null} [organizationId=null]
   * @param {Object} [options={}]
   * @returns {Promise<Object>} { total, limit, offset, matches }
   */
  async getRecentMatches(organizationId = null, options = {}) {
    const orgId = organizationId || null;
    const { limit = 50, offset = 0 } = options;
    const safeLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 50));
    const safeOffset = Math.max(0, parseInt(offset, 10) || 0);

    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM public.incident_ioc_matches
      WHERE ($1::uuid IS NULL OR organization_id = $1);
    `;
    const countRes = await db.query(countQuery, [orgId]);
    const total = countRes.rows[0]?.total || 0;

    const queryText = `
      SELECT
        iim.id,
        iim.incident_id,
        iim.organization_id,
        iim.matched_value AS indicator_value,
        COALESCE(ti.indicator_type, iim.metadata->>'indicator_type', 'unknown') AS indicator_type,
        iim.reputation_score AS confidence_score,
        iim.feed_source AS source_feed,
        iim.matched_at,
        iim.severity AS threat_level,
        iim.match_context,
        inc.threat_type AS incident_threat_type,
        inc.risk_score AS incident_risk_score,
        inc.status AS incident_status
      FROM public.incident_ioc_matches iim
      LEFT JOIN public.threat_indicators ti ON ti.id = iim.indicator_id
      LEFT JOIN public.incidents inc ON inc.id = iim.incident_id
      WHERE ($1::uuid IS NULL OR iim.organization_id = $1)
      ORDER BY iim.matched_at DESC
      LIMIT $2 OFFSET $3;
    `;

    const res = await db.query(queryText, [orgId, safeLimit, safeOffset]);

    return {
      total,
      limit: safeLimit,
      offset: safeOffset,
      matches: res.rows || []
    };
  }
}

const threatIntelService = new ThreatIntelService();

module.exports = threatIntelService;
