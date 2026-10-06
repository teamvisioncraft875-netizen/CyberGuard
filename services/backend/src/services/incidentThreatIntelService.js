const db = require('../config/db');
const threatIntelService = require('./threatIntelService');
const reputationService = require('./reputationService');
const { extractIOCs, normalizeIOC } = require('../utils/iocExtractor');

const VALID_MATCH_CONTEXTS = new Set([
  'source_ip',
  'destination_ip',
  'url_domain',
  'url_path',
  'payload_hash',
  'listening_port_ip',
  'message_body',
  'raw_input'
]);

/**
 * CYBERGUARD Incident Threat Intelligence Enrichment Service
 * Correlates incident telemetry, detection signals, explanations, and payload content
 * against active threat intelligence indicators, calculates dynamic risk boosts,
 * and maintains audit-ready correlation junction records in incident_ioc_matches.
 */
class IncidentThreatIntelService {
  /**
   * Extracts and deduplicates IOCs from multiple potential sources within an incident payload:
   * - detection signals (key/value mappings, object arrays)
   * - URLs and domain references
   * - message bodies and raw text
   * - telemetry payloads
   * - model explanation prose
   *
   * @param {Object} input - Incident context or raw ML result
   * @returns {Array<{ type: string, value: string, match_context: string, signal_id?: string, signal_name?: string }>}
   */
  extractIncidentIOCs(input = {}) {
    if (!input || typeof input !== 'object') return [];

    const extractedList = [];
    const seen = new Set();

    const addExtracted = (type, value, matchContext, extra = {}) => {
      const norm = normalizeIOC(type, value);
      if (!norm) return;

      const safeContext = VALID_MATCH_CONTEXTS.has(matchContext) ? matchContext : 'raw_input';
      const key = `${norm.type}:${norm.value}:${safeContext}`;
      if (seen.has(key)) return;
      seen.add(key);

      extractedList.push({
        type: norm.type,
        value: norm.value,
        match_context: safeContext,
        ...extra
      });
    };

    // 1. Extract from Explanations
    const explanation = input.explanation || input.mlResult?.explanation || '';
    if (typeof explanation === 'string' && explanation.trim()) {
      const iocs = extractIOCs(explanation);
      for (const ioc of iocs) {
        let ctx = 'raw_input';
        if (ioc.type === 'ip') ctx = 'source_ip';
        else if (ioc.type === 'domain') ctx = 'url_domain';
        else if (ioc.type === 'url') ctx = 'url_path';
        else if (['md5', 'sha1', 'sha256'].includes(ioc.type)) ctx = 'payload_hash';
        addExtracted(ioc.type, ioc.value, ctx);
      }
    }

    // 2. Extract from Message Text / Content
    const messageContent = input.text || input.message || input.message_body || input.mlResult?.text || input.mlResult?.message || '';
    if (typeof messageContent === 'string' && messageContent.trim()) {
      const iocs = extractIOCs(messageContent);
      for (const ioc of iocs) {
        let ctx = 'message_body';
        if (ioc.type === 'url') ctx = 'url_path';
        else if (ioc.type === 'domain') ctx = 'url_domain';
        else if (['md5', 'sha1', 'sha256'].includes(ioc.type)) ctx = 'payload_hash';
        addExtracted(ioc.type, ioc.value, ctx);
      }
    }

    // 3. Extract from Explicit URLs
    const explicitUrl = input.url || input.mlResult?.url || input.details?.url || input.mlResult?.details?.url || '';
    if (typeof explicitUrl === 'string' && explicitUrl.trim()) {
      const iocs = extractIOCs(explicitUrl);
      for (const ioc of iocs) {
        const ctx = ioc.type === 'domain' ? 'url_domain' : 'url_path';
        addExtracted(ioc.type, ioc.value, ctx);
      }
    }

    // 4. Extract from Signals (array or dictionary)
    const rawSignals = input.signals || input.mlResult?.signals || [];
    if (Array.isArray(rawSignals)) {
      for (const sig of rawSignals) {
        if (!sig || typeof sig !== 'object') continue;
        const name = String(sig.signal_name || sig.name || Object.keys(sig)[0] || '').toLowerCase();
        const val = sig.signal_value !== undefined ? sig.signal_value : (sig.value !== undefined ? sig.value : sig[name]);
        if (val === undefined || val === null) continue;

        let ctx = 'raw_input';
        if (name.includes('dest') || name.includes('dst')) ctx = 'destination_ip';
        else if (name.includes('src') || name.includes('source')) ctx = 'source_ip';
        else if (name.includes('port') || name.includes('listen')) ctx = 'listening_port_ip';
        else if (name.includes('url')) ctx = 'url_path';
        else if (name.includes('domain')) ctx = 'url_domain';
        else if (name.includes('hash') || name.includes('sha') || name.includes('md5')) ctx = 'payload_hash';
        else if (name.includes('body') || name.includes('msg')) ctx = 'message_body';

        const iocs = extractIOCs(String(val));
        for (const ioc of iocs) {
          addExtracted(ioc.type, ioc.value, ctx, { signal_name: name });
        }
      }
    } else if (rawSignals && typeof rawSignals === 'object') {
      for (const [key, val] of Object.entries(rawSignals)) {
        if (val === undefined || val === null) continue;
        const lowerKey = key.toLowerCase();

        let ctx = 'raw_input';
        if (lowerKey.includes('dest') || lowerKey.includes('dst')) ctx = 'destination_ip';
        else if (lowerKey.includes('src') || lowerKey.includes('source')) ctx = 'source_ip';
        else if (lowerKey.includes('port') || lowerKey.includes('listen')) ctx = 'listening_port_ip';
        else if (lowerKey.includes('url')) ctx = 'url_path';
        else if (lowerKey.includes('domain')) ctx = 'url_domain';
        else if (lowerKey.includes('hash') || lowerKey.includes('sha') || lowerKey.includes('md5')) ctx = 'payload_hash';
        else if (lowerKey.includes('body') || lowerKey.includes('msg')) ctx = 'message_body';

        const iocs = extractIOCs(String(val));
        for (const ioc of iocs) {
          addExtracted(ioc.type, ioc.value, ctx, { signal_name: key });
        }
      }
    }

    // 5. Extract from Telemetry or Details Object
    const details = input.details || input.mlResult?.details || input.telemetry || input.mlResult?.telemetry || {};
    if (details && typeof details === 'object') {
      for (const [key, val] of Object.entries(details)) {
        if (val === undefined || val === null || typeof val === 'object') continue;
        const lowerKey = key.toLowerCase();
        let ctx = 'raw_input';
        if (lowerKey.includes('ip')) ctx = 'source_ip';
        else if (lowerKey.includes('url')) ctx = 'url_path';
        else if (lowerKey.includes('domain')) ctx = 'url_domain';
        else if (lowerKey.includes('hash')) ctx = 'payload_hash';

        const iocs = extractIOCs(String(val));
        for (const ioc of iocs) {
          addExtracted(ioc.type, ioc.value, ctx);
        }
      }
    }

    return extractedList;
  }

  /**
   * Correlates extracted IOCs against Redis cache and PostgreSQL threat_indicators table
   * using a batch Redis-first lookup. Enforces tenant isolation.
   *
   * @param {Array<{ type: string, value: string, match_context: string }>} extractedIOCs
   * @param {Object} [options={}]
   * @param {string|null} [options.organizationId=null]
   * @param {boolean} [options.bypassCache=false]
   * @param {Object|null} [options.client=null]
   * @returns {Promise<Array<Object>>} Correlated match records
   */
  async correlateIncidentIOCs(extractedIOCs = [], options = {}) {
    if (!Array.isArray(extractedIOCs) || extractedIOCs.length === 0) {
      return [];
    }

    const { organizationId = null, bypassCache = false, client = null } = options;

    // Batch lookup all extracted indicators
    const lookupMap = await threatIntelService.lookupBatchIOCs(extractedIOCs, {
      organizationId,
      bypassCache,
      client
    });

    const matches = [];
    const seenMatchKeys = new Set();

    for (const ioc of extractedIOCs) {
      const norm = normalizeIOC(ioc.type, ioc.value);
      if (!norm) continue;

      const normType = norm.type === 'ipv4' || norm.type === 'ipv6' ? 'ip' : norm.type;
      const key = `${normType}:${norm.value}`;
      const indicator = lookupMap.get(key);

      if (indicator) {
        // Enforce tenant scoping: indicator must be global (NULL) or match organizationId
        if (indicator.organization_id && indicator.organization_id !== organizationId) {
          continue;
        }

        const matchContext = VALID_MATCH_CONTEXTS.has(ioc.match_context) ? ioc.match_context : 'raw_input';
        const dedupeKey = `${indicator.id}:${matchContext}`;

        // Deduplicate against unique constraint (incident_id, indicator_id, match_context)
        if (seenMatchKeys.has(dedupeKey)) continue;
        seenMatchKeys.add(dedupeKey);

        matches.push({
          indicator_id: indicator.id,
          matched_value: norm.value,
          match_context: matchContext,
          reputation_score: indicator.confidence_score,
          severity: indicator.severity,
          feed_source: indicator.feed_name || indicator.feed_slug || 'Threat Intelligence Feed',
          threat_actor: indicator.threat_actor || null,
          malware_family: indicator.malware_family || null,
          tags: Array.isArray(indicator.tags) ? indicator.tags : [],
          confidence_score: indicator.confidence_score,
          _cached: Boolean(indicator._cached),
          metadata: {
            indicator_type: indicator.indicator_type,
            threat_actor: indicator.threat_actor,
            malware_family: indicator.malware_family,
            tags: indicator.tags || []
          }
        });
      }
    }

    return matches;
  }

  /**
   * Calculates the Threat Intelligence risk boost and dynamic risk score.
   *
   * Boost tiers based on highest confidence indicator:
   * - 50-69  => +10
   * - 70-89  => +20
   * - 90-100 => +35
   * Final score capped at 100.
   *
   * @param {Array<Object>} matches - Matched indicators
   * @param {number} [baseRiskScore=50] - Initial engine score (0-100)
   * @returns {{ boost: number, highestConfidence: number, highestIndicator: Object|null, finalScore: number, enrichedRiskLevel: string }}
   */
  calculateThreatIntelBoost(matches = [], baseRiskScore = 50) {
    const base = typeof baseRiskScore === 'number' && !isNaN(baseRiskScore) ? baseRiskScore : 50;

    if (!Array.isArray(matches) || matches.length === 0) {
      const roundedBase = Math.min(100, Math.max(0, Math.round(base)));
      return {
        boost: 0,
        highestConfidence: 0,
        highestIndicator: null,
        finalScore: roundedBase,
        enrichedRiskLevel: this._scoreToRiskLevel(roundedBase)
      };
    }

    let highestConfidence = 0;
    let highestIndicator = null;

    for (const m of matches) {
      const conf = m.reputation_score !== undefined ? m.reputation_score : (m.confidence_score || 0);
      if (conf > highestConfidence) {
        highestConfidence = conf;
        highestIndicator = m;
      }
    }

    let boost = 0;
    if (highestConfidence >= 90) {
      boost = 35;
    } else if (highestConfidence >= 70) {
      boost = 20;
    } else if (highestConfidence >= 50) {
      boost = 10;
    }

    const finalScore = Math.min(100, Math.max(0, Math.round(base + boost)));
    const enrichedRiskLevel = this._scoreToRiskLevel(finalScore);

    return {
      boost,
      highestConfidence,
      highestIndicator,
      finalScore,
      enrichedRiskLevel
    };
  }

  /**
   * Helper to map numeric risk scores to standard risk levels.
   * @private
   */
  _scoreToRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  /**
   * Persists correlated IOC matches into incident_ioc_matches within an existing database transaction.
   * Single batch query; idempotent with ON CONFLICT (incident_id, indicator_id, match_context) DO NOTHING.
   *
   * @param {string} incidentId
   * @param {string|null} organizationId
   * @param {Array<Object>} matches
   * @param {Object} dbClient - PostgreSQL client (transaction scope)
   * @returns {Promise<Array<Object>>} Inserted match records
   */
  async persistIncidentIOCMatches(incidentId, organizationId, matches = [], dbClient = null) {
    if (!incidentId || !Array.isArray(matches) || matches.length === 0) {
      return [];
    }
    const client = dbClient || db;

    const values = [];
    const valuePlaceholders = [];

    matches.forEach((match, idx) => {
      const offset = idx * 10;
      valuePlaceholders.push(`(
        $${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5},
        $${offset + 6}, $${offset + 7}, $${offset + 8}, $${offset + 9}, $${offset + 10}
      )`);

      values.push(
        organizationId || null,
        incidentId,
        match.indicator_id,
        match.signal_id || null,
        match.matched_value,
        match.match_context,
        match.reputation_score,
        match.severity || 'medium',
        match.feed_source || 'Threat Intel Feed',
        JSON.stringify(match.metadata || {})
      );
    });

    const queryText = `
      INSERT INTO public.incident_ioc_matches (
        organization_id, incident_id, indicator_id, signal_id, matched_value,
        match_context, reputation_score, severity, feed_source, metadata
      ) VALUES ${valuePlaceholders.join(', ')}
      ON CONFLICT (incident_id, indicator_id, match_context) DO NOTHING
      RETURNING *;
    `;

    try {
      const res = await client.query(queryText, values);
      return res.rows || [];
    } catch (err) {
      console.error('[incidentThreatIntelService.persistIncidentIOCMatches Error]', err.message);
      throw err;
    }
  }

  /**
   * Queries external reputation connectors (AbuseIPDB, VirusTotal, Safe Browsing)
   * for IOCs that did not match local threat intelligence indicators.
   *
   * @param {Array<{ type: string, value: string, match_context: string }>} unmatchedIOCs
   * @param {Object} [options={}]
   * @returns {Promise<Array<Object>>} Malicious external reputation matches
   */
  async queryExternalReputation(unmatchedIOCs = [], options = {}) {
    if (!Array.isArray(unmatchedIOCs) || unmatchedIOCs.length === 0) {
      return [];
    }

    const repMatches = [];
    for (const ioc of unmatchedIOCs) {
      try {
        const rep = await reputationService.lookupIOC(ioc.type, ioc.value, options);
        if (rep && rep.malicious) {
          const isHighConfidence = (rep.confidence >= 80) || (rep.reputation_score >= 80);
          const boost = isHighConfidence ? 25 : 15;
          repMatches.push({
            indicator_value: ioc.value,
            indicator_type: ioc.type,
            match_context: ioc.match_context || 'raw_input',
            source: rep.source,
            reputation_score: rep.reputation_score,
            confidence: rep.confidence,
            categories: rep.categories || [],
            last_seen: rep.last_seen || null,
            malicious: true,
            boost,
            raw: rep.raw
          });
        }
      } catch (err) {
        console.warn(`[incidentThreatIntelService] External reputation error for ${ioc.type}:${ioc.value}:`, err.message);
      }
    }

    return repMatches;
  }

  /**
   * Pre-insert enrichment workflow:
   * 1. Extracts IOCs from incident payload/signals/explanations
   * 2. Correlates IOCs with Redis cache and DB indicators
   * 3. Queries external reputation connectors for unmatched IOCs
   * 4. Calculates dynamic threat intel risk boost + reputation boost
   *
   * @param {Object} params
   * @returns {Promise<Object>} Enrichment result with adjusted risk score, level, and matches
   */
  async enrichIncidentPreInsert({
    threatType,
    sourceType,
    mlResult = {},
    organizationId = null,
    client = null,
    bypassCache = false
  } = {}) {
    const rawSignals = mlResult.signals || {};
    const baseRiskLevel = (mlResult.risk_level || 'medium').toLowerCase();
    const baseRiskScore = typeof mlResult.risk_score === 'number'
      ? mlResult.risk_score
      : (baseRiskLevel === 'critical' ? 90 : baseRiskLevel === 'high' ? 70 : baseRiskLevel === 'medium' ? 50 : 20);

    // 1. Extract IOCs
    const extractedIOCs = this.extractIncidentIOCs({
      threatType,
      sourceType,
      mlResult,
      explanation: mlResult.explanation,
      signals: rawSignals,
      text: mlResult.text || mlResult.message,
      url: mlResult.url || mlResult.details?.url,
      details: mlResult.details
    });

    // 2. Correlate IOCs against local threat intelligence
    const matches = await this.correlateIncidentIOCs(extractedIOCs, {
      organizationId,
      bypassCache,
      client
    });

    // 3. Query external reputation connectors for IOCs not matched locally
    const matchedValues = new Set(matches.map((m) => m.matched_value));
    const unmatchedIOCs = extractedIOCs.filter((ioc) => !matchedValues.has(ioc.value));

    const reputationMatches = await this.queryExternalReputation(unmatchedIOCs, { bypassCache });

    // 4. Calculate Boosts
    const { boost: localBoost, highestConfidence, highestIndicator } =
      this.calculateThreatIntelBoost(matches, baseRiskScore);

    // External reputation boost: +25 if any high-confidence malicious, else +15 if any malicious
    let reputationBoost = 0;
    if (reputationMatches.length > 0) {
      const hasHighConfidence = reputationMatches.some((r) => r.boost === 25);
      reputationBoost = hasHighConfidence ? 25 : 15;
    }

    const totalBoost = localBoost + reputationBoost;
    const finalScore = Math.min(100, Math.max(0, Math.round(baseRiskScore + totalBoost)));
    const enrichedRiskLevel = this._scoreToRiskLevel(finalScore);

    // 5. Construct Enrichment Metadata
    const threatIntelMetadata = {
      matched_ioc_count: matches.length,
      highest_confidence_indicator: highestIndicator ? {
        id: highestIndicator.indicator_id,
        value: highestIndicator.matched_value,
        confidence: highestIndicator.reputation_score,
        severity: highestIndicator.severity,
        threat_actor: highestIndicator.threat_actor,
        malware_family: highestIndicator.malware_family
      } : null,
      matched_feed_names: [...new Set(matches.map((m) => m.feed_source).filter(Boolean))],
      indicator_tags: [...new Set(matches.flatMap((m) => m.tags || []))],
      threat_intel_boost: localBoost,
      reputation_boost: reputationBoost,
      total_boost: totalBoost,
      original_risk_score: baseRiskScore,
      enriched_risk_score: finalScore,
      enriched_risk_level: enrichedRiskLevel,
      reputation_matches: reputationMatches,
      reputation_sources: [...new Set(reputationMatches.map((r) => r.source))]
    };

    return {
      extracted_iocs: extractedIOCs,
      matches,
      reputation_matches: reputationMatches,
      boost: totalBoost,
      local_boost: localBoost,
      reputation_boost: reputationBoost,
      original_risk_score: baseRiskScore,
      enriched_risk_score: finalScore,
      enriched_risk_level: enrichedRiskLevel,
      threat_intel: threatIntelMetadata
    };
  }

  /**
   * End-to-end incident enrichment method.
   * Extracts IOCs, correlates with threat intelligence, calculates risk boosts,
   * and optionally persists incident_ioc_matches if incidentId and dbClient are provided.
   *
   * @param {Object} params
   * @returns {Promise<Object>}
   */
  /**
   * End-to-end incident enrichment method.
   * Extracts IOCs, correlates with threat intelligence, calculates risk boosts,
   * and optionally persists incident_ioc_matches if incidentId and dbClient are provided.
   *
   * @param {Object} params
   * @returns {Promise<Object>}
   */
  async enrichIncident(params = {}) {
    const preResult = await this.enrichIncidentPreInsert(params);

    if (params.incidentId && params.client && preResult.matches.length > 0) {
      await this.persistIncidentIOCMatches(
        params.incidentId,
        params.organizationId || null,
        preResult.matches,
        params.client
      );
    }

    return preResult;
  }

  /**
   * Evaluates response policies for an incident with its threat intelligence findings.
   * Connects IncidentThreatIntelService -> IOC Matches -> PolicyEngine -> ResponseActions.
   *
   * @param {Object} incident
   * @param {Object} [client=null]
   * @returns {Promise<Array<Object>>} Proposed response actions
   */
  async evaluateIncidentPolicies(incident, client = null) {
    const PolicyEngine = require('./PolicyEngine');
    return PolicyEngine.evaluateAndProposeActions(incident, client);
  }
}

const incidentThreatIntelService = new IncidentThreatIntelService();

module.exports = incidentThreatIntelService;
