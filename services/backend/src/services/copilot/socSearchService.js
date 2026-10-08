const db = require('../../config/db');
const socQueryParser = require('./socQueryParser');
const { log: auditLog } = require('../auditService');

/**
 * SOC Search Service — Executes structured entity searches based on parsed natural language queries.
 * Enforces strict tenant isolation and ranks results by security relevance.
 */
class SocSearchService {
  /**
   * Executes a search inquiry.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id] - Invoking user ID
   * @param {string} params.query - Natural language query string
   * @param {Object} [params.structuredQuery] - Pre-parsed query object
   * @param {number} [params.limit=10]
   * @param {Object} [client] - DB client
   * @returns {Promise<{ entity: string, count: number, results: Array, parsed: Object }>}
   */
  async search({
    organization_id,
    user_id = null,
    query,
    structuredQuery = null,
    limit = 10
  }, client = null) {
    if (!organization_id) throw new Error('SocSearchService requires organization_id');

    const dbClient = client || db;
    const parsed = structuredQuery || socQueryParser.parse(query);
    const { entity, severity, status, timeRangeHours, keywords, mitreTechnique } = parsed;

    let results = [];

    switch (entity) {
      case 'alerts': {
        const conditions = ['organization_id = $1'];
        const params = [organization_id];

        if (severity) {
          params.push(severity);
          conditions.push(`LOWER(severity) = $${params.length}`);
        }
        if (status) {
          if (status === 'open') {
            conditions.push(`status IN ('new', 'investigating')`);
          } else {
            params.push(status);
            conditions.push(`LOWER(status) = $${params.length}`);
          }
        }
        if (mitreTechnique) {
          params.push(`%${mitreTechnique}%`);
          conditions.push(`mitre_technique ILIKE $${params.length}`);
        }
        if (timeRangeHours) {
          params.push(timeRangeHours);
          conditions.push(`created_at >= NOW() - ($${params.length} || ' hours')::interval`);
        }
        if (keywords) {
          params.push(`%${keywords}%`);
          const kIdx = params.length;
          conditions.push(`(title ILIKE $${kIdx} OR metadata::text ILIKE $${kIdx})`);
        }

        params.push(limit);
        const limitIdx = params.length;

        const sql = `
          SELECT id, title, severity, status, source_type, mitre_technique, metadata, created_at,
                 (CASE WHEN severity = 'critical' THEN 4 WHEN severity = 'high' THEN 3 WHEN severity = 'medium' THEN 2 ELSE 1 END) as rank_score
          FROM public.siem_alerts
          WHERE ${conditions.join(' AND ')}
          ORDER BY rank_score DESC, created_at DESC
          LIMIT $${limitIdx};
        `;
        const res = await dbClient.query(sql, params);
        results = res.rows.map(r => ({
          type: 'alert',
          id: r.id,
          title: r.title,
          severity: r.severity,
          status: r.status,
          mitre_technique: r.mitre_technique,
          created_at: r.created_at,
          metadata: r.metadata
        }));
        break;
      }

      case 'incidents': {
        const conditions = ['organization_id = $1'];
        const params = [organization_id];

        if (severity) {
          params.push(severity);
          conditions.push(`LOWER(risk_level::text) = $${params.length}`);
        }
        if (status) {
          params.push(status);
          conditions.push(`LOWER(status::text) = $${params.length}`);
        }
        if (timeRangeHours) {
          params.push(timeRangeHours);
          conditions.push(`created_at >= NOW() - ($${params.length} || ' hours')::interval`);
        }
        if (keywords) {
          params.push(`%${keywords}%`);
          const kIdx = params.length;
          conditions.push(`(explanation ILIKE $${kIdx} OR threat_type::text ILIKE $${kIdx})`);
        }

        params.push(limit);
        const limitIdx = params.length;

        const sql = `
          SELECT id, threat_type, source_type, risk_level, risk_score, explanation, status, priority, created_at
          FROM public.incidents
          WHERE ${conditions.join(' AND ')}
          ORDER BY risk_score DESC, created_at DESC
          LIMIT $${limitIdx};
        `;
        const res = await dbClient.query(sql, params);
        results = res.rows.map(r => ({
          type: 'incident',
          id: r.id,
          threat_type: r.threat_type,
          risk_level: r.risk_level,
          risk_score: r.risk_score,
          explanation: r.explanation,
          status: r.status,
          created_at: r.created_at
        }));
        break;
      }

      case 'cases': {
        const conditions = ['organization_id = $1'];
        const params = [organization_id];

        if (severity) {
          params.push(severity);
          conditions.push(`LOWER(severity::text) = $${params.length}`);
        }
        if (status) {
          if (status === 'open') {
            conditions.push(`status::text IN ('open', 'in_progress', 'investigating')`);
          } else {
            params.push(status);
            conditions.push(`LOWER(status::text) = $${params.length}`);
          }
        }
        if (keywords) {
          params.push(`%${keywords}%`);
          const kIdx = params.length;
          conditions.push(`(title ILIKE $${kIdx} OR description ILIKE $${kIdx})`);
        }

        params.push(limit);
        const limitIdx = params.length;

        try {
          const sql = `
            SELECT id, title, severity, status, priority, threat_intel_findings, created_at
            FROM public.soar_cases
            WHERE ${conditions.join(' AND ')}
            ORDER BY created_at DESC
            LIMIT $${limitIdx};
          `;
          const res = await dbClient.query(sql, params);
          results = res.rows.map(r => ({
            type: 'case',
            id: r.id,
            title: r.title,
            severity: r.severity,
            status: r.status,
            priority: r.priority,
            created_at: r.created_at
          }));
        } catch (_) {
          results = [];
        }
        break;
      }

      case 'iocs': {
        const conditions = ['organization_id = $1'];
        const params = [organization_id];

        if (keywords) {
          const kwList = String(keywords).split(/\s+/).filter(Boolean);
          if (kwList.length === 1) {
            params.push(`%${kwList[0]}%`);
            const kIdx = params.length;
            conditions.push(`(ioc_value ILIKE $${kIdx} OR COALESCE(threat_actor, '') ILIKE $${kIdx} OR COALESCE(malware_family, '') ILIKE $${kIdx} OR COALESCE(tags::text, '') ILIKE $${kIdx})`);
          } else {
            const orClauses = [];
            for (const kw of kwList) {
              params.push(`%${kw}%`);
              const kIdx = params.length;
              orClauses.push(`(ioc_value ILIKE $${kIdx} OR COALESCE(threat_actor, '') ILIKE $${kIdx} OR COALESCE(malware_family, '') ILIKE $${kIdx} OR COALESCE(tags::text, '') ILIKE $${kIdx})`);
            }
            conditions.push(`(${orClauses.join(' OR ')})`);
          }
        }

        params.push(limit);
        const limitIdx = params.length;

        const sql = `
          SELECT id, ioc_type, ioc_value, risk_score, confidence, threat_actor, malware_family, tags, created_at
          FROM public.threat_iocs
          WHERE ${conditions.join(' AND ')}
          ORDER BY risk_score DESC, created_at DESC
          LIMIT $${limitIdx};
        `;
        const res = await dbClient.query(sql, params);
        results = res.rows.map(r => ({
          type: 'ioc',
          id: r.id,
          ioc_type: r.ioc_type,
          ioc_value: r.ioc_value,
          risk_score: r.risk_score,
          threat_actor: r.threat_actor,
          malware_family: r.malware_family,
          tags: r.tags
        }));
        break;
      }

      case 'threat_intel':
      default: {
        // Return blended threat intelligence findings (high risk IOCs + active threats)
        const sql = `
          SELECT id, ioc_type, ioc_value, risk_score, threat_actor, malware_family, created_at
          FROM public.threat_iocs
          WHERE organization_id = $1
          ORDER BY risk_score DESC, created_at DESC
          LIMIT $2;
        `;
        const res = await dbClient.query(sql, [organization_id, limit]);
        results = res.rows.map(r => ({
          type: 'threat_intel',
          id: r.id,
          indicator: `${r.ioc_type}:${r.ioc_value}`,
          risk_score: r.risk_score,
          threat_actor: r.threat_actor || 'Unknown Actor',
          malware_family: r.malware_family || 'N/A'
        }));
        break;
      }
    }

    // Audit log SOC search query
    await auditLog({
      organization_id,
      user_id,
      action: 'COPILOT_SOC_SEARCH',
      resource_type: 'copilot',
      resource_id: entity,
      details: {
        query_type: 'soc_search',
        entity,
        results_count: results.length,
        parsed_filter: { severity, status, mitreTechnique, timeRangeHours }
      }
    }).catch(() => {});

    return {
      entity,
      count: results.length,
      results,
      parsed
    };
  }
}

const socSearchService = new SocSearchService();
module.exports = socSearchService;
