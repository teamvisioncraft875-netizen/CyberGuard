const db = require('../../config/db');

/**
 * Timeline Service — Aggregates unified operational security events, detections,
 * incidents, and attack chains into a single chronological investigation timeline.
 */
const timelineService = {
  /**
   * Retrieves paginated, unified chronological security timeline for an organization.
   */
  async getUnifiedTimeline(organizationId, {
    limit = 50,
    offset = 0,
    startDate = null,
    endDate = null,
    types = null // optional filter: ['event', 'detection', 'incident', 'attack_chain']
  } = {}, client = null) {
    if (!organizationId) {
      throw new Error('timelineService: organizationId is required');
    }
    const dbClient = client || db;

    const parsedLimit = Math.max(1, Math.min(200, parseInt(limit, 10) || 50));
    const parsedOffset = Math.max(0, parseInt(offset, 10) || 0);

    const timeFilters = [];
    const params = [organizationId];

    if (startDate) {
      params.push(new Date(startDate));
      timeFilters.push(`timestamp >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      timeFilters.push(`timestamp <= $${params.length}`);
    }

    const timeWhereClause = timeFilters.length > 0 ? `AND ${timeFilters.join(' AND ')}` : '';

    const query = `
      WITH unified AS (
        -- 1. Security Events
        SELECT
          id,
          'event' AS item_type,
          event_timestamp AS timestamp,
          severity::text AS severity,
          event_type::text AS title,
          jsonb_build_object(
            'source_type', source_type,
            'device_id', device_id,
            'user_id', user_id,
            'normalized_summary', normalized_event->>'summary'
          ) AS details
        FROM public.security_events
        WHERE organization_id = $1 ${timeWhereClause.replace(/timestamp/g, 'event_timestamp')}

        UNION ALL

        -- 2. Detection Hits
        SELECT
          h.id,
          'detection' AS item_type,
          h.matched_at AS timestamp,
          COALESCE(r.severity::text, 'high') AS severity,
          COALESCE(r.name::text, 'SIEM Detection Hit') AS title,
          jsonb_build_object(
            'rule_id', h.rule_id,
            'incident_id', h.incident_id,
            'confidence_score', h.confidence_score,
            'metadata', h.metadata
          ) AS details
        FROM public.siem_detection_hits h
        LEFT JOIN public.siem_detection_rules r ON h.rule_id = r.id
        WHERE h.organization_id = $1 ${timeWhereClause.replace(/timestamp/g, 'h.matched_at')}

        UNION ALL

        -- 3. Incidents
        SELECT
          id,
          'incident' AS item_type,
          created_at AS timestamp,
          risk_level::text AS severity,
          threat_type::text AS title,
          jsonb_build_object(
            'risk_score', risk_score,
            'status', status,
            'priority', priority,
            'source_type', source_type
          ) AS details
        FROM public.incidents
        WHERE organization_id = $1 ${timeWhereClause.replace(/timestamp/g, 'created_at')}

        UNION ALL

        -- 4. Attack Chain Snapshots
        SELECT
          id,
          'attack_chain' AS item_type,
          created_at AS timestamp,
          'high'::text AS severity,
          'MITRE Attack Chain Progression'::text AS title,
          jsonb_build_object(
            'root_incident_id', root_incident_id,
            'chain_length', chain_length,
            'confidence_score', confidence_score
          ) AS details
        FROM public.attack_chain_snapshots
        WHERE organization_id = $1 ${timeWhereClause.replace(/timestamp/g, 'created_at')}
      )
      SELECT *
      FROM unified
      ${types && Array.isArray(types) && types.length > 0 ? `WHERE item_type = ANY(ARRAY['${types.join("','")}'])` : ''}
      ORDER BY timestamp DESC
      LIMIT ${parsedLimit} OFFSET ${parsedOffset};
    `;

    const res = await dbClient.query(query, params);
    return res.rows;
  }
};

module.exports = timelineService;
