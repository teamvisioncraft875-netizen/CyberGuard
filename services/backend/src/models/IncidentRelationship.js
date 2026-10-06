const db = require('../config/db');

/**
 * IncidentRelationship Model — Graph edges representing correlations between incidents
 */
const IncidentRelationship = {
  /**
   * Creates a correlation relationship edge between two incidents.
   * Uses ON CONFLICT DO NOTHING to guarantee edge idempotency.
   */
  async create({
    organization_id,
    source_incident_id,
    target_incident_id,
    relationship_type,
    confidence_score,
    rule_id = null,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO incident_relationships (
        organization_id,
        source_incident_id,
        target_incident_id,
        relationship_type,
        confidence_score,
        rule_id,
        metadata,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      ON CONFLICT (source_incident_id, target_incident_id, relationship_type)
      DO NOTHING
      RETURNING *;
    `;

    const res = await dbClient.query(text, [
      organization_id,
      source_incident_id,
      target_incident_id,
      relationship_type,
      confidence_score,
      rule_id,
      typeof metadata === 'object' && metadata !== null ? JSON.stringify(metadata) : '{}'
    ]);

    return res.rows[0] || null;
  },

  /**
   * Finds all relationships associated with a given incident (as source or target).
   */
  async findByIncident(incidentId, organizationId = null, client = null) {
    const dbClient = (organizationId && typeof organizationId === 'object' && organizationId.query)
      ? organizationId
      : (client || db);
    const orgId = (organizationId && typeof organizationId === 'string') ? organizationId : null;

    let text;
    let params;

    if (orgId) {
      text = `
        SELECT
          id,
          organization_id,
          source_incident_id,
          target_incident_id,
          relationship_type,
          confidence_score::float AS confidence_score,
          rule_id,
          metadata,
          created_at,
          CASE
            WHEN source_incident_id = $1 THEN target_incident_id
            ELSE source_incident_id
          END AS related_incident_id
        FROM incident_relationships
        WHERE (source_incident_id = $1 OR target_incident_id = $1)
          AND organization_id = $2
        ORDER BY created_at DESC;
      `;
      params = [incidentId, orgId];
    } else {
      text = `
        SELECT
          id,
          organization_id,
          source_incident_id,
          target_incident_id,
          relationship_type,
          confidence_score::float AS confidence_score,
          rule_id,
          metadata,
          created_at,
          CASE
            WHEN source_incident_id = $1 THEN target_incident_id
            ELSE source_incident_id
          END AS related_incident_id
        FROM incident_relationships
        WHERE source_incident_id = $1 OR target_incident_id = $1
        ORDER BY created_at DESC;
      `;
      params = [incidentId];
    }

    const res = await dbClient.query(text, params);
    return res.rows;
  },

  /**
   * Returns distinct UUIDs of incidents related to the given incident.
   */
  async findRelatedIncidentIds(incidentId, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT DISTINCT
        CASE
          WHEN source_incident_id = $1 THEN target_incident_id
          ELSE source_incident_id
        END AS related_incident_id
      FROM incident_relationships
      WHERE source_incident_id = $1 OR target_incident_id = $1;
    `;
    const res = await dbClient.query(text, [incidentId]);
    return res.rows.map(r => r.related_incident_id);
  },

  /**
   * Checks whether a relationship edge already exists between two incidents with given type.
   * Checks both directions (source->target or target->source) to prevent duplicate inverse edges.
   */
  async exists(sourceId, targetId, type, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT 1 FROM incident_relationships
      WHERE ((source_incident_id = $1 AND target_incident_id = $2)
         OR  (source_incident_id = $2 AND target_incident_id = $1))
        AND relationship_type = $3
      LIMIT 1;
    `;
    const res = await dbClient.query(text, [sourceId, targetId, type]);
    return res.rowCount > 0;
  }
};

module.exports = IncidentRelationship;
