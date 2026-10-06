const db = require('../config/db');

/**
 * IncidentRecommendation Model — CRUD operations on the 'incident_recommendations' table
 */
const IncidentRecommendation = {
  /**
   * Create a single recommendation
   */
  async create({
    organization_id,
    incident_id,
    title,
    description,
    priority = 'medium',
    automatable = false,
    action_type = null,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO incident_recommendations (
        organization_id, incident_id, title, description, priority, automatable, action_type, metadata, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      incident_id,
      title,
      description,
      priority,
      Boolean(automatable),
      action_type,
      JSON.stringify(metadata)
    ]);
    return res.rows[0];
  },

  /**
   * Bulk create recommendations
   */
  async createMany(recommendations = [], client = null) {
    if (!recommendations || recommendations.length === 0) return [];
    const results = [];
    for (const rec of recommendations) {
      const created = await this.create(rec, client);
      results.push(created);
    }
    return results;
  },

  /**
   * Find recommendations for an incident
   */
  async findByIncident(incidentId, organizationId = null, client = null) {
    const dbClient = client || db;
    const conditions = ['incident_id = $1'];
    const values = [incidentId];

    if (organizationId) {
      values.push(organizationId);
      conditions.push(`organization_id = $${values.length}`);
    }

    const text = `
      SELECT * FROM incident_recommendations
      WHERE ${conditions.join(' AND ')}
      ORDER BY 
        CASE priority
          WHEN 'P1' THEN 1
          WHEN 'critical' THEN 2
          WHEN 'P2' THEN 3
          WHEN 'high' THEN 4
          WHEN 'P3' THEN 5
          WHEN 'medium' THEN 6
          WHEN 'P4' THEN 7
          WHEN 'low' THEN 8
          ELSE 9
        END ASC,
        created_at DESC;
    `;
    const res = await dbClient.query(text, values);
    return res.rows;
  },

  /**
   * Delete existing recommendations for an incident (e.g. before regenerating)
   */
  async deleteByIncident(incidentId, organizationId = null, client = null) {
    const dbClient = client || db;
    const conditions = ['incident_id = $1'];
    const values = [incidentId];

    if (organizationId) {
      values.push(organizationId);
      conditions.push(`organization_id = $${values.length}`);
    }

    const text = `DELETE FROM incident_recommendations WHERE ${conditions.join(' AND ')} RETURNING id;`;
    const res = await dbClient.query(text, values);
    return res.rows;
  }
};

module.exports = IncidentRecommendation;
