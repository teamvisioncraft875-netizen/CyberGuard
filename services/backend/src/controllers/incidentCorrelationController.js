const db = require('../config/db');
const IncidentRelationship = require('../models/IncidentRelationship');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for Incident Correlation & Graph Relationships
 */
const incidentCorrelationController = {
  /**
   * GET /api/v1/incidents/:id/related
   * Returns all correlated/related incidents for a specific incident.
   * Enforces role checks (admin/analyst) and strict tenant isolation.
   */
  async getRelatedIncidents(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident not found'
      });
    }

    const orgId = req.user?.organization_id;

    try {
      // 1. Verify incident exists and belongs to the user's organization
      let incidentQuery = `SELECT id, organization_id FROM public.incidents WHERE id = $1;`;
      const incRes = await db.query(incidentQuery, [id]);

      if (incRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      const incident = incRes.rows[0];

      // Strict tenant isolation: user's org must match incident's org
      if (orgId && incident.organization_id && incident.organization_id !== orgId) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      // 2. Fetch all relationships where this incident is source or target
      const relationships = await IncidentRelationship.findByIncident(id);

      // Filter by tenant organization if applicable
      const tenantFiltered = orgId
        ? relationships.filter(r => !r.organization_id || r.organization_id === orgId)
        : relationships;

      // 3. Format response as specified in API contract
      const formatted = tenantFiltered.map(r => ({
        relationship_type: r.relationship_type,
        confidence_score: typeof r.confidence_score === 'number' ? r.confidence_score : parseFloat(r.confidence_score),
        related_incident_id: r.related_incident_id,
        created_at: r.created_at
      }));

      return res.status(200).json({
        incident_id: id,
        relationships: formatted
      });
    } catch (err) {
      console.error('[IncidentCorrelationController.getRelatedIncidents Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve related incidents'
      });
    }
  }
};

module.exports = incidentCorrelationController;
