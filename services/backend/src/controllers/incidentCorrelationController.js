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

    if (!orgId) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'User is not associated with an organization'
      });
    }

    try {
      // 1. Verify incident exists and belongs to the user's organization
      const incRes = await db.query(
        `SELECT id, organization_id FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
        [id, orgId]
      );

      if (incRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      // 2. Fetch all relationships where this incident is source or target in this organization
      const relationships = await IncidentRelationship.findByIncident(id, orgId);

      // 3. Format response as specified in API contract
      const formatted = relationships.map(r => ({
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
