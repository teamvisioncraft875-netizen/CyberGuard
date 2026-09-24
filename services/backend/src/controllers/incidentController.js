const Incident = require('../models/Incident');

const VALID_INCIDENT_STATUSES = Object.freeze(['open', 'investigating', 'resolved']);

/**
 * Incident Controller — Triage and investigation endpoints for Command Dashboard.
 */
const incidentController = {
  /**
   * GET /api/v1/incidents
   */
  async listIncidents(req, res) {
    const { risk_level, category, status } = req.query;

    // Strict tenant isolation:
    // Non-admin (individual / employee) is forced to their own user_id.
    // Admin is forced to their own organization_id (ignoring any client-supplied organization_id).
    const filter = { risk_level, category, status };
    if (req.user?.role === 'admin') {
      filter.organization_id = req.user.organization_id;
    } else {
      filter.user_id = req.user?.id;
    }

    try {
      const incidents = await Incident.findAll(filter);
      return res.status(200).json(incidents);
    } catch (err) {
      console.error('[incidentController.listIncidents error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve incidents' });
    }
  },

  /**
   * PATCH /api/v1/incidents/:id
   */
  async updateIncidentStatus(req, res) {
    const { id } = req.params;
    const { status } = req.body;

    if (!status || !VALID_INCIDENT_STATUSES.includes(status)) {
      return res.status(400).json({
        error: 'INVALID_STATUS',
        message: "Status must be one of: 'open', 'investigating', 'resolved'"
      });
    }

    // Force organization scope: admin can only update incidents within their own organization
    const orgId = req.user?.organization_id || null;

    try {
      const updated = await Incident.updateStatus(id, status, req.user?.id, orgId);
      if (!updated) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found or does not belong to your organization'
        });
      }

      return res.status(200).json({
        id: updated.id,
        status: updated.status,
        resolved_by: updated.resolved_by || req.user?.id,
        updated_at: updated.resolved_at || updated.updated_at || new Date().toISOString()
      });
    } catch (err) {
      console.error('[incidentController.updateIncidentStatus error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to update incident status' });
    }
  }
};

module.exports = incidentController;
