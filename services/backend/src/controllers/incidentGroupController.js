const IncidentGroup = require('../models/IncidentGroup');
const IncidentGroupMember = require('../models/IncidentGroupMember');
const incidentGroupingService = require('../services/incidentGroupingService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for Incident Groups & Campaign Aggregation
 */
const incidentGroupController = {
  /**
   * GET /api/v1/incident-groups
   * Lists incident groups for the authenticated user's organization.
   */
  async listGroups(req, res) {
    try {
      const orgId = req.user?.organization_id;
      const { status, group_type, page = 1 } = req.query;
      const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 25, 100));
      const parsedPage = Math.max(1, parseInt(page, 10) || 1);
      const offset = (parsedPage - 1) * limit;

      const { groups, total } = await IncidentGroup.list({
        organization_id: orgId,
        status,
        group_type,
        limit,
        offset
      });

      // Enrich groups with member counts and basic metrics
      const enriched = await Promise.all(
        groups.map(async (g) => {
          const metrics = await incidentGroupingService.getGroupMetrics(g.id);
          return {
            ...g,
            metrics
          };
        })
      );

      return res.status(200).json({
        total,
        page: parsedPage,
        limit,
        groups: enriched
      });
    } catch (err) {
      console.error('[IncidentGroupController.listGroups Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to list incident groups'
      });
    }
  },

  /**
   * GET /api/v1/incident-groups/:id
   * Retrieves an incident group, its member incidents, and aggregate metrics.
   */
  async getGroupById(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident group not found'
      });
    }

    try {
      const orgId = req.user?.organization_id;
      const group = await IncidentGroup.findById(id);

      if (!group) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident group not found'
        });
      }

      // Tenant isolation check
      if (orgId && group.organization_id && group.organization_id !== orgId) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident group not found'
        });
      }

      const [members, metrics] = await Promise.all([
        IncidentGroupMember.findByGroup(id),
        incidentGroupingService.getGroupMetrics(id)
      ]);

      return res.status(200).json({
        group,
        members,
        metrics
      });
    } catch (err) {
      console.error('[IncidentGroupController.getGroupById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve incident group'
      });
    }
  },

  /**
   * POST /api/v1/incident-groups/:id/resolve
   * Resolves an incident group and cascades resolution to all member incidents.
   */
  async resolveGroup(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident group not found'
      });
    }

    try {
      const orgId = req.user?.organization_id;
      const resolvedById = req.user?.id || null;

      const result = await incidentGroupingService.resolveGroup(id, orgId, resolvedById);

      return res.status(200).json({
        success: true,
        group: result.group,
        resolved_incidents_count: result.resolved_incidents_count,
        resolved_incident_ids: result.resolved_incident_ids
      });
    } catch (err) {
      if (err.status === 404 || err.message === 'Incident group not found') {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident group not found'
        });
      }

      console.error('[IncidentGroupController.resolveGroup Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to resolve incident group'
      });
    }
  }
};

module.exports = incidentGroupController;
