const RecommendedAction = require('../models/RecommendedAction');

const VALID_ACTION_STATUSES = Object.freeze(['taken', 'dismissed']);
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Action Controller — Handles triage operations on incident recommended actions.
 */
const actionController = {
  /**
   * PATCH /api/v1/actions/:id
   * Updates a recommended action's status to 'taken' or 'dismissed'.
   */
  async updateActionStatus(req, res) {
    const { id } = req.params;
    const { action_status } = req.body;

    // Reject non-UUID IDs cleanly with 404 to avoid SQL syntax errors
    if (!UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Recommended action not found'
      });
    }

    // Validate requested status
    if (!action_status || !VALID_ACTION_STATUSES.includes(action_status)) {
      return res.status(400).json({
        error: 'INVALID_STATUS',
        message: "action_status must be either 'taken' or 'dismissed'"
      });
    }

    // Tenant Scoping Discipline:
    // Non-admin can only access actions linked to their own incidents (incident.user_id = req.user.id)
    // Admin can only access actions linked to their organization's incidents (incident.organization_id = req.user.organization_id)
    const scope = {};
    if (req.user?.role === 'admin') {
      scope.organization_id = req.user.organization_id || null;
      if (!scope.organization_id) {
        scope.user_id = req.user.id;
      }
    } else {
      scope.user_id = req.user?.id;
    }

    try {
      // Verify action exists and belongs to an incident accessible to the requesting user
      const action = await RecommendedAction.findByIdAndScope(id, scope);
      if (!action) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Recommended action not found'
        });
      }

      // Update the action_status column and return the updated row
      const updated = await RecommendedAction.updateStatus(id, action_status);
      return res.status(200).json(updated);
    } catch (err) {
      console.error('[actionController.updateActionStatus error]', err.message);
      return res.status(500).json({
        error: 'DB_ERROR',
        message: 'Failed to update recommended action status'
      });
    }
  }
};

module.exports = actionController;
