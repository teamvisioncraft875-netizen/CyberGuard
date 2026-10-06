const investigationWorkspaceService = require('../services/investigationWorkspaceService');
const recommendationEngine = require('../services/recommendationEngine');
const incidentPrioritizationService = require('../services/incidentPrioritizationService');
const commandCenterService = require('../services/commandCenterService');
const incidentWorkflowService = require('../services/incidentWorkflowService');

/**
 * Controller for SOC Investigation, Command Center, and Workflow APIs
 */
const investigationController = {
  /**
   * GET /api/v1/incidents/:id/workspace
   */
  async getWorkspace(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const result = await investigationWorkspaceService.getWorkspace(id, organizationId, {
        actorUserId: req.user.id
      });

      if (!result) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Incident ${id} not found in this organization`
        });
      }

      return res.status(200).json({
        status: 'success',
        ...result
      });
    } catch (err) {
      console.error('[InvestigationController Error] getWorkspace failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/incidents/:id/notes
   */
  async addNote(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;
      const { note } = req.body;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      if (!note || typeof note !== 'string' || !note.trim()) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Field "note" is required and cannot be empty'
        });
      }

      const created = await investigationWorkspaceService.addNote(id, organizationId, {
        userId: req.user.id,
        note
      });

      return res.status(201).json({
        status: 'success',
        note: created
      });
    } catch (err) {
      console.error('[InvestigationController Error] addNote failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/incidents/:id/recommendations
   */
  async getRecommendations(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;
      const refresh = req.query.refresh === 'true';

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const recommendations = await recommendationEngine.getRecommendations(id, organizationId, {
        refresh,
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        incident_id: id,
        count: recommendations.length,
        recommendations
      });
    } catch (err) {
      console.error('[InvestigationController Error] getRecommendations failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/incidents/:id/command-center
   */
  async getCommandCenter(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const payload = await commandCenterService.getCommandCenter(id, organizationId, {
        actorUserId: req.user.id
      });

      if (!payload) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Incident ${id} not found in this organization`
        });
      }

      return res.status(200).json({
        status: 'success',
        ...payload
      });
    } catch (err) {
      console.error('[InvestigationController Error] getCommandCenter failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/incidents/prioritized
   */
  async getPrioritizedIncidents(req, res) {
    try {
      const organizationId = req.user.organization_id;
      const { status, priority, limit = 50, offset = 0 } = req.query;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const incidents = await incidentPrioritizationService.getPrioritizedIncidents(organizationId, {
        status,
        priority,
        limit: Math.min(100, parseInt(limit, 10) || 50),
        offset: Math.max(0, parseInt(offset, 10) || 0)
      });

      return res.status(200).json({
        status: 'success',
        count: incidents.length,
        incidents
      });
    } catch (err) {
      console.error('[InvestigationController Error] getPrioritizedIncidents failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/incidents/queue
   */
  async getQueue(req, res) {
    try {
      const organizationId = req.user.organization_id;
      const { assigned_to, limit = 50, offset = 0 } = req.query;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const queue = await incidentPrioritizationService.getQueue(organizationId, {
        assigned_to,
        limit: Math.min(100, parseInt(limit, 10) || 50),
        offset: Math.max(0, parseInt(offset, 10) || 0)
      });

      return res.status(200).json({
        status: 'success',
        count: queue.length,
        queue
      });
    } catch (err) {
      console.error('[InvestigationController Error] getQueue failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/incidents/:id/assign
   */
  async assignIncident(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;
      const { user_id } = req.body;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      if (!user_id) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Field "user_id" is required for assignment'
        });
      }

      const updated = await incidentWorkflowService.assignIncident(id, organizationId, user_id, {
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        message: 'Incident assigned successfully',
        incident: updated
      });
    } catch (err) {
      console.error('[InvestigationController Error] assignIncident failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/incidents/:id/escalate
   */
  async escalateIncident(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;
      const { reason } = req.body || {};

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const updated = await incidentWorkflowService.escalateIncident(id, organizationId, {
        actorUserId: req.user.id,
        reason
      });

      return res.status(200).json({
        status: 'success',
        message: 'Incident escalated to P1 priority',
        incident: updated
      });
    } catch (err) {
      console.error('[InvestigationController Error] escalateIncident failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/incidents/:id/resolve
   */
  async resolveIncident(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const updated = await incidentWorkflowService.resolveIncident(id, organizationId, {
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        message: 'Incident marked as resolved',
        incident: updated
      });
    } catch (err) {
      console.error('[InvestigationController Error] resolveIncident failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/incidents/:id/reopen
   */
  async reopenIncident(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user.organization_id;
      const { reason } = req.body || {};

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const updated = await incidentWorkflowService.reopenIncident(id, organizationId, {
        actorUserId: req.user.id,
        reason
      });

      return res.status(200).json({
        status: 'success',
        message: 'Incident reopened to open status',
        incident: updated
      });
    } catch (err) {
      console.error('[InvestigationController Error] reopenIncident failed:', err);
      if (err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  }
};

module.exports = investigationController;
