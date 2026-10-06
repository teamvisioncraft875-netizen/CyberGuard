const SoarPlaybook = require('../models/SoarPlaybook');
const SoarExecution = require('../models/SoarExecution');
const SoarApproval = require('../models/SoarApproval');
const approvalService = require('../services/soar/approvalService');
const playbookEngine = require('../services/soar/playbookEngine');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const soarController = {
  // =========================================================================
  // PLAYBOOK MANAGEMENT
  // =========================================================================

  /**
   * POST /api/v1/soar/playbooks
   */
  async createPlaybook(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        name,
        description = null,
        enabled = true,
        trigger_type = 'alert',
        trigger_conditions = {},
        steps = []
      } = req.body;

      if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Playbook name string is required'
        });
      }

      const playbook = await SoarPlaybook.create({
        organization_id: orgId,
        name: name.trim(),
        description,
        enabled,
        trigger_type,
        trigger_conditions,
        created_by: req.user.id,
        steps
      });

      await auditLog({
        organization_id: orgId,
        actor_id: req.user.id,
        action: AUDIT_ACTIONS.SOAR_PLAYBOOK_CREATED,
        resource_type: 'soar_playbook',
        resource_id: playbook.id,
        details: { name: playbook.name, trigger_type: playbook.trigger_type, step_count: steps.length }
      }).catch(err => console.error('[soarController] Audit log error:', err.message));

      return res.status(201).json({
        success: true,
        data: playbook
      });
    } catch (err) {
      console.error('[soarController.createPlaybook] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/soar/playbooks
   */
  async listPlaybooks(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        enabled,
        trigger_type,
        search,
        limit = 50,
        offset = 0
      } = req.query;

      const parsedEnabled = enabled !== undefined ? enabled === 'true' || enabled === true : undefined;

      const result = await SoarPlaybook.findMany({
        organization_id: orgId,
        enabled: parsedEnabled,
        trigger_type,
        search,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        success: true,
        data: result.data,
        total: result.total
      });
    } catch (err) {
      console.error('[soarController.listPlaybooks] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/soar/playbooks/:id
   */
  async getPlaybookById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid playbook ID format (must be UUID)'
        });
      }

      const playbook = await SoarPlaybook.findById(id, orgId);
      if (!playbook) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Playbook not found'
        });
      }

      return res.status(200).json({
        success: true,
        data: playbook
      });
    } catch (err) {
      console.error('[soarController.getPlaybookById] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * PATCH /api/v1/soar/playbooks/:id
   */
  async updatePlaybook(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid playbook ID format (must be UUID)'
        });
      }

      const updated = await SoarPlaybook.update(id, orgId, req.body);
      if (!updated) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Playbook not found'
        });
      }

      await auditLog({
        organization_id: orgId,
        actor_id: req.user.id,
        action: AUDIT_ACTIONS.SOAR_PLAYBOOK_UPDATED,
        resource_type: 'soar_playbook',
        resource_id: id,
        details: { updates: Object.keys(req.body) }
      }).catch(err => console.error('[soarController] Audit log error:', err.message));

      return res.status(200).json({
        success: true,
        data: updated
      });
    } catch (err) {
      console.error('[soarController.updatePlaybook] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * DELETE /api/v1/soar/playbooks/:id
   */
  async deletePlaybook(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid playbook ID format (must be UUID)'
        });
      }

      const deleted = await SoarPlaybook.delete(id, orgId);
      if (!deleted) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Playbook not found'
        });
      }

      await auditLog({
        organization_id: orgId,
        actor_id: req.user.id,
        action: AUDIT_ACTIONS.SOAR_PLAYBOOK_DELETED,
        resource_type: 'soar_playbook',
        resource_id: id,
        details: {}
      }).catch(err => console.error('[soarController] Audit log error:', err.message));

      return res.status(200).json({
        success: true,
        message: 'Playbook deleted successfully'
      });
    } catch (err) {
      console.error('[soarController.deletePlaybook] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  // =========================================================================
  // EXECUTION MANAGEMENT
  // =========================================================================

  /**
   * GET /api/v1/soar/executions
   */
  async listExecutions(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        playbook_id,
        status,
        limit = 50,
        offset = 0
      } = req.query;

      const result = await SoarExecution.findMany({
        organization_id: orgId,
        playbook_id,
        status,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        success: true,
        data: result.data,
        total: result.total
      });
    } catch (err) {
      console.error('[soarController.listExecutions] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/soar/executions/:id
   */
  async getExecutionById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid execution ID format (must be UUID)'
        });
      }

      const execution = await SoarExecution.findById(id, orgId);
      if (!execution) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Execution not found'
        });
      }

      return res.status(200).json({
        success: true,
        data: execution
      });
    } catch (err) {
      console.error('[soarController.getExecutionById] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/soar/playbooks/:id/execute
   */
  async executePlaybookManually(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid playbook ID format (must be UUID)'
        });
      }

      const playbook = await SoarPlaybook.findById(id, orgId);
      if (!playbook) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Playbook not found'
        });
      }

      const alertContext = req.body.alert || {
        id: req.body.alert_id || null,
        organization_id: orgId,
        title: `Manual Execution: ${playbook.name}`,
        severity: 'high'
      };

      const executions = await playbookEngine.triggerPlaybook(alertContext, {
        playbookId: id,
        actor_id: req.user.id,
        context: req.body.context || {}
      });

      return res.status(200).json({
        success: true,
        data: executions[0] || null
      });
    } catch (err) {
      console.error('[soarController.executePlaybookManually] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  // =========================================================================
  // APPROVAL WORKFLOWS (ADMIN ONLY)
  // =========================================================================

  /**
   * GET /api/v1/soar/approvals
   */
  async listApprovals(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { status, limit = 50, offset = 0 } = req.query;
      const result = await SoarApproval.findMany({
        organization_id: orgId,
        status,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        success: true,
        data: result.data,
        total: result.total
      });
    } catch (err) {
      console.error('[soarController.listApprovals] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/soar/approvals/:id/approve
   */
  async approveExecution(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      // Check admin role
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Only administrators may approve playbook executions'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid approval ID format (must be UUID)'
        });
      }

      const result = await approvalService.approveExecution({
        approval_id: id,
        organization_id: orgId,
        approved_by: req.user.id,
        reason: req.body?.reason || 'Approved by security administrator'
      });

      return res.status(200).json({
        success: true,
        message: 'Execution approved and resumed successfully',
        data: result
      });
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(400).json({
        error: 'INVALID_OPERATION',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/soar/approvals/:id/reject
   */
  async rejectExecution(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      // Check admin role
      if (req.user?.role !== 'admin') {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Only administrators may reject playbook executions'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid approval ID format (must be UUID)'
        });
      }

      const result = await approvalService.rejectExecution({
        approval_id: id,
        organization_id: orgId,
        rejected_by: req.user.id,
        reason: req.body?.reason || 'Rejected by security administrator'
      });

      return res.status(200).json({
        success: true,
        message: 'Execution rejected and cancelled',
        data: result
      });
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: err.message
        });
      }
      return res.status(400).json({
        error: 'INVALID_OPERATION',
        message: err.message
      });
    }
  }
};

module.exports = soarController;
