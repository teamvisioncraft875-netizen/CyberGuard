const SoarPlaybook = require('../models/SoarPlaybook');
const SoarExecution = require('../models/SoarExecution');
const SoarApproval = require('../models/SoarApproval');
const SoarCase = require('../models/SoarCase');
const SoarCaseEvidence = require('../models/SoarCaseEvidence');
const approvalService = require('../services/soar/approvalService');
const playbookEngine = require('../services/soar/playbookEngine');
const playbookMetricsService = require('../services/soar/playbookMetricsService');
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
          message: `Playbook "${id}" not found`
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
          message: `Playbook "${id}" not found`
        });
      }

      await auditLog({
        organization_id: orgId,
        actor_id: req.user.id,
        action: AUDIT_ACTIONS.SOAR_PLAYBOOK_UPDATED,
        resource_type: 'soar_playbook',
        resource_id: id,
        details: { updated_fields: Object.keys(req.body) }
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
          message: `Playbook "${id}" not found`
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
        message: `Playbook "${id}" deleted successfully`
      });
    } catch (err) {
      console.error('[soarController.deletePlaybook] Error:', err);
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
      const { alert_id = null, context = {}, case_id = null } = req.body;

      const executions = await playbookEngine.triggerPlaybook(
        {
          id: alert_id,
          organization_id: orgId,
          title: `Manual Execution: Playbook ${id}`,
          severity: 'medium',
          ...context
        },
        {
          playbookId: id,
          actor_id: req.user.id,
          caseId: case_id,
          context
        }
      );

      return res.status(200).json({
        success: true,
        data: executions
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
  // EXECUTIONS
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

      const { playbook_id, status, limit = 50, offset = 0 } = req.query;

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
      const execution = await SoarExecution.findById(id, orgId);
      if (!execution) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Execution "${id}" not found`
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
   * POST /api/v1/soar/executions/recover
   */
  async recoverExecutions(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const recovered = await playbookEngine.recoverStaleExecutions({ organization_id: orgId });

      return res.status(200).json({
        success: true,
        message: `Recovered ${recovered.length} stale executions`,
        data: recovered
      });
    } catch (err) {
      console.error('[soarController.recoverExecutions] Error:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  // =========================================================================
  // APPROVALS & ESCALATIONS
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

      const { status, level, limit = 50, offset = 0 } = req.query;

      const result = await SoarApproval.findMany({
        organization_id: orgId,
        status,
        level,
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

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid approval ID format (must be UUID)'
        });
      }

      const userRole = req.user?.role || 'analyst';

      const result = await approvalService.approveExecution({
        approval_id: id,
        organization_id: orgId,
        approved_by: req.user.id,
        user_role: userRole,
        reason: req.body?.reason || 'Approved by security administrator'
      });

      return res.status(200).json({
        success: true,
        message: 'Execution approved and resumed successfully',
        data: result
      });
    } catch (err) {
      if (err.statusCode === 403) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: err.message
        });
      }
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
        reason: req.body?.reason || 'Rejected by security administrator',
        rejection_comment: req.body?.rejection_comment || req.body?.comment || req.body?.reason
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
  },

  /**
   * POST /api/v1/soar/approvals/:id/escalate
   */
  async escalateApproval(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { target_level = 'L2', reason, ttl_minutes } = req.body;

      const escalated = await approvalService.escalateApproval({
        approval_id: id,
        organization_id: orgId,
        escalated_by: req.user.id,
        target_level,
        reason,
        ttl_minutes
      });

      return res.status(200).json({
        success: true,
        message: `Approval escalated to ${target_level}`,
        data: escalated
      });
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(400).json({ error: 'INVALID_OPERATION', message: err.message });
    }
  },

  // =========================================================================
  // CASE MANAGEMENT
  // =========================================================================

  /**
   * POST /api/v1/soar/cases
   */
  async createCase(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        title,
        description,
        severity,
        status = 'open',
        priority,
        assigned_to,
        alert_id,
        incident_ids = [],
        ioc_ids = [],
        threat_intel_findings = {},
        tags = []
      } = req.body;

      if (!title || typeof title !== 'string' || !title.trim()) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Case title is required'
        });
      }

      const soarCase = await SoarCase.create({
        organization_id: orgId,
        title: title.trim(),
        description,
        severity,
        status,
        priority,
        assigned_to,
        created_by: req.user.id,
        alert_id,
        incident_ids,
        ioc_ids,
        threat_intel_findings,
        tags
      });

      return res.status(201).json({
        success: true,
        data: soarCase
      });
    } catch (err) {
      console.error('[soarController.createCase] Error:', err);
      return res.status(400).json({
        error: 'INVALID_REQUEST',
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/soar/cases/from-alert/:alert_id
   */
  async createCaseFromAlert(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { alert_id } = req.params;
      const soarCase = await SoarCase.createFromAlert(alert_id, orgId, {
        ...req.body,
        created_by: req.user.id
      });

      return res.status(201).json({
        success: true,
        data: soarCase
      });
    } catch (err) {
      console.error('[soarController.createCaseFromAlert] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/cases
   */
  async listCases(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { status, severity, priority, assigned_to, search, limit = 50, offset = 0 } = req.query;

      const result = await SoarCase.findMany({
        organization_id: orgId,
        status,
        severity,
        priority,
        assigned_to,
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
      console.error('[soarController.listCases] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/cases/:id
   */
  async getCaseById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const found = await SoarCase.findById(id, orgId);
      if (!found) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Case "${id}" not found` });
      }

      return res.status(200).json({
        success: true,
        data: found
      });
    } catch (err) {
      console.error('[soarController.getCaseById] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/soar/cases/:id
   */
  async updateCase(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const updated = await SoarCase.update(id, orgId, {
        ...req.body,
        actor_id: req.user.id
      });
      if (!updated) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Case "${id}" not found` });
      }

      return res.status(200).json({
        success: true,
        data: updated
      });
    } catch (err) {
      console.error('[soarController.updateCase] Error:', err);
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/soar/cases/:id/status
   */
  async updateCaseStatus(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { status, reason } = req.body;

      if (!status) {
        return res.status(400).json({ error: 'INVALID_REQUEST', message: 'status is required' });
      }

      const updated = await SoarCase.updateStatus(id, orgId, status, {
        actor_id: req.user.id,
        reason
      });
      if (!updated) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Case "${id}" not found` });
      }

      return res.status(200).json({
        success: true,
        data: updated
      });
    } catch (err) {
      console.error('[soarController.updateCaseStatus] Error:', err);
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/cases/:id/incidents
   */
  async attachIncidents(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { incident_ids } = req.body;

      const updated = await SoarCase.attachIncidents(id, orgId, incident_ids);
      return res.status(200).json({ success: true, data: updated });
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/cases/:id/iocs
   */
  async attachIOCs(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { ioc_ids } = req.body;

      const updated = await SoarCase.attachIOCs(id, orgId, ioc_ids);
      return res.status(200).json({ success: true, data: updated });
    } catch (err) {
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/cases/:id/evidence
   */
  async addCaseEvidence(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { evidence_type, data, execution_id } = req.body;

      const evidence = await SoarCaseEvidence.create({
        case_id: id,
        organization_id: orgId,
        evidence_type,
        data,
        execution_id,
        created_by: req.user.id
      });

      return res.status(201).json({
        success: true,
        data: evidence
      });
    } catch (err) {
      console.error('[soarController.addCaseEvidence] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/cases/:id/evidence
   */
  async listCaseEvidence(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const caseFound = await SoarCase.findById(id, orgId);
      if (!caseFound) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Case "${id}" not found` });
      }

      const { evidence_type, limit = 50, offset = 0 } = req.query;

      const result = await SoarCaseEvidence.findByCaseId(id, orgId, {
        evidence_type,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        success: true,
        data: result.data,
        total: result.total
      });
    } catch (err) {
      console.error('[soarController.listCaseEvidence] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * DELETE /api/v1/soar/cases/:id (Admin only)
   */
  async deleteCase(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const deleted = await SoarCase.delete(id, orgId);
      if (!deleted) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Case "${id}" not found` });
      }

      return res.status(200).json({
        success: true,
        message: `Case "${id}" deleted successfully`
      });
    } catch (err) {
      console.error('[soarController.deleteCase] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  // =========================================================================
  // ANALYTICS & METRICS
  // =========================================================================

  /**
   * GET /api/v1/soar/metrics
   */
  async getMetrics(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const metrics = await playbookMetricsService.getGlobalMetrics(orgId);
      return res.status(200).json({
        success: true,
        data: metrics
      });
    } catch (err) {
      console.error('[soarController.getMetrics] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/metrics/playbooks/:id
   */
  async getPlaybookMetrics(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const metrics = await playbookMetricsService.getPlaybookMetrics(id, orgId);
      return res.status(200).json({
        success: true,
        data: metrics
      });
    } catch (err) {
      console.error('[soarController.getPlaybookMetrics] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  }
};

module.exports = soarController;
