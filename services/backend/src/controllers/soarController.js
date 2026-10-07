const SoarPlaybook = require('../models/SoarPlaybook');
const SoarExecution = require('../models/SoarExecution');
const SoarApproval = require('../models/SoarApproval');
const SoarCase = require('../models/SoarCase');
const SoarCaseEvidence = require('../models/SoarCaseEvidence');
const SoarConnector = require('../models/SoarConnector');
const connectorRegistry = require('../services/soar/connectors/ConnectorRegistry');
const approvalService = require('../services/soar/approvalService');
const playbookEngine = require('../services/soar/playbookEngine');
const playbookMetricsService = require('../services/soar/playbookMetricsService');
const iocResponseAutomationService = require('../services/soar/iocResponseAutomationService');
const threatEnrichmentService = require('../services/soar/threatEnrichmentService');
const recommendationEngine = require('../services/soar/recommendationEngine');
const soarAnalyticsService = require('../services/soar/soarAnalyticsService');
const knowledgeBaseService = require('../services/soar/knowledgeBaseService');
const soarDashboardService = require('../services/soar/soarDashboardService');
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
  },

  // =========================================================================
  // ENTERPRISE CONNECTORS (SPRINT B PHASE 3)
  // =========================================================================

  /**
   * POST /api/v1/soar/connectors
   */
  async createConnector(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { name, type, description, status, config, is_default } = req.body;
      if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Field "name" is required and must be a non-empty string'
        });
      }

      if (!type || typeof type !== 'string' || !['webhook', 'jira', 'slack', 'teams', 'custom'].includes(type.toLowerCase())) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Field "type" must be one of: webhook, jira, slack, teams, custom'
        });
      }

      const connector = await connectorRegistry.registerConnector({
        organization_id: orgId,
        name: name.trim(),
        type: type.toLowerCase(),
        description,
        status: status || 'active',
        config: config || {},
        is_default: Boolean(is_default),
        created_by: req.user.id
      });

      return res.status(201).json({
        success: true,
        data: {
          id: connector.id,
          name: connector.name,
          type: connector.type,
          description: connector.description,
          status: connector.status,
          config: SoarConnector.maskConfig(connector.config),
          is_default: connector.is_default,
          health_status: connector.health_status,
          created_at: connector.created_at
        }
      });
    } catch (err) {
      console.error('[soarController.createConnector] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/connectors
   */
  async listConnectors(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { type, status, limit, offset, search } = req.query;
      const connectors = await connectorRegistry.listConnectors(orgId, {
        type,
        status,
        search,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        success: true,
        data: connectors.map(c => ({
          id: c.id,
          name: c.name,
          type: c.type,
          description: c.description,
          status: c.status,
          config: SoarConnector.maskConfig(c.config),
          is_default: c.is_default,
          health_status: c.health_status,
          last_health_check: c.last_health_check
        })),
        total: connectors.length
      });
    } catch (err) {
      console.error('[soarController.listConnectors] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/connectors/:id
   */
  async getConnectorById(req, res) {
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
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      const connector = await connectorRegistry.getConnector(id, orgId);
      if (!connector) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      return res.status(200).json({
        success: true,
        data: {
          id: connector.id,
          name: connector.name,
          type: connector.type,
          description: connector.description,
          status: connector.status,
          config: SoarConnector.maskConfig(connector.config),
          is_default: connector.is_default,
          health_status: connector.health_status,
          last_health_check: connector.last_health_check
        }
      });
    } catch (err) {
      console.error('[soarController.getConnectorById] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/soar/connectors/:id
   */
  async updateConnector(req, res) {
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
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      const existing = await connectorRegistry.getConnector(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      const updated = await connectorRegistry.updateConnector(id, orgId, req.body, req.user.id);
      return res.status(200).json({
        success: true,
        data: {
          id: updated.id,
          name: updated.name,
          type: updated.type,
          description: updated.description,
          status: updated.status,
          config: SoarConnector.maskConfig(updated.config),
          is_default: updated.is_default,
          health_status: updated.health_status
        }
      });
    } catch (err) {
      console.error('[soarController.updateConnector] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/soar/connectors/:id/status
   */
  async updateConnectorStatus(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      const { status } = req.body;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      if (!status || !['active', 'disabled', 'error'].includes(status.toLowerCase())) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'Field "status" must be one of: active, disabled, error'
        });
      }

      const existing = await connectorRegistry.getConnector(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      let updated;
      if (status.toLowerCase() === 'active') {
        updated = await connectorRegistry.enableConnector(id, orgId, req.user.id);
      } else if (status.toLowerCase() === 'disabled') {
        updated = await connectorRegistry.disableConnector(id, orgId, req.user.id);
      } else {
        updated = await connectorRegistry.updateConnector(id, orgId, { status: status.toLowerCase() }, req.user.id);
      }

      return res.status(200).json({
        success: true,
        data: {
          id: updated.id,
          name: updated.name,
          status: updated.status
        }
      });
    } catch (err) {
      console.error('[soarController.updateConnectorStatus] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/connectors/:id/test
   */
  async testConnector(req, res) {
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
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      const existing = await connectorRegistry.getConnector(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      const testResult = await connectorRegistry.testConnector(id, orgId, req.user.id);
      return res.status(200).json({
        success: true,
        data: testResult
      });
    } catch (err) {
      console.error('[soarController.testConnector] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * DELETE /api/v1/soar/connectors/:id
   */
  async deleteConnector(req, res) {
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
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      const existing = await connectorRegistry.getConnector(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      await connectorRegistry.deleteConnector(id, orgId, req.user.id);
      return res.status(200).json({
        success: true,
        message: 'Connector deleted successfully'
      });
    } catch (err) {
      console.error('[soarController.deleteConnector] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/connectors/:id/logs
   */
  async getConnectorLogs(req, res) {
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
          message: 'Invalid connector ID format (must be UUID)'
        });
      }

      const existing = await connectorRegistry.getConnector(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Connector "${id}" not found or unauthorized`
        });
      }

      const logs = await SoarConnector.getLogs(id, orgId, req.query);
      return res.status(200).json({
        success: true,
        data: logs,
        total: logs.length
      });
    } catch (err) {
      console.error('[soarController.getConnectorLogs] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  // =========================================================================
  // PHASE 4: IOC AUTOMATION & THREAT INTEL OPTIMIZATION
  // =========================================================================

  /**
   * POST /api/v1/soar/ioc/automate
   */
  async automateIocResponse(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { ioc_type, ioc_value, case_id, alert_id, threat_actor, malware_family, confidence } = req.body;
      if (!ioc_type || !ioc_value) {
        return res.status(400).json({ error: 'INVALID_REQUEST', message: 'ioc_type and ioc_value are required' });
      }

      const result = await iocResponseAutomationService.automateResponse({
        organization_id: orgId,
        ioc_type,
        ioc_value,
        case_id,
        alert_id,
        threat_actor,
        malware_family,
        confidence
      });

      return res.status(200).json({ success: true, data: result });
    } catch (err) {
      console.error('[soarController.automateIocResponse] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/enrich/alert/:id
   */
  async enrichAlert(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const result = await threatEnrichmentService.enrichAlert(id, orgId);
      return res.status(200).json({ success: true, data: result });
    } catch (err) {
      console.error('[soarController.enrichAlert] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/enrich/case/:id
   */
  async enrichCase(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const result = await threatEnrichmentService.enrichCase(id, orgId);
      return res.status(200).json({ success: true, data: result });
    } catch (err) {
      console.error('[soarController.enrichCase] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/recommendations/generate
   */
  async generateRecommendations(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { alert_id, case_id, ioc_id, alert_severity, mitre_techniques, ioc_risk_score, context } = req.body;
      const recommendations = await recommendationEngine.generateRecommendations({
        organization_id: orgId,
        alert_id,
        case_id,
        ioc_id,
        alert_severity,
        mitre_techniques,
        ioc_risk_score,
        context
      });

      return res.status(201).json({ success: true, data: recommendations });
    } catch (err) {
      console.error('[soarController.generateRecommendations] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/recommendations
   */
  async listRecommendations(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const recommendations = await recommendationEngine.listRecommendations(orgId, req.query);
      return res.status(200).json({ success: true, data: recommendations });
    } catch (err) {
      console.error('[soarController.listRecommendations] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/recommendations/:id/apply
   */
  async applyRecommendation(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const result = await recommendationEngine.applyRecommendation(id, orgId, req.user?.id);
      return res.status(200).json({ success: true, data: result });
    } catch (err) {
      console.error('[soarController.applyRecommendation] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/recommendations/:id/dismiss
   */
  async dismissRecommendation(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const { reason } = req.body;
      const result = await recommendationEngine.dismissRecommendation(id, orgId, req.user?.id, reason);
      return res.status(200).json({ success: true, data: result });
    } catch (err) {
      console.error('[soarController.dismissRecommendation] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/knowledge-base
   */
  async createKnowledgeBaseArticle(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const article = await knowledgeBaseService.createArticle({
        ...req.body,
        organization_id: orgId,
        created_by: req.user?.id
      });
      return res.status(201).json({ success: true, data: article });
    } catch (err) {
      console.error('[soarController.createKnowledgeBaseArticle] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/knowledge-base
   */
  async listKnowledgeBaseArticles(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const articles = await knowledgeBaseService.listArticles(orgId, req.query);
      return res.status(200).json({ success: true, data: articles });
    } catch (err) {
      console.error('[soarController.listKnowledgeBaseArticles] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/knowledge-base/:id
   */
  async getKnowledgeBaseArticleById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const article = await knowledgeBaseService.getArticleById(id, orgId);
      if (!article) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Article "${id}" not found` });
      }
      return res.status(200).json({ success: true, data: article });
    } catch (err) {
      console.error('[soarController.getKnowledgeBaseArticleById] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/soar/knowledge-base/:id
   */
  async updateKnowledgeBaseArticle(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const updated = await knowledgeBaseService.updateArticle(id, orgId, req.body, req.user?.id);
      return res.status(200).json({ success: true, data: updated });
    } catch (err) {
      console.error('[soarController.updateKnowledgeBaseArticle] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * DELETE /api/v1/soar/knowledge-base/:id
   */
  async deleteKnowledgeBaseArticle(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      await knowledgeBaseService.deleteArticle(id, orgId, req.user?.id);
      return res.status(200).json({ success: true, message: 'Article deleted successfully' });
    } catch (err) {
      console.error('[soarController.deleteKnowledgeBaseArticle] Error:', err);
      if (err.message && err.message.includes('not found')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: err.message });
      }
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/knowledge-base/:id/link-case
   */
  async linkKnowledgeBaseCase(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const { case_id } = req.body;
      const updated = await knowledgeBaseService.linkCase(id, orgId, case_id);
      return res.status(200).json({ success: true, data: updated });
    } catch (err) {
      console.error('[soarController.linkKnowledgeBaseCase] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/soar/knowledge-base/:id/link-playbook
   */
  async linkKnowledgeBasePlaybook(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const { playbook_id } = req.body;
      const updated = await knowledgeBaseService.linkPlaybook(id, orgId, playbook_id);
      return res.status(200).json({ success: true, data: updated });
    } catch (err) {
      console.error('[soarController.linkKnowledgeBasePlaybook] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/analytics/effectiveness
   */
  async getEffectivenessAnalytics(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const metrics = await soarAnalyticsService.getOrganizationMetrics(orgId);
      return res.status(200).json({ success: true, data: metrics });
    } catch (err) {
      console.error('[soarController.getEffectivenessAnalytics] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/analytics/playbooks/:id
   */
  async getPlaybookEffectiveness(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const metrics = await soarAnalyticsService.getPlaybookEffectiveness(id, orgId);
      return res.status(200).json({ success: true, data: metrics });
    } catch (err) {
      console.error('[soarController.getPlaybookEffectiveness] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/analytics/actions
   */
  async getActionEffectiveness(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const metrics = await soarAnalyticsService.getActionEffectiveness(orgId);
      return res.status(200).json({ success: true, data: metrics });
    } catch (err) {
      console.error('[soarController.getActionEffectiveness] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/dashboard/executive
   */
  async getExecutiveDashboard(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const data = await soarDashboardService.getExecutiveView(orgId);
      return res.status(200).json({ success: true, data });
    } catch (err) {
      console.error('[soarController.getExecutiveDashboard] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/dashboard/analyst
   */
  async getAnalystDashboard(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const data = await soarDashboardService.getAnalystView(orgId);
      return res.status(200).json({ success: true, data });
    } catch (err) {
      console.error('[soarController.getAnalystDashboard] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/soar/dashboard/engineering
   */
  async getEngineeringDashboard(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const data = await soarDashboardService.getEngineeringView(orgId);
      return res.status(200).json({ success: true, data });
    } catch (err) {
      console.error('[soarController.getEngineeringDashboard] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  }
};

module.exports = soarController;
