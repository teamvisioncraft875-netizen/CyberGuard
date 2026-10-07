const db = require('../../config/db');
const auditService = require('../auditService');
const SoarCase = require('../../models/SoarCase');
const SoarPlaybook = require('../../models/SoarPlaybook');
const SoarExecution = require('../../models/SoarExecution');
const SoarApproval = require('../../models/SoarApproval');
const CopilotSession = require('../../models/CopilotSession');
const CopilotSessionAction = require('../../models/CopilotSessionAction');
const playbookEngine = require('../soar/playbookEngine');
const approvalService = require('../soar/approvalService');
const actionExecutor = require('../soar/actionExecutor');

/**
 * Copilot Action Service — Bridge between Copilot investigations and SOAR execution.
 * Handles SOAR Case creation, playbook launches, approval gating, and conversation action memory.
 */
class CopilotActionService {
  constructor() {
    this.HIGH_RISK_ACTIONS = [
      'isolate_endpoint',
      'isolate_host',
      'disable_account',
      'disable_user',
      'block_ip',
      'firewall_block',
      'network_quarantine'
    ];
  }

  /**
   * Determines if an action type is sensitive and requires supervisor approval.
   */
  isHighRiskAction(actionType) {
    if (!actionType) return false;
    const clean = String(actionType).toLowerCase().trim();
    return this.HIGH_RISK_ACTIONS.includes(clean);
  }

  /**
   * Creates a formal SOAR Case from Copilot investigation context.
   */
  async createSoarCase({
    organization_id,
    session_id = null,
    title,
    description = '',
    severity = 'medium',
    priority = 'medium',
    alert_id = null,
    incident_ids = [],
    ioc_ids = [],
    threat_intel_findings = {},
    tags = [],
    created_by = null
  }) {
    if (!organization_id) throw new Error('CopilotActionService Error: organization_id is required');
    if (!title) throw new Error('CopilotActionService Error: title is required');

    const soarCase = await SoarCase.create({
      organization_id,
      title,
      description,
      severity,
      priority,
      alert_id: (alert_id && /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(alert_id)) ? alert_id : null,
      incident_ids,
      ioc_ids,
      threat_intel_findings,
      tags,
      created_by
    });

    if (session_id) {
      await CopilotSessionAction.create({
        session_id,
        organization_id,
        action_type: 'create_soar_case',
        action_payload: { case_id: soarCase.id, title, severity },
        status: 'executed',
        case_id: soarCase.id,
        reason: 'Created SOAR investigation case via Copilot',
        requires_approval: false,
        created_by
      }).catch(err => console.error('[CopilotActionService] Memory log error:', err.message));
    }

    await auditService.log({
      organization_id,
      actor_id: created_by,
      action: 'COPILOT_ACTION_EXECUTED',
      resource_type: 'soar_case',
      resource_id: soarCase.id,
      details: { action: 'create_soar_case', case_id: soarCase.id, title }
    }).catch(err => console.error('[CopilotActionService] Audit log error:', err.message));

    return soarCase;
  }

  /**
   * Launches a SOAR Playbook from Copilot investigation.
   */
  async launchPlaybook({
    organization_id,
    session_id = null,
    playbook_id,
    alert_id = null,
    context = {},
    actor_id = null
  }) {
    if (!organization_id) throw new Error('CopilotActionService Error: organization_id is required');
    if (!playbook_id) throw new Error('CopilotActionService Error: playbook_id is required');

    // Retrieve or construct trigger context
    const executions = await playbookEngine.triggerPlaybook(
      {
        id: alert_id || null,
        organization_id,
        title: `Copilot Automation: Playbook ${playbook_id}`,
        severity: context.severity || 'high',
        ...context
      },
      {
        playbookId: playbook_id,
        actor_id,
        context
      }
    );

    const firstExecution = executions[0] || null;

    if (session_id) {
      await CopilotSessionAction.create({
        session_id,
        organization_id,
        action_type: 'launch_playbook',
        action_payload: { playbook_id, alert_id, context },
        status: 'executed',
        execution_id: firstExecution?.id || null,
        reason: `Launched playbook ${playbook_id}`,
        requires_approval: false,
        created_by: actor_id
      }).catch(err => console.error('[CopilotActionService] Memory log error:', err.message));
    }

    await auditService.log({
      organization_id,
      actor_id,
      action: 'COPILOT_ACTION_EXECUTED',
      resource_type: 'soar_playbook',
      resource_id: playbook_id,
      details: { action: 'launch_playbook', execution_count: executions.length }
    }).catch(err => console.error('[CopilotActionService] Audit log error:', err.message));

    return executions;
  }

  /**
   * Submits high-risk action for human-in-the-loop approval.
   */
  async createApprovalRequest({
    organization_id,
    session_id = null,
    action_type,
    payload = {},
    reason = '',
    requested_by = null,
    level = 'L1'
  }) {
    if (!organization_id) throw new Error('CopilotActionService Error: organization_id is required');
    if (!action_type) throw new Error('CopilotActionService Error: action_type is required');

    let executionId = payload.execution_id || null;

    if (!executionId) {
      // Find or provision placeholder execution in SOAR to bind approval record
      const pbRes = await db.query(
        `SELECT id FROM public.soar_playbooks WHERE organization_id = $1 LIMIT 1;`,
        [organization_id]
      );
      let playbookId = pbRes.rows[0]?.id;
      if (!playbookId) {
        const defaultPb = await SoarPlaybook.create({
          organization_id,
          name: 'Copilot Gated Response Playbook',
          description: 'Auto-provisioned container for Copilot gated actions',
          trigger_type: 'manual',
          created_by: requested_by
        });
        playbookId = defaultPb.id;
      }

      const exec = await SoarExecution.create({
        organization_id,
        playbook_id: playbookId,
        trigger_alert_id: payload.alert_id || null,
        status: 'pending'
      });
      executionId = exec.id;
    }

    const approval = await approvalService.requestApproval({
      execution_id: executionId,
      requested_by,
      reason: reason || `Action "${action_type}" requires security approval prior to execution`,
      organization_id,
      level
    });

    if (session_id) {
      await CopilotSessionAction.create({
        session_id,
        organization_id,
        action_type,
        action_payload: payload,
        status: 'pending_approval',
        execution_id: executionId,
        approval_id: approval.id,
        reason: reason || 'Awaiting supervisor authorization',
        requires_approval: true,
        created_by: requested_by
      }).catch(err => console.error('[CopilotActionService] Memory log error:', err.message));
    }

    return approval;
  }

  /**
   * Escalates an existing SOAR Case.
   */
  async escalateCase({
    organization_id,
    session_id = null,
    case_id,
    reason = 'Escalated by Copilot analysis',
    new_priority = 'critical',
    new_severity = 'critical',
    actor_id = null
  }) {
    if (!organization_id || !case_id) {
      throw new Error('CopilotActionService Error: organization_id and case_id are required');
    }

    const updated = await SoarCase.update(case_id, organization_id, {
      priority: new_priority,
      severity: new_severity
    });

    if (!updated) {
      const err = new Error(`Case "${case_id}" not found in organization`);
      err.statusCode = 404;
      throw err;
    }

    if (session_id) {
      await CopilotSessionAction.create({
        session_id,
        organization_id,
        action_type: 'escalate_case',
        action_payload: { case_id, new_priority, new_severity },
        status: 'executed',
        case_id,
        reason,
        requires_approval: false,
        created_by: actor_id
      }).catch(err => console.error('[CopilotActionService] Memory log error:', err.message));
    }

    await auditService.log({
      organization_id,
      actor_id,
      action: 'COPILOT_ACTION_EXECUTED',
      resource_type: 'soar_case',
      resource_id: case_id,
      details: { action: 'escalate_case', new_priority, new_severity }
    }).catch(err => console.error('[CopilotActionService] Audit log error:', err.message));

    return updated;
  }

  /**
   * Executes an action with strict approval gating and conversation action memory.
   */
  async executeAction({
    organization_id,
    session_id = null,
    action_type,
    payload = {},
    reason = '',
    user
  }) {
    if (!organization_id) throw new Error('CopilotActionService Error: organization_id is required');
    if (!action_type) throw new Error('CopilotActionService Error: action_type is required');
    if (!user) throw new Error('CopilotActionService Error: user is required');

    // Tenant check on session_id if provided
    if (session_id) {
      const sess = await CopilotSession.findById(session_id, organization_id);
      if (!sess) {
        const err = new Error(`Session "${session_id}" not found in organization`);
        err.statusCode = 404;
        throw err;
      }
    }

    const cleanAction = action_type.toLowerCase().trim();
    const isHighRisk = this.isHighRiskAction(cleanAction);

    // 1. Enforce Approval Gating for High-Risk Actions
    if (isHighRisk) {
      let isApproved = false;

      // Check if an existing approval was passed and is in 'approved' status
      if (payload.approval_id) {
        const existingApproval = await SoarApproval.findById(payload.approval_id, organization_id);
        if (existingApproval && existingApproval.status === 'approved') {
          isApproved = true;
        } else {
          const err = new Error(`Action "${action_type}" cannot execute: Approval is not in approved state`);
          err.statusCode = 403;
          throw err;
        }
      }

      // If not pre-approved, automatically route to approval gating
      if (!isApproved) {
        // Analysts CANNOT bypass approval
        const approval = await this.createApprovalRequest({
          organization_id,
          session_id,
          action_type: cleanAction,
          payload,
          reason: reason || `Approval required for high-risk action ${cleanAction}`,
          requested_by: user.id,
          level: 'L1'
        });

        return {
          success: true,
          status: 'pending_approval',
          requires_approval: true,
          action_type: cleanAction,
          approval_id: approval.id,
          message: `High-risk action "${cleanAction}" requires supervisor approval before execution.`
        };
      }
    }

    // 2. Execute Action via SOAR Layer
    let executionResult;
    if (cleanAction === 'create_soar_case') {
      executionResult = await this.createSoarCase({
        organization_id,
        session_id,
        title: payload.title || `Incident Case: ${payload.alert_id || 'Security Event'}`,
        description: payload.description || reason,
        severity: payload.severity || 'medium',
        priority: payload.priority || 'medium',
        alert_id: payload.alert_id || null,
        incident_ids: payload.incident_ids || [],
        ioc_ids: payload.ioc_ids || [],
        created_by: user.id
      });
    } else if (cleanAction === 'launch_playbook' || cleanAction === 'execute_playbook') {
      executionResult = await this.launchPlaybook({
        organization_id,
        session_id,
        playbook_id: payload.playbook_id,
        alert_id: payload.alert_id || null,
        context: payload,
        actor_id: user.id
      });
    } else if (cleanAction === 'escalate_case') {
      executionResult = await this.escalateCase({
        organization_id,
        session_id,
        case_id: payload.case_id,
        reason,
        new_priority: payload.priority || 'critical',
        new_severity: payload.severity || 'critical',
        actor_id: user.id
      });
    } else {
      // Dispatch to ActionExecutor
      executionResult = await actionExecutor.executeAction(
        cleanAction,
        payload,
        { organization_id, actor_id: user.id, ...payload }
      );
    }

    // 3. Record Executed Action in Session Memory
    let memoryRecord = null;
    if (session_id) {
      memoryRecord = await CopilotSessionAction.create({
        session_id,
        organization_id,
        action_type: cleanAction,
        action_payload: payload,
        status: 'executed',
        execution_id: executionResult?.id || payload.execution_id || null,
        approval_id: payload.approval_id || null,
        case_id: executionResult?.id || payload.case_id || null,
        reason,
        requires_approval: isHighRisk,
        created_by: user.id
      }).catch(err => console.error('[CopilotActionService] Memory log error:', err.message));
    }

    // 4. Audit Logging
    await auditService.log({
      organization_id,
      actor_id: user.id,
      action: 'COPILOT_ACTION_EXECUTED',
      resource_type: 'copilot_action',
      resource_id: memoryRecord?.id || cleanAction,
      details: {
        action_type: cleanAction,
        session_id,
        approval_id: payload.approval_id || null
      }
    }).catch(err => console.error('[CopilotActionService] Audit log error:', err.message));

    return {
      success: true,
      status: 'executed',
      requires_approval: false,
      action_type: cleanAction,
      result: executionResult
    };
  }

  /**
   * Retrieves conversation action memory for a session.
   */
  async getSessionActions({ session_id, organization_id }) {
    if (!session_id || !organization_id) {
      throw new Error('CopilotActionService Error: session_id and organization_id are required');
    }

    const actions = await CopilotSessionAction.findBySession(session_id, organization_id);

    return {
      session_id,
      total: actions.length,
      actions,
      summary: {
        total: actions.length,
        recommended: actions.filter(a => a.status === 'recommended').length,
        pending_approval: actions.filter(a => a.status === 'pending_approval').length,
        approved: actions.filter(a => a.status === 'approved').length,
        rejected: actions.filter(a => a.status === 'rejected').length,
        executed: actions.filter(a => a.status === 'executed').length
      }
    };
  }
}

const copilotActionService = new CopilotActionService();
module.exports = copilotActionService;
