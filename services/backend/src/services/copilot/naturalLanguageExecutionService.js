const db = require('../../config/db');
const auditService = require('../auditService');
const intentDetectionService = require('./intentDetectionService');
const entityExtractionService = require('./entityExtractionService');
const commandPlannerService = require('./commandPlannerService');
const copilotActionService = require('./copilotActionService');
const approvalService = require('../soar/approvalService');
const SoarApproval = require('../../models/SoarApproval');
const CopilotSession = require('../../models/CopilotSession');
const CopilotMessage = require('../../models/CopilotMessage');
const CopilotSessionAction = require('../../models/CopilotSessionAction');

/**
 * Natural Language Execution Service — Orchestrates natural-language SOC operations:
 * Intent Detection -> Entity Extraction -> Command Planning -> Approval Enforcement -> SOAR Execution.
 */
class NaturalLanguageExecutionService {
  /**
   * Translates a natural language command into an execution plan and safely executes it.
   *
   * @param {Object} params
   * @param {string} params.command - Natural language analyst instruction
   * @param {string} [params.session_id] - Optional investigation session UUID
   * @param {string} params.organization_id - Tenant UUID
   * @param {Object} params.user - Authenticated user object
   * @param {Object} [params.options] - Optional flags (e.g. approval_id)
   * @returns {Promise<Object>} Execution result with explainability payload
   */
  async executeCommand({
    command,
    session_id = null,
    organization_id,
    user,
    options = {}
  }) {
    if (!organization_id) {
      const err = new Error('NaturalLanguageExecutionService Error: organization_id is required');
      err.statusCode = 403;
      throw err;
    }
    if (!user) {
      const err = new Error('NaturalLanguageExecutionService Error: user is required');
      err.statusCode = 401;
      throw err;
    }

    // Role check: Only analyst, senior_analyst, admin
    const allowedRoles = ['analyst', 'senior_analyst', 'admin'];
    if (!allowedRoles.includes((user.role || '').toLowerCase())) {
      const err = new Error('Access denied: Unauthorized role for SOC command execution');
      err.statusCode = 403;
      throw err;
    }

    // Tenant Isolation check on session if provided
    let session = null;
    if (session_id) {
      session = await CopilotSession.findById(session_id, organization_id);
      if (!session) {
        const err = new Error(`Investigation session "${session_id}" not found in organization`);
        err.statusCode = 404;
        throw err;
      }
    }

    const cleanCommand = String(command || '').trim();
    if (!cleanCommand) {
      const err = new Error('Command text is required');
      err.statusCode = 400;
      throw err;
    }

    // 1. Intent Detection
    const { intent, intents, confidence } = await intentDetectionService.detectIntent(cleanCommand, {
      organization_id,
      actor_id: user.id
    });

    // 2. Entity Extraction
    const entities = await entityExtractionService.extractEntities(cleanCommand, {
      organization_id,
      actor_id: user.id
    });

    // 3. Command Planning
    const { plan, summary } = await commandPlannerService.createPlan({
      intent,
      intents,
      entities,
      raw_command: cleanCommand,
      organization_id,
      actor_id: user.id,
      context: {
        session_id,
        entity_id: session?.entity_id || null
      }
    });

    const executedSteps = [];
    const explainability = [];
    let stoppedForApproval = false;
    let pendingApprovalInfo = null;

    // 4. Sequential Execution of Planned Steps
    for (const step of plan) {
      // 5. Approval Confirmation Layer for High-Risk Actions
      if (step.requires_approval) {
        const approvalId = options.approval_id || step.payload.approval_id || null;
        let isPreApproved = false;

        if (approvalId) {
          const approvalRecord = await SoarApproval.findById(approvalId, organization_id).catch(() => null);
          if (approvalRecord && approvalRecord.status === 'approved') {
            isPreApproved = true;
          }
        }

        // Analysts cannot bypass approvals: if not pre-approved, pause chain and request approval
        if (!isPreApproved) {
          stoppedForApproval = true;

          const approval = await copilotActionService.createApprovalRequest({
            organization_id,
            session_id,
            action_type: step.action,
            payload: step.payload,
            reason: step.reason,
            requested_by: user.id,
            level: 'L1'
          });

          pendingApprovalInfo = {
            status: 'approval_required',
            requires_approval: true,
            action: step.action,
            approval_id: approval.id,
            message: `Action "${step.action}" requires SOC supervisor approval before execution.`
          };

          explainability.push({
            action: step.action,
            reason: step.reason,
            risk_level: step.risk_level,
            requires_approval: true,
            evidence: step.evidence,
            mitre_mapping: step.mitre_mapping,
            status: 'approval_required',
            approval_id: approval.id
          });

          // Stop multi-step chain execution at the unapproved high-risk barrier
          break;
        }
      }

      // Execute Approved or Low-Risk Action through Copilot Action Service Bridge
      try {
        const stepResult = await copilotActionService.executeAction({
          organization_id,
          session_id,
          action_type: step.action,
          payload: { ...step.payload, approval_id: options.approval_id || null },
          reason: step.reason,
          user
        });

        executedSteps.push({
          step: step.step,
          action: step.action,
          status: 'executed',
          result: stepResult.result
        });

        explainability.push({
          action: step.action,
          reason: step.reason,
          risk_level: step.risk_level,
          requires_approval: step.requires_approval,
          evidence: step.evidence,
          mitre_mapping: step.mitre_mapping,
          status: 'executed'
        });
      } catch (stepErr) {
        // Multi-step chain failure: stop on failure and capture error
        executedSteps.push({
          step: step.step,
          action: step.action,
          status: 'failed',
          error: stepErr.message
        });

        explainability.push({
          action: step.action,
          reason: step.reason,
          risk_level: step.risk_level,
          requires_approval: step.requires_approval,
          evidence: step.evidence,
          mitre_mapping: step.mitre_mapping,
          status: 'failed',
          error: stepErr.message
        });

        break;
      }
    }

    // 6. Record Audit Event
    await auditService.log({
      organization_id,
      actor_id: user.id,
      action: 'COPILOT_COMMAND_EXECUTED',
      resource_type: 'copilot_command',
      resource_id: session_id || 'nl_command',
      details: {
        command: cleanCommand.slice(0, 150),
        intent,
        steps_planned: plan.length,
        steps_executed: executedSteps.length,
        stopped_for_approval: stoppedForApproval
      }
    }).catch(err => console.error('[NaturalLanguageExecutionService] Audit log error:', err.message));

    // 7. Store summary in session memory if session_id provided
    if (session_id) {
      await CopilotMessage.create({
        session_id,
        role: 'user',
        content: cleanCommand,
        metadata: { intent, entities }
      }).catch(() => {});

      const responseText = stoppedForApproval
        ? `Command parsed. High-risk action "${pendingApprovalInfo.action}" requires supervisor approval (Approval ID: ${pendingApprovalInfo.approval_id}).`
        : `Command executed: ${executedSteps.map(s => s.action).join(', ')}.`;

      await CopilotMessage.create({
        session_id,
        role: 'assistant',
        content: responseText,
        metadata: { plan_summary: summary, executedSteps }
      }).catch(() => {});
    }

    if (stoppedForApproval) {
      return {
        success: true,
        status: 'approval_required',
        requires_approval: true,
        approval_id: pendingApprovalInfo.approval_id,
        command: cleanCommand,
        intent,
        intents,
        entities,
        plan,
        executed_steps: executedSteps,
        explainability,
        message: pendingApprovalInfo.message
      };
    }

    return {
      success: true,
      status: 'completed',
      requires_approval: false,
      command: cleanCommand,
      intent,
      intents,
      entities,
      plan,
      executed_steps: executedSteps,
      explainability
    };
  }

  /**
   * Explains a specific security action and its rationale.
   */
  explainAction({ action, reason = '', evidence = '', mitre_mapping = 'T1000', risk_level = 'medium' }) {
    const isHighRisk = ['isolate_endpoint', 'disable_account', 'block_ip', 'block_domain'].includes(action);
    return {
      action,
      reason: reason || `Automated or analyst-directed SOC containment action.`,
      risk_level: isHighRisk ? 'high' : risk_level,
      requires_approval: isHighRisk,
      evidence: evidence || `Detection signals and contextual telemetry.`,
      mitre_mapping: mitre_mapping || 'T1000'
    };
  }

  /**
   * Retrieves unified chronological investigation timeline for a session.
   */
  async getSessionTimeline({ session_id, organization_id }) {
    if (!session_id || !organization_id) {
      throw new Error('NaturalLanguageExecutionService Error: session_id and organization_id required');
    }

    // 1. Validate session ownership
    const session = await CopilotSession.findById(session_id, organization_id);
    if (!session) {
      const err = new Error(`Session "${session_id}" not found in organization`);
      err.statusCode = 404;
      throw err;
    }

    // 2. Retrieve messages
    const messages = await CopilotMessage.findRecent(session_id, 100);

    // 3. Retrieve recorded actions
    const actions = await CopilotSessionAction.findBySession(session_id, organization_id);

    // 4. Construct unified chronological timeline
    const timeline = [];

    for (const msg of messages) {
      timeline.push({
        type: 'message',
        id: msg.id,
        role: msg.role,
        content: msg.content,
        timestamp: msg.timestamp || msg.created_at,
        metadata: msg.metadata || {}
      });
    }

    for (const act of actions) {
      timeline.push({
        type: 'action',
        id: act.id,
        action: act.action_type,
        status: act.status,
        requires_approval: act.requires_approval,
        approval_id: act.approval_id,
        case_id: act.case_id,
        execution_id: act.execution_id,
        reason: act.reason,
        timestamp: act.created_at,
        explanation: act.explanation || {}
      });
    }

    // Sort ascending by timestamp
    timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    return {
      session_id,
      timeline,
      summary: {
        total_events: timeline.length,
        messages: messages.length,
        actions: actions.length,
        approvals: actions.filter(a => a.approval_id).length,
        cases: actions.filter(a => a.case_id).length,
        executed: actions.filter(a => a.status === 'executed').length
      }
    };
  }
}

const naturalLanguageExecutionService = new NaturalLanguageExecutionService();
module.exports = naturalLanguageExecutionService;
