const db = require('../../config/db');
const SoarPlaybook = require('../../models/SoarPlaybook');
const SoarExecution = require('../../models/SoarExecution');
const SoarApproval = require('../../models/SoarApproval');
const SoarCaseEvidence = require('../../models/SoarCaseEvidence');
const actionExecutor = require('./actionExecutor');
const auditService = require('../auditService');

/**
 * Recursively resolves {{variable}} placeholders from context in config objects.
 */
function resolveTemplateVariables(obj, context) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) {
    return obj.map(item => resolveTemplateVariables(item, context));
  }
  const resolved = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      resolved[k] = v.replace(/\{\{([a-zA-Z0-9_]+)\}\}/g, (match, prop) => {
        return context[prop] !== undefined ? context[prop] : match;
      });
    } else if (typeof v === 'object' && v !== null) {
      resolved[k] = resolveTemplateVariables(v, context);
    } else {
      resolved[k] = v;
    }
  }
  return resolved;
}

/**
 * Playbook Engine — Orchestrates security automation workflows, sequential step execution,
 * approval gating, execution retries with backoff, recovery, and evidence collection.
 */
class PlaybookEngine {
  /**
   * Triggers playbooks based on an alert ID or alert object.
   */
  async triggerPlaybook(alertOrId, options = {}, client = null) {
    const dbClient = client || db;
    let alert = null;

    if (typeof alertOrId === 'string') {
      const res = await dbClient.query('SELECT * FROM public.siem_alerts WHERE id = $1;', [alertOrId]);
      alert = res.rows[0] || null;
      if (!alert) {
        // Fallback: check incidents table
        const incRes = await dbClient.query('SELECT * FROM public.incidents WHERE id = $1;', [alertOrId]);
        alert = incRes.rows[0] || null;
      }
      if (!alert) {
        throw new Error(`PlaybookEngine Error: Alert or incident "${alertOrId}" not found`);
      }
    } else if (alertOrId && typeof alertOrId === 'object') {
      alert = alertOrId;
    } else {
      throw new Error('PlaybookEngine Error: Valid alertId or alert object is required');
    }

    const orgId = alert.organization_id;
    if (!orgId) {
      throw new Error('PlaybookEngine Error: Alert missing organization_id');
    }

    // If a specific playbookId is requested in options, trigger only that one
    let targetPlaybooks = [];
    if (options.playbookId) {
      const pb = await SoarPlaybook.findById(options.playbookId, orgId, dbClient);
      if (pb && pb.enabled) {
        targetPlaybooks.push(pb);
      }
    } else {
      // Find matching playbooks based on alert trigger conditions
      targetPlaybooks = await SoarPlaybook.findMatchingPlaybooks({
        organization_id: orgId,
        trigger_type: options.trigger_type || 'alert',
        alert
      }, dbClient);
    }

    const executions = [];
    for (const playbook of targetPlaybooks) {
      try {
        // Prevent duplicate execution records for the same alert and playbook
        if (alert.id && !options.allowDuplicate) {
          const existing = await dbClient.query(
            'SELECT id, status FROM public.soar_executions WHERE playbook_id = $1 AND trigger_alert_id = $2;',
            [playbook.id, alert.id]
          );
          if (existing.rows.length > 0) {
            continue;
          }
        }

        // 1. Create execution record
        const execution = await SoarExecution.create({
          organization_id: orgId,
          playbook_id: playbook.id,
          trigger_alert_id: alert.id || null,
          status: 'pending',
          retry_count: 0
        }, dbClient);

        // 2. Pre-create execution step records
        const steps = playbook.steps || (await SoarPlaybook.getSteps(playbook.id, dbClient));
        for (const step of steps) {
          await SoarExecution.createStepRecord({
            execution_id: execution.id,
            playbook_step_id: step.id,
            status: 'pending',
            result_payload: {},
            retry_count: 0
          }, dbClient);
        }

        // 3. Initiate playbook execution
        const runResult = await this.executePlaybook(execution.id, {
          alertContext: alert,
          caseId: options.caseId || null,
          ...options
        }, dbClient);

        executions.push(runResult);
      } catch (err) {
        console.error(`[PlaybookEngine] Error executing playbook ${playbook.id}:`, err.message);
      }
    }

    return executions;
  }

  /**
   * Sequentially executes the steps of a playbook execution with retries, approval gating,
   * and evidence collection.
   */
  async executePlaybook(executionId, options = {}, client = null) {
    const dbClient = client || db;

    // 1. Fetch execution
    const execRes = await dbClient.query('SELECT * FROM public.soar_executions WHERE id = $1;', [executionId]);
    const execution = execRes.rows[0];
    if (!execution) {
      throw new Error(`PlaybookEngine Error: Execution "${executionId}" not found`);
    }

    const orgId = execution.organization_id;

    // 2. Fetch playbook and steps
    const playbook = await SoarPlaybook.findById(execution.playbook_id, orgId, dbClient);
    if (!playbook) {
      throw new Error(`PlaybookEngine Error: Playbook "${execution.playbook_id}" not found`);
    }

    // 3. Transition execution to running if pending or resumed
    if (['pending', 'waiting_approval', 'retrying'].includes(execution.status)) {
      await SoarExecution.updateStatus(executionId, orgId, 'running', {
        started_at: execution.started_at || new Date()
      }, dbClient);

      await auditService.log({
        organization_id: orgId,
        actor_id: options.actor_id || null,
        action: 'SOAR_EXECUTION_STARTED',
        resource_type: 'soar_execution',
        resource_id: executionId,
        details: { playbook_id: playbook.id, playbook_name: playbook.name }
      }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));
    }

    // 4. Fetch execution steps
    const execSteps = await SoarExecution.getExecutionSteps(executionId, dbClient);

    const targetCaseId = options.caseId || execution.case_id || options.context?.case_id || null;

    // Build context
    const runtimeContext = {
      organization_id: orgId,
      execution_id: executionId,
      playbook_id: playbook.id,
      playbook_name: playbook.name,
      alert_id: execution.trigger_alert_id,
      case_id: targetCaseId,
      ...(options.alertContext || {}),
      ...(options.context || {})
    };

    // 5. Sequential Step Execution
    for (const step of execSteps) {
      // Skip completed steps
      if (step.status === 'completed') {
        continue;
      }

      // Check if step requires approval
      if (step.requires_approval) {
        const latestApproval = await SoarApproval.findByExecutionId(executionId, dbClient);

        if (!latestApproval || latestApproval.status === 'pending') {
          // If no approval record yet, request one
          if (!latestApproval) {
            const approvalService = require('./approvalService');
            await approvalService.requestApproval({
              execution_id: executionId,
              requested_by: options.actor_id || null,
              reason: `Approval required for step "${step.action_type}" in playbook "${playbook.name}"`,
              organization_id: orgId,
              level: step.action_config?.approval_level || 'L1',
              ttl_minutes: step.action_config?.approval_ttl_minutes || null
            }, dbClient);
          } else {
            // Already has pending approval, ensure execution status is waiting_approval
            await SoarExecution.updateStatus(executionId, orgId, 'waiting_approval', {}, dbClient);
          }

          const currentExec = await SoarExecution.findById(executionId, orgId, dbClient);
          return currentExec;
        }

        if (latestApproval.status === 'rejected') {
          // Playbook rejected
          await SoarExecution.updateStatus(executionId, orgId, 'cancelled', {
            completed_at: new Date()
          }, dbClient);
          await SoarExecution.updateStepRecord(step.id, {
            status: 'skipped',
            result_payload: { reason: 'Approval rejected', rejection_comment: latestApproval.rejection_comment }
          }, dbClient);

          return await SoarExecution.findById(executionId, orgId, dbClient);
        }

        // If latestApproval.status === 'approved', proceed to execute this step!
      }

      // Execute step action with Retry & Exponential Backoff Policy
      const retryPolicy = step.retry_policy || { max_retries: 0, backoff_ms: 50, backoff_multiplier: 2 };
      const maxRetries = typeof retryPolicy.max_retries === 'number' ? retryPolicy.max_retries : 0;
      let attempt = 0;
      let actionResult = null;
      let stepSucceeded = false;

      while (attempt <= maxRetries) {
        if (attempt > 0) {
          // Transition to retrying status
          const baseBackoff = retryPolicy.backoff_ms || 50;
          const multiplier = retryPolicy.backoff_multiplier || 2;
          const backoffDelay = Math.min(baseBackoff * Math.pow(multiplier, attempt - 1), 300);

          await SoarExecution.recordRetry(executionId, orgId, attempt, {
            step_id: step.id,
            attempt,
            backoff_ms: backoffDelay,
            last_error: actionResult?.error
          }, dbClient);

          await auditService.log({
            organization_id: orgId,
            actor_id: options.actor_id || null,
            action: 'SOAR_EXECUTION_RETRIED',
            resource_type: 'soar_execution',
            resource_id: executionId,
            details: { step_id: step.id, action_type: step.action_type, attempt, max_retries: maxRetries }
          }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));

          if (backoffDelay > 0 && !options.skipBackoffDelay) {
            await new Promise(r => setTimeout(r, backoffDelay));
          }
        }

        await SoarExecution.updateStepRecord(step.id, {
          status: 'running',
          result_payload: {},
          retry_count: attempt
        }, dbClient);

        const resolvedConfig = resolveTemplateVariables(step.action_config || {}, runtimeContext);

        actionResult = await actionExecutor.executeAction(
          step.action_type,
          resolvedConfig,
          runtimeContext,
          dbClient
        );

        if (actionResult.success) {
          stepSucceeded = true;
          break;
        }

        attempt++;
      }

      if (stepSucceeded) {
        await SoarExecution.updateStepRecord(step.id, {
          status: 'completed',
          result_payload: actionResult,
          retry_count: attempt,
          executed_at: new Date()
        }, dbClient);

        // Track external IDs, connector responses, and execution history in runtimeContext
        runtimeContext.last_step_result = actionResult;
        if (actionResult.external_ticket_id) {
          runtimeContext.external_ticket_id = actionResult.external_ticket_id;
        }
        if (actionResult.external_url) {
          runtimeContext.external_url = actionResult.external_url;
        }
        if (actionResult.external_id) {
          runtimeContext.external_id = actionResult.external_id;
        }
        if (actionResult.message_id) {
          runtimeContext.message_id = actionResult.message_id;
        }
        runtimeContext.execution_history = runtimeContext.execution_history || [];
        runtimeContext.execution_history.push({
          step_order: step.step_order,
          action_type: step.action_type,
          result: actionResult,
          executed_at: new Date().toISOString()
        });

        // Response Evidence Collection: If linked to a case, attach step action evidence
        if (targetCaseId) {
          try {
            await SoarCaseEvidence.create({
              case_id: targetCaseId,
              organization_id: orgId,
              evidence_type: 'remediation_output',
              data: {
                step_order: step.step_order,
                action_type: step.action_type,
                result: actionResult
              },
              execution_id: executionId,
              created_by: options.actor_id || null
            }, dbClient);
          } catch (evErr) {
            console.warn('[PlaybookEngine] Failed to attach step evidence:', evErr.message);
          }
        }
      } else {
        // Step failed after retries exhausted
        await SoarExecution.updateStepRecord(step.id, {
          status: 'failed',
          result_payload: actionResult,
          retry_count: maxRetries,
          executed_at: new Date()
        }, dbClient);

        await SoarExecution.updateStatus(executionId, orgId, 'failed', {
          completed_at: new Date()
        }, dbClient);

        // Record execution failure log as evidence if case linked
        if (targetCaseId) {
          try {
            await SoarCaseEvidence.create({
              case_id: targetCaseId,
              organization_id: orgId,
              evidence_type: 'execution_log',
              data: {
                status: 'failed',
                failed_step: step.action_type,
                error: actionResult?.error
              },
              execution_id: executionId,
              created_by: options.actor_id || null
            }, dbClient);
          } catch (evErr) {
            console.warn('[PlaybookEngine] Failed to attach failure evidence:', evErr.message);
          }
        }

        await auditService.log({
          organization_id: orgId,
          actor_id: options.actor_id || null,
          action: 'SOAR_EXECUTION_FAILED',
          resource_type: 'soar_execution',
          resource_id: executionId,
          details: { failed_step: step.action_type, error: actionResult?.error, attempts: attempt }
        }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));

        return await SoarExecution.findById(executionId, orgId, dbClient);
      }
    }

    // 6. All steps completed successfully
    const completedExec = await SoarExecution.updateStatus(executionId, orgId, 'completed', {
      completed_at: new Date()
    }, dbClient);

    // Record final execution log as evidence if case linked
    if (targetCaseId) {
      try {
        await SoarCaseEvidence.create({
          case_id: targetCaseId,
          organization_id: orgId,
          evidence_type: 'execution_log',
          data: {
            status: 'completed',
            playbook_name: playbook.name,
            total_steps: execSteps.length
          },
          execution_id: executionId,
          created_by: options.actor_id || null
        }, dbClient);
      } catch (evErr) {
        console.warn('[PlaybookEngine] Failed to attach completion evidence:', evErr.message);
      }
    }

    await auditService.log({
      organization_id: orgId,
      actor_id: options.actor_id || null,
      action: 'SOAR_EXECUTION_COMPLETED',
      resource_type: 'soar_execution',
      resource_id: executionId,
      details: { playbook_id: playbook.id, total_steps: execSteps.length }
    }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));

    return await SoarExecution.findById(executionId, orgId, dbClient);
  }

  /**
   * Resumes execution after approval is granted.
   */
  async resumeExecution(executionId, client = null) {
    return this.executePlaybook(executionId, { isResumed: true }, client);
  }

  /**
   * Automatically evaluates and triggers enabled playbooks when an alert is created.
   */
  async triggerMatchingPlaybooks(alert, client = null) {
    if (!alert || !alert.organization_id) return [];
    try {
      return await this.triggerPlaybook(alert, { trigger_type: 'alert' }, client);
    } catch (err) {
      console.error('[PlaybookEngine] triggerMatchingPlaybooks error:', err.message);
      return [];
    }
  }

  /**
   * Recovers stale executions left in 'running' or 'retrying' states (e.g. after crash or restart).
   */
  async recoverStaleExecutions({ organization_id = null } = {}, client = null) {
    const dbClient = client || db;
    const staleExecutions = await SoarExecution.findStaleRunningExecutions(organization_id, dbClient);
    const recovered = [];

    for (const exec of staleExecutions) {
      try {
        // Inspect steps
        const steps = await SoarExecution.getExecutionSteps(exec.id, dbClient);
        const hasPendingSteps = steps.some(s => ['pending', 'running'].includes(s.status));

        if (hasPendingSteps) {
          // Resume execution
          const resumed = await this.executePlaybook(exec.id, { isRecovered: true }, dbClient);
          recovered.push(resumed);

          await auditService.log({
            organization_id: exec.organization_id,
            actor_id: null,
            action: 'SOAR_EXECUTION_RECOVERED',
            resource_type: 'soar_execution',
            resource_id: exec.id,
            details: { previous_status: exec.status, new_status: resumed.status }
          }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));
        } else {
          // All steps finished, mark completed
          const updated = await SoarExecution.updateStatus(exec.id, exec.organization_id, 'completed', {
            completed_at: new Date()
          }, dbClient);
          recovered.push(updated);
        }
      } catch (err) {
        console.error(`[PlaybookEngine] Failed to recover execution ${exec.id}:`, err.message);
      }
    }

    return recovered;
  }
}

const playbookEngine = new PlaybookEngine();
module.exports = playbookEngine;
