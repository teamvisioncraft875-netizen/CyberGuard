const db = require('../../config/db');
const SoarPlaybook = require('../../models/SoarPlaybook');
const SoarExecution = require('../../models/SoarExecution');
const SoarApproval = require('../../models/SoarApproval');
const actionExecutor = require('./actionExecutor');
const auditService = require('../auditService');

/**
 * Playbook Engine — Orchestrates security automation workflows, sequential step execution,
 * approval gating, and lifecycle state transitions.
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
          status: 'pending'
        }, dbClient);

        // 2. Pre-create execution step records
        const steps = playbook.steps || (await SoarPlaybook.getSteps(playbook.id, dbClient));
        for (const step of steps) {
          await SoarExecution.createStepRecord({
            execution_id: execution.id,
            playbook_step_id: step.id,
            status: 'pending',
            result_payload: {}
          }, dbClient);
        }

        // 3. Initiate playbook execution
        const runResult = await this.executePlaybook(execution.id, {
          alertContext: alert,
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
   * Sequentially executes the steps of a playbook execution.
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
    if (['pending', 'waiting_approval'].includes(execution.status)) {
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

    // Build context
    const runtimeContext = {
      organization_id: orgId,
      execution_id: executionId,
      playbook_id: playbook.id,
      playbook_name: playbook.name,
      alert_id: execution.trigger_alert_id,
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
              organization_id: orgId
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
            result_payload: { reason: 'Approval rejected' }
          }, dbClient);

          return await SoarExecution.findById(executionId, orgId, dbClient);
        }

        // If latestApproval.status === 'approved', proceed to execute this step!
      }

      // Execute step action
      await SoarExecution.updateStepRecord(step.id, {
        status: 'running',
        result_payload: {}
      }, dbClient);

      const actionResult = await actionExecutor.executeAction(
        step.action_type,
        step.action_config || {},
        runtimeContext,
        dbClient
      );

      if (actionResult.success) {
        await SoarExecution.updateStepRecord(step.id, {
          status: 'completed',
          result_payload: actionResult,
          executed_at: new Date()
        }, dbClient);
      } else {
        // Step failed
        await SoarExecution.updateStepRecord(step.id, {
          status: 'failed',
          result_payload: actionResult,
          executed_at: new Date()
        }, dbClient);

        await SoarExecution.updateStatus(executionId, orgId, 'failed', {
          completed_at: new Date()
        }, dbClient);

        await auditService.log({
          organization_id: orgId,
          actor_id: options.actor_id || null,
          action: 'SOAR_EXECUTION_FAILED',
          resource_type: 'soar_execution',
          resource_id: executionId,
          details: { failed_step: step.action_type, error: actionResult.error }
        }).catch(err => console.error('[playbookEngine] Audit log error:', err.message));

        return await SoarExecution.findById(executionId, orgId, dbClient);
      }
    }

    // 6. All steps completed successfully
    const completedExec = await SoarExecution.updateStatus(executionId, orgId, 'completed', {
      completed_at: new Date()
    }, dbClient);

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
}

const playbookEngine = new PlaybookEngine();
module.exports = playbookEngine;
