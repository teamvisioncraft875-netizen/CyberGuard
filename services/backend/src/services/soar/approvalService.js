const SoarApproval = require('../../models/SoarApproval');
const SoarExecution = require('../../models/SoarExecution');
const auditService = require('../auditService');

/**
 * Approval Service — Handles human-in-the-loop gating for sensitive SOAR actions
 */
const approvalService = {
  /**
   * Requests human approval for an ongoing playbook execution.
   */
  async requestApproval({
    execution_id,
    requested_by = null,
    reason = 'Action requires security administrator approval',
    organization_id = null
  }, client = null) {
    if (!execution_id) throw new Error('approvalService Error: execution_id is required');

    // 1. Create pending approval record
    const approval = await SoarApproval.create({
      execution_id,
      requested_by,
      reason
    }, client);

    // 2. Mark execution as waiting_approval
    const orgId = organization_id || approval.organization_id;
    if (orgId) {
      await SoarExecution.updateStatus(execution_id, orgId, 'waiting_approval', {}, client);
    }

    // 3. Record audit trail
    if (orgId) {
      await auditService.log({
        organization_id: orgId,
        actor_id: requested_by,
        action: 'SOAR_APPROVAL_REQUESTED',
        resource_type: 'soar_approval',
        resource_id: approval.id,
        details: { execution_id, reason }
      }).catch(err => console.error('[approvalService] Audit log error:', err.message));
    }

    return approval;
  },

  /**
   * Approves an execution and resumes playbook execution.
   */
  async approveExecution({
    approval_id,
    organization_id,
    approved_by = null,
    reason = 'Approved by administrator'
  }, client = null) {
    if (!approval_id) throw new Error('approvalService Error: approval_id is required');

    // 1. Retrieve approval
    const approval = await SoarApproval.findById(approval_id, organization_id, client);
    if (!approval) {
      throw new Error(`Approval not found or access denied`);
    }

    if (approval.status !== 'pending') {
      throw new Error(`Approval cannot be decided: current status is "${approval.status}"`);
    }

    // 2. Record approval decision
    const decided = await SoarApproval.decide(approval_id, {
      status: 'approved',
      decided_by: approved_by,
      reason
    }, client);

    // 3. Audit trail
    await auditService.log({
      organization_id: approval.organization_id,
      actor_id: approved_by,
      action: 'SOAR_APPROVAL_APPROVED',
      resource_type: 'soar_approval',
      resource_id: approval_id,
      details: { execution_id: approval.execution_id, reason }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    // 4. Resume playbook execution
    const playbookEngine = require('./playbookEngine');
    const executionResult = await playbookEngine.resumeExecution(approval.execution_id, client);

    return {
      approval: decided,
      execution: executionResult
    };
  },

  /**
   * Rejects an execution, halting further action steps.
   */
  async rejectExecution({
    approval_id,
    organization_id,
    rejected_by = null,
    reason = 'Rejected by administrator'
  }, client = null) {
    if (!approval_id) throw new Error('approvalService Error: approval_id is required');

    // 1. Retrieve approval
    const approval = await SoarApproval.findById(approval_id, organization_id, client);
    if (!approval) {
      throw new Error(`Approval not found or access denied`);
    }

    if (approval.status !== 'pending') {
      throw new Error(`Approval cannot be decided: current status is "${approval.status}"`);
    }

    // 2. Record rejection
    const decided = await SoarApproval.decide(approval_id, {
      status: 'rejected',
      decided_by: rejected_by,
      reason
    }, client);

    // 3. Update execution status to cancelled
    const updatedExecution = await SoarExecution.updateStatus(
      approval.execution_id,
      approval.organization_id,
      'cancelled',
      { completed_at: new Date() },
      client
    );

    // 4. Audit trail
    await auditService.log({
      organization_id: approval.organization_id,
      actor_id: rejected_by,
      action: 'SOAR_APPROVAL_REJECTED',
      resource_type: 'soar_approval',
      resource_id: approval_id,
      details: { execution_id: approval.execution_id, reason }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    return {
      approval: decided,
      execution: updatedExecution
    };
  }
};

module.exports = approvalService;
