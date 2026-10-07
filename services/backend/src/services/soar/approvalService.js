const SoarApproval = require('../../models/SoarApproval');
const SoarExecution = require('../../models/SoarExecution');
const auditService = require('../auditService');

/**
 * Approval Service — Handles human-in-the-loop gating, multi-level escalation,
 * and SLA timeout expiration for sensitive SOAR actions.
 */
const approvalService = {
  LEVEL_ROLES: {
    'L1': ['analyst', 'senior_analyst', 'admin'],
    'L2': ['senior_analyst', 'admin'],
    'L3': ['admin']
  },

  /**
   * Requests human approval for an ongoing playbook execution.
   */
  async requestApproval({
    execution_id,
    requested_by = null,
    reason = 'Action requires security approval',
    organization_id = null,
    level = 'L1',
    ttl_minutes = null,
    expires_at = null
  }, client = null) {
    if (!execution_id) throw new Error('approvalService Error: execution_id is required');

    const cleanLevel = (level || 'L1').toUpperCase();
    let expiresAt = expires_at || null;
    if (!expiresAt && ttl_minutes !== undefined && ttl_minutes !== null && typeof ttl_minutes === 'number') {
      expiresAt = new Date(Date.now() + ttl_minutes * 60 * 1000);
    }

    // 1. Create pending approval record
    const approval = await SoarApproval.create({
      execution_id,
      requested_by,
      reason,
      level: cleanLevel,
      expires_at: expiresAt
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
        details: { execution_id, reason, level: cleanLevel, expires_at: expiresAt }
      }).catch(err => console.error('[approvalService] Audit log error:', err.message));
    }

    return approval;
  },

  /**
   * Verifies if a user role has authority to approve a given level.
   */
  canRoleApproveLevel(role, level) {
    const cleanRole = (role || '').toLowerCase();
    const cleanLevel = (level || 'L1').toUpperCase();
    const allowed = this.LEVEL_ROLES[cleanLevel] || ['admin'];
    return allowed.includes(cleanRole);
  },

  /**
   * Helper to decide approval (approved / rejected)
   */
  async decideApproval(approvalId, userId, decision, reason = '', organizationId = null, role = 'admin') {
    if (decision === 'approved') {
      return await this.approveExecution({
        approval_id: approvalId,
        organization_id: organizationId,
        approved_by: userId,
        user_role: role,
        reason
      });
    } else {
      return await this.rejectExecution({
        approval_id: approvalId,
        organization_id: organizationId,
        rejected_by: userId,
        reason,
        rejection_comment: reason
      });
    }
  },

  /**
   * Approves an execution and resumes playbook execution.
   */
  async approveExecution({
    approval_id,
    organization_id,
    approved_by = null,
    user_role = 'admin',
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

    // Check expiration
    if (approval.is_expired || (approval.expires_at && new Date(approval.expires_at) <= new Date())) {
      await this.expireApproval(approval, client);
      throw new Error(`Approval has expired and cannot be approved`);
    }

    // 2. Role vs level authorization check
    if (user_role && !this.canRoleApproveLevel(user_role, approval.level)) {
      const err = new Error(`Role "${user_role}" insufficient to approve level ${approval.level} request`);
      err.statusCode = 403;
      throw err;
    }

    // 3. Record approval decision
    const decided = await SoarApproval.decide(approval_id, {
      status: 'approved',
      decided_by: approved_by,
      reason
    }, client);

    // 4. Audit trail
    await auditService.log({
      organization_id: approval.organization_id,
      actor_id: approved_by,
      action: 'SOAR_APPROVAL_APPROVED',
      resource_type: 'soar_approval',
      resource_id: approval_id,
      details: { execution_id: approval.execution_id, level: approval.level, reason }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    // 5. Resume playbook execution
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
    reason = 'Rejected by administrator',
    rejection_comment = null
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

    const comment = rejection_comment || reason;

    // 2. Record rejection
    const decided = await SoarApproval.decide(approval_id, {
      status: 'rejected',
      decided_by: rejected_by,
      reason,
      rejection_comment: comment
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
      details: { execution_id: approval.execution_id, rejection_comment: comment }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    return {
      approval: decided,
      execution: updatedExecution
    };
  },

  /**
   * Escalates an approval request up the escalation chain (L1 -> L2 -> L3).
   */
  async escalateApproval({
    approval_id,
    organization_id,
    escalated_by = null,
    target_level = 'L2',
    reason = 'Escalated due to elevated risk or SLA expiry',
    ttl_minutes = null
  }, client = null) {
    if (!approval_id) throw new Error('approvalService Error: approval_id is required');

    const approval = await SoarApproval.findById(approval_id, organization_id, client);
    if (!approval) {
      throw new Error('Approval not found or access denied');
    }

    if (approval.status !== 'pending') {
      throw new Error(`Cannot escalate approval: status is already "${approval.status}"`);
    }

    const cleanTarget = (target_level || 'L2').toUpperCase();
    let newExpiresAt = approval.expires_at;
    if (ttl_minutes && typeof ttl_minutes === 'number' && ttl_minutes > 0) {
      newExpiresAt = new Date(Date.now() + ttl_minutes * 60 * 1000);
    }

    const escalated = await SoarApproval.escalate(approval_id, {
      escalated_to_level: cleanTarget,
      reason,
      expires_at: newExpiresAt
    }, client);

    await auditService.log({
      organization_id: approval.organization_id,
      actor_id: escalated_by,
      action: 'SOAR_APPROVAL_ESCALATED',
      resource_type: 'soar_approval',
      resource_id: approval_id,
      details: {
        previous_level: approval.level,
        escalated_to_level: cleanTarget,
        reason
      }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    return escalated;
  },

  /**
   * Expires a single approval and marks the corresponding execution cancelled.
   */
  async expireApproval(approval, client = null) {
    const expired = await SoarApproval.markExpired(approval.id, client);

    await SoarExecution.updateStatus(
      approval.execution_id,
      approval.organization_id,
      'cancelled',
      { completed_at: new Date() },
      client
    );

    await auditService.log({
      organization_id: approval.organization_id,
      actor_id: null,
      action: 'SOAR_APPROVAL_EXPIRED',
      resource_type: 'soar_approval',
      resource_id: approval.id,
      details: { execution_id: approval.execution_id, level: approval.level }
    }).catch(err => console.error('[approvalService] Audit log error:', err.message));

    return expired;
  },

  /**
   * Sweeps and expires all pending approvals past their expires_at deadline.
   */
  async checkAndExpireApprovals(client = null) {
    const pendingExpired = await SoarApproval.findPendingExpired(client);
    const results = [];

    for (const appr of pendingExpired) {
      try {
        const res = await this.expireApproval(appr, client);
        results.push(res);
      } catch (err) {
        console.error(`[approvalService] Failed to expire approval ${appr.id}:`, err.message);
      }
    }

    return results;
  }
};

module.exports = approvalService;
