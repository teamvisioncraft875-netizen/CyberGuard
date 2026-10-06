const db = require('../config/db');
const Incident = require('../models/Incident');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Analyst Workflow Engine
 *
 * Coordinates SOC incident lifecycle operations:
 * - Assign incident to analyst
 * - Change incident status (investigating, open)
 * - Escalate incident to P1 with timestamp
 * - Resolve incident with resolution timestamp
 * - Reopen resolved incident
 */
class IncidentWorkflowService {
  /**
   * Assign an incident to an analyst
   */
  async assignIncident(incidentId, organizationId, assignedToUserId, { actorUserId = null } = {}) {
    // Verify target analyst user exists in the organization if provided
    if (assignedToUserId) {
      const userRes = await db.query(
        `SELECT id, email FROM public.users WHERE id = $1 AND organization_id = $2;`,
        [assignedToUserId, organizationId]
      );
      if (userRes.rows.length === 0) {
        throw new Error('Assigned user not found in this organization');
      }
    }

    const updated = await Incident.assign(incidentId, assignedToUserId, organizationId);
    if (!updated) {
      throw new Error(`Incident ${incidentId} not found in organization`);
    }

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.INCIDENT_ASSIGNED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        assigned_to: assignedToUserId,
        assigned_at: updated.assigned_at
      }
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return updated;
  }

  /**
   * Escalate an incident to critical priority (P1)
   */
  async escalateIncident(incidentId, organizationId, { actorUserId = null, reason = 'Analyst escalation' } = {}) {
    const updated = await Incident.escalate(incidentId, organizationId);
    if (!updated) {
      throw new Error(`Incident ${incidentId} not found in organization`);
    }

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.INCIDENT_ESCALATED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        priority: 'P1',
        escalated_at: updated.escalated_at,
        reason
      }
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return updated;
  }

  /**
   * Resolve an incident
   */
  async resolveIncident(incidentId, organizationId, { actorUserId = null } = {}) {
    const updated = await Incident.updateStatus(incidentId, 'resolved', actorUserId, organizationId);
    if (!updated) {
      throw new Error(`Incident ${incidentId} not found in organization`);
    }

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.INCIDENT_STATUS_UPDATED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        status: 'resolved',
        resolved_by: actorUserId,
        resolved_at: updated.resolved_at
      }
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return updated;
  }

  /**
   * Reopen a resolved incident
   */
  async reopenIncident(incidentId, organizationId, { actorUserId = null, reason = 'Analyst reopen' } = {}) {
    const updated = await Incident.reopen(incidentId, organizationId);
    if (!updated) {
      throw new Error(`Incident ${incidentId} not found in organization`);
    }

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.INCIDENT_REOPENED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        status: 'open',
        reopened_at: new Date().toISOString(),
        reason
      }
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return updated;
  }

  /**
   * Update general incident status (e.g. 'investigating', 'open')
   */
  async updateStatus(incidentId, organizationId, newStatus, { actorUserId = null } = {}) {
    const validStatuses = ['open', 'investigating', 'resolved'];
    const resolvedStatus = (newStatus || '').toLowerCase();
    if (!validStatuses.includes(resolvedStatus)) {
      throw new Error(`Invalid status: ${newStatus}. Must be one of: ${validStatuses.join(', ')}`);
    }

    if (resolvedStatus === 'resolved') {
      return this.resolveIncident(incidentId, organizationId, { actorUserId });
    }

    const updated = await Incident.updateStatus(incidentId, resolvedStatus, null, organizationId);
    if (!updated) {
      throw new Error(`Incident ${incidentId} not found in organization`);
    }

    auditLog({
      organization_id: organizationId,
      user_id: actorUserId,
      actor_type: actorUserId ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.INCIDENT_STATUS_UPDATED,
      resource_type: 'incident',
      resource_id: incidentId,
      details: {
        status: resolvedStatus
      }
    });

    try {
      require('./commandCenterService').invalidateCache(incidentId);
    } catch {}

    return updated;
  }
}

module.exports = new IncidentWorkflowService();
