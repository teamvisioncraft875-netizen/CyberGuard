const AuditLog = require('../models/AuditLog');

const SENSITIVE_KEY_REGEX = /password|token|secret|authorization|cookie/i;
const MAX_STRING_LENGTH = 500;

/**
 * Standard Catalog of Audit Action Identifiers
 */
const AUDIT_ACTIONS = Object.freeze({
  AUTH_SIGNUP: 'auth:signup',
  AUTH_LOGIN_SUCCESS: 'auth:login_success',
  AUTH_LOGIN_FAILED: 'auth:login_failed',
  AUTH_LOGOUT: 'auth:logout',
  AUTH_REFRESH_FAILED: 'auth:refresh_failed',
  INCIDENT_STATUS_UPDATED: 'incident:status_updated',
  ACTION_STATUS_UPDATED: 'action:status_updated',
  GUARDIAN_LINK_CREATED: 'guardian:link_created',
  GUARDIAN_LINK_ACCEPTED: 'guardian:link_accepted',
  GUARDIAN_LINK_DECLINED: 'guardian:link_declined',
  GUARDIAN_LINK_REVOKED: 'guardian:link_revoked',
  RESPONSE_ACTION_APPROVED: 'response_action:approved',
  RESPONSE_ACTION_REJECTED: 'response_action:rejected',
  TELEMETRY_SYSTEM_EVENT: 'telemetry:system_event',
  FIREWALL_RULE_CREATED: 'firewall_rule_created',
  FIREWALL_RULE_CREATION_FAILED: 'firewall_rule_creation_failed',
  FIREWALL_RULE_DELETED: 'firewall_rule_deleted',
  FIREWALL_RULE_DELETION_FAILED: 'firewall_rule_deletion_failed',
  FIREWALL_RULE_REVOCATION_FAILED: 'firewall_rule_deletion_failed',
  FIREWALL_COMMAND_CREATED: 'firewall_command_created',
  ATTACK_SURFACE_SNAPSHOT_TRUNCATED: 'attack_surface_snapshot_truncated',
  ATTACK_SURFACE_EXPOSURE_RESOLVED: 'attack_surface_exposure_resolved',
  INCIDENT_DEDUPLICATED: 'incident_deduplicated',
  INCIDENT_CONSOLIDATED: 'incident_consolidated',
  INCIDENT_CORRELATED: 'INCIDENT_CORRELATED',
  INCIDENT_RELATIONSHIP_CREATED: 'INCIDENT_RELATIONSHIP_CREATED',
  incident_correlated: 'INCIDENT_CORRELATED',
  incident_relationship_created: 'INCIDENT_RELATIONSHIP_CREATED',
  INCIDENT_GROUP_CREATED: 'INCIDENT_GROUP_CREATED',
  INCIDENT_GROUP_MEMBER_ADDED: 'INCIDENT_GROUP_MEMBER_ADDED',
  INCIDENT_GROUP_MERGED: 'INCIDENT_GROUP_MERGED',
  INCIDENT_GROUP_RESOLVED: 'INCIDENT_GROUP_RESOLVED',
  ATTACK_CHAIN_CREATED: 'ATTACK_CHAIN_CREATED',
  ATTACK_CHAIN_UPDATED: 'ATTACK_CHAIN_UPDATED',
  ATTACK_CHAIN_VIEWED: 'ATTACK_CHAIN_VIEWED'
});

/**
 * Recursively strips sensitive keys matching /password|token|secret|authorization|cookie/i
 * and truncates any string values longer than 500 characters.
 *
 * @param {*} data
 * @param {number} [depth=0]
 * @returns {*} Sanitized data
 */
function sanitizeDetails(data, depth = 0) {
  if (depth > 10 || data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    return data.length > MAX_STRING_LENGTH
      ? `${data.slice(0, MAX_STRING_LENGTH)}...[truncated]`
      : data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeDetails(item, depth + 1));
  }

  if (typeof data === 'object') {
    const cleaned = {};
    for (const [key, val] of Object.entries(data)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        continue; // Strip sensitive key entirely
      }
      cleaned[key] = sanitizeDetails(val, depth + 1);
    }
    return cleaned;
  }

  return data;
}

/**
 * Fire-and-forget audit logger.
 * Appends an audit log entry to PostgreSQL.
 * Guarantees zero unhandled exceptions: never throws and never blocks request execution.
 *
 * @param {Object} params
 * @param {string|null} [params.organization_id=null]
 * @param {string|null} [params.user_id=null]
 * @param {'user'|'admin'|'system_policy'|'system_guard'} params.actor_type
 * @param {string} params.action - One of AUDIT_ACTIONS
 * @param {string} params.resource_type
 * @param {string|null} [params.resource_id=null]
 * @param {Object} [params.details={}]
 * @param {string|null} [params.ip_address=null]
 * @returns {Promise<Object|null>} The created log row, or null on error
 */
async function log({
  organization_id = null,
  user_id = null,
  actor_type = 'user',
  action,
  resource_type,
  resource_id = null,
  details = {},
  ip_address = null
}, client = null) {
  try {
    const sanitizedDetails = sanitizeDetails(details);
    const validActorTypes = ['user', 'admin', 'system_policy', 'system_guard', 'device'];
    let resolvedActorType = validActorTypes.includes(actor_type) ? actor_type : 'user';
    if (actor_type === 'agent') {
      resolvedActorType = 'device';
    }

    const record = await AuditLog.create({
      organization_id,
      user_id,
      actor_type: resolvedActorType,
      action,
      resource_type,
      resource_id: resource_id ? String(resource_id) : null,
      details: sanitizedDetails,
      ip_address
    }, client);
    return record;
  } catch (err) {
    console.error('[AuditService.log Error]', err.message);
    return null;
  }
}

const auditService = {
  log,
  AUDIT_ACTIONS,
  sanitizeDetails
};

module.exports = {
  log,
  AUDIT_ACTIONS,
  sanitizeDetails,
  auditService
};

