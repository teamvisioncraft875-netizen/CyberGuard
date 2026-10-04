const ResponsePolicy = require('../models/ResponsePolicy');
const ResponseAction = require('../models/ResponseAction');
const notificationService = require('./notificationService');

const ALLOWED_ACTION_TYPES = [
  'notify_admin',
  'notify_user',
  'revoke_session',
  'force_password_reset',
  'require_mfa',
  'block_ip',
  'block_domain',
  'suspend_device',
  'isolate_device',
  'block_port'
];

const ALLOWED_ACTION_MODES = ['shadow', 'live'];

/**
 * PolicyEngine — Phase 1B Automated Response Layer (SHADOW MODE).
 * Decides what response actions should be taken for an incident.
 * Read-only on policies table, write-only on response_actions table.
 */
class PolicyEngine {
  /**
   * Filters response_policies.rules by threat_type, score, and target filter.
   *
   * @param {Object} incident
   * @returns {Promise<Array<Object>>} Matching rules with policy_id attached
   */
  static async getApplicablePolicies(incident) {
    if (!incident || !incident.organization_id) {
      return [];
    }

    const policies = await ResponsePolicy.findEnabledByOrg(incident.organization_id);
    const applicableRules = [];

    const incidentScore = Number(incident.risk_score ?? 0);
    const incidentThreatType = String(incident.threat_type || '').toLowerCase();

    for (const policy of policies) {
      let rules = policy.rules;
      if (typeof rules === 'string') {
        try {
          rules = JSON.parse(rules);
        } catch {
          rules = [];
        }
      }

      if (!Array.isArray(rules)) continue;

      for (const rule of rules) {
        if (!rule || !rule.threat_type || !rule.action_type) continue;

        // Threat type match (case-insensitive or wildcard)
        const ruleThreat = String(rule.threat_type).toLowerCase();
        const threatMatches = ruleThreat === '*' || ruleThreat === incidentThreatType;
        if (!threatMatches) continue;

        // Score threshold match
        const minScore = Number(rule.min_score ?? 0);
        if (incidentScore < minScore) continue;

        // Target filter match (e.g. user_roles)
        if (rule.target_filter && Array.isArray(rule.target_filter.user_roles) && incident.user_role) {
          if (!rule.target_filter.user_roles.includes(incident.user_role)) {
            continue;
          }
        }

        applicableRules.push({
          ...rule,
          policy_id: policy.id,
          policy_name: policy.name
        });
      }
    }

    // Built-in Platform Response Policy for exposed_secret incidents
    if (incidentThreatType === 'exposed_secret') {
      const hasNotifyAdmin = applicableRules.some((r) => r.action_type === 'notify_admin');
      if (!hasNotifyAdmin && incidentScore >= 70) {
        applicableRules.push({
          threat_type: 'exposed_secret',
          min_score: 70,
          action_type: 'notify_admin',
          action_mode: 'shadow',
          requires_approval: false,
          policy_id: null,
          policy_name: 'Default Exposed Secret Admin Alert'
        });
      }

      const hasNotifyUser = applicableRules.some((r) => r.action_type === 'notify_user');
      if (!hasNotifyUser && incidentScore >= 85) {
        applicableRules.push({
          threat_type: 'exposed_secret',
          min_score: 85,
          action_type: 'notify_user',
          action_mode: 'shadow',
          requires_approval: false,
          policy_id: null,
          policy_name: 'Default Exposed Secret User Alert'
        });
      }
    }

    // Built-in Platform Response Policy for attack_surface_exposure incidents
    if (incidentThreatType === 'attack_surface_exposure') {
      const hasNotifyAdmin = applicableRules.some((r) => r.action_type === 'notify_admin');
      if (!hasNotifyAdmin && incidentScore >= 70) {
        applicableRules.push({
          threat_type: 'attack_surface_exposure',
          min_score: 70,
          action_type: 'notify_admin',
          action_mode: 'shadow',
          requires_approval: false,
          policy_id: null,
          policy_name: 'Default Attack Surface Admin Alert'
        });
      }

      const hasBlockPort = applicableRules.some((r) => r.action_type === 'block_port');
      if (!hasBlockPort && incidentScore >= 70) {
        applicableRules.push({
          threat_type: 'attack_surface_exposure',
          min_score: 70,
          action_type: 'block_port',
          action_mode: 'shadow',
          requires_approval: true,
          policy_id: null,
          policy_name: 'Default Attack Surface Block Port Proposal'
        });
      }

      const hasIsolateDevice = applicableRules.some((r) => r.action_type === 'isolate_device');
      if (!hasIsolateDevice && incidentScore >= 90) {
        applicableRules.push({
          threat_type: 'attack_surface_exposure',
          min_score: 90,
          action_type: 'isolate_device',
          action_mode: 'shadow',
          requires_approval: true,
          policy_id: null,
          policy_name: 'Default Critical Exposure Device Isolation Proposal'
        });
      }
    }

    return applicableRules;
  }

  /**
   * For each applicable rule, determines the action_type, action_mode, and target.
   * Returns an array of proposed actions (intent only, no DB status yet).
   *
   * @param {Object} incident
   * @param {Array<Object>} applicablePolicies
   * @returns {Array<Object>} Proposed action intents
   */
  static calculateActions(incident, applicablePolicies = []) {
    const proposedActions = [];

    for (const rule of applicablePolicies) {
      const actionMode = this.determineMode(rule.action_type, incident);

      // Extract target metadata based on action_type
      const target = this._extractTarget(rule.action_type, incident);

      // Determine approval requirements (Rule + Guardrail C)
      let requiresApproval = Boolean(rule.requires_approval);
      if (this._isOrgLevelAction(rule.action_type, incident)) {
        requiresApproval = true;
      }

      // Calculate scheduled_at if auto_execute_after_mins is specified
      let scheduledAt = null;
      if (rule.auto_execute_after_mins && Number(rule.auto_execute_after_mins) > 0) {
        scheduledAt = new Date(Date.now() + Number(rule.auto_execute_after_mins) * 60000);
      }

      proposedActions.push({
        organization_id: incident.organization_id,
        incident_id: incident.id,
        policy_id: rule.policy_id,
        action_type: rule.action_type,
        action_mode: actionMode, // 'shadow' in Phase 1
        requires_approval: requiresApproval,
        target,
        scheduled_at: scheduledAt,
        requested_by_id: null
      });
    }

    return proposedActions;
  }

  /**
   * Determines the operational mode for an action.
   * Phase 1 OVERRIDE: returns 'shadow' for ALL actions.
   *
   * Guardrails evaluated:
   * a) Always shadow for network/system engine incidents (low precision).
   * b) Always shadow for any incident with analysis_confidence < 70 or where ML was degraded.
   * c) Never auto without approval for actions touching org-level targets (block_domain, block_ip when not user device).
   *
   * @param {string} action_type
   * @param {Object} incident
   * @returns {'shadow'|'live'}
   */
  static determineMode(action_type, incident = {}) {
    // In Phase 1, the response policy engine runs in 100% SHADOW MODE.
    // Guardrails are evaluated for telemetry/reasoning, but mode is universally 'shadow'.
    return 'shadow';
  }

  /**
   * Helper to check if an action affects org-level resources (Guardrail C).
   * Actions touching org-level targets (block_domain, block_ip not tied to user device)
   * must NEVER auto-execute without explicit admin approval.
   *
   * @param {string} action_type
   * @param {Object} incident
   * @returns {boolean}
   */
  static _isOrgLevelAction(action_type, incident = {}) {
    if (action_type === 'block_domain') {
      return true;
    }
    if (action_type === 'block_port') {
      return true;
    }
    if (action_type === 'block_ip') {
      // If it's an IP block not explicitly scoped to the user's specific registered device
      const isUserDevice = Boolean(incident.device_id && incident.user_id && !incident.is_shared_network);
      return !isUserDevice;
    }
    return false;
  }

  /**
   * Checks guardrail conditions for audit/telemetry purposes.
   *
   * @param {Object} incident
   * @returns {{ isSystemEngine: boolean, isLowConfidence: boolean, isOrgLevel: boolean }}
   */
  static evaluateGuardrails(incident = {}) {
    const sourceType = String(incident.source_type || '').toLowerCase();
    const threatType = String(incident.threat_type || '').toLowerCase();
    const engine = String(incident.engine || '').toLowerCase();

    // Guardrail A: System or network engine (low precision)
    const isSystemEngine = sourceType === 'system' ||
      sourceType === 'system_engine' ||
      engine === 'system_engine' ||
      threatType === 'technical_threat';

    // Guardrail B: Confidence < 70 or ML degraded
    const confidence = incident.analysis_confidence ??
      incident.confidence ??
      (incident.signals?.confidence_score != null ? incident.signals.confidence_score * 100 : null) ??
      100;
    const isDegraded = Boolean(incident.ml_degraded || incident.signals?.ml_degraded);
    const isLowConfidence = Number(confidence) < 70 || isDegraded;

    return {
      isSystemEngine,
      isLowConfidence,
      forceShadow: isSystemEngine || isLowConfidence
    };
  }

  /**
   * Extracts target details for an action from the incident context.
   *
   * @param {string} action_type
   * @param {Object} incident
   * @returns {Object}
   */
  static _extractTarget(action_type, incident) {
    const signals = incident.signals || {};
    const details = incident.details || {};
    const explicitTarget = incident.target || {};

    switch (action_type) {
      case 'block_ip':
        return {
          ip_address: explicitTarget.ip_address || signals.ip_address || details.ip_address || incident.ip_address || null
        };

      case 'block_domain':
        return {
          domain: explicitTarget.domain || signals.domain || details.domain || incident.domain || null
        };

      case 'revoke_session':
        return {
          user_id: incident.user_id || explicitTarget.user_id || null,
          session_id: explicitTarget.session_id || incident.session_id || null
        };

      case 'force_password_reset':
      case 'require_mfa':
      case 'notify_user':
        return {
          user_id: incident.user_id || explicitTarget.user_id || null
        };

      case 'suspend_device':
      case 'isolate_device':
        return {
          device_id: explicitTarget.device_id || incident.device_id || signals.device_id || null,
          user_id: incident.user_id || null
        };

      case 'notify_admin':
        return {
          organization_id: incident.organization_id || null,
          incident_id: incident.id || null
        };

      case 'block_port':
        return {
          port: explicitTarget.port || details.port || signals.port || (Array.isArray(signals) ? signals.find((s) => s.signal_name === 'public_exposed_service')?.signal_value : null),
          protocol: explicitTarget.protocol || details.protocol || 'tcp',
          device_id: explicitTarget.device_id || incident.device_id || signals.device_id || null
        };

      default:
        return explicitTarget;
    }
  }

  /**
   * Validates policy rules structure.
   *
   * @param {Array<Object>} rules
   * @throws {Error} If any rule fails validation
   */
  static validateRules(rules) {
    if (!Array.isArray(rules)) {
      throw new Error('Rules must be an array of rule objects');
    }

    if (rules.length === 0) {
      throw new Error('Rules array cannot be empty');
    }

    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!rule || typeof rule !== 'object') {
        throw new Error(`Rule at index ${i} must be an object`);
      }

      if (!rule.threat_type || typeof rule.threat_type !== 'string') {
        throw new Error(`Rule at index ${i}: threat_type is required and must be a string`);
      }

      if (rule.min_score === undefined || rule.min_score === null || isNaN(Number(rule.min_score))) {
        throw new Error(`Rule at index ${i}: min_score is required and must be a number`);
      }
      const score = Number(rule.min_score);
      if (score < 0 || score > 100) {
        throw new Error(`Rule at index ${i}: min_score must be between 0 and 100`);
      }

      if (!rule.action_type || !ALLOWED_ACTION_TYPES.includes(rule.action_type)) {
        throw new Error(`Rule at index ${i}: action_type must be one of: ${ALLOWED_ACTION_TYPES.join(', ')}`);
      }

      if (rule.action_mode && !ALLOWED_ACTION_MODES.includes(rule.action_mode)) {
        throw new Error(`Rule at index ${i}: action_mode must be 'shadow' or 'live'`);
      }

      if (rule.auto_execute_after_mins !== undefined && (isNaN(Number(rule.auto_execute_after_mins)) || Number(rule.auto_execute_after_mins) < 0)) {
        throw new Error(`Rule at index ${i}: auto_execute_after_mins must be a non-negative number`);
      }

      if (rule.target_filter && typeof rule.target_filter !== 'object') {
        throw new Error(`Rule at index ${i}: target_filter must be an object`);
      }
    }
  }

  /**
   * End-to-end evaluation & action proposal for an incident.
   * Creates rows in response_actions with status='proposed' and action_mode='shadow'.
   * Never throws (fire-and-forget safe).
   *
   * @param {Object} incident
   * @returns {Promise<Array<Object>>} Proposed action records
   */
  static async evaluateAndProposeActions(incident) {
    if (!incident || !incident.organization_id || !incident.id) {
      return [];
    }

    try {
      const applicablePolicies = await this.getApplicablePolicies(incident);
      if (!applicablePolicies || applicablePolicies.length === 0) {
        return [];
      }

      const calculatedActions = this.calculateActions(incident, applicablePolicies);
      const createdActions = [];

      for (const action of calculatedActions) {
        const created = await ResponseAction.create({
          organization_id: action.organization_id,
          incident_id: action.incident_id,
          policy_id: action.policy_id,
          action_type: action.action_type,
          action_mode: 'shadow', // Always shadow in Phase 1
          status: 'proposed',
          target: action.target,
          scheduled_at: action.scheduled_at,
          requested_by_id: action.requested_by_id
        });
        createdActions.push(created);

        // Hook into response_actions creation (Phase 1C: Notification Service)
        // Fire-and-forget: never block execution or fail incident response
        const matchingPolicy = applicablePolicies.find((p) => p.policy_id === action.policy_id);
        notificationService.sendActionNotification(created, incident, matchingPolicy).catch((nErr) => {
          console.error('[NotificationService Hook Error]', nErr.message);
        });
      }

      return createdActions;
    } catch (err) {
      console.error('[PolicyEngine Proposal Error]', err.message);
      return [];
    }
  }
}

module.exports = PolicyEngine;
