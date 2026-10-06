const ResponsePolicy = require('../models/ResponsePolicy');
const ResponseAction = require('../models/ResponseAction');
const notificationService = require('./notificationService');
const db = require('../config/db');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

const ALLOWED_ACTION_TYPES = [
  'notify_admin',
  'notify_user',
  'revoke_session',
  'force_password_reset',
  'require_mfa',
  'block_ip',
  'block_domain',
  'block_url',
  'suspend_device',
  'isolate_device',
  'block_port'
];

const ALLOWED_ACTION_MODES = ['shadow', 'live'];

/**
 * PolicyEngine — Automated Response Layer with Threat Intelligence Integration.
 * Decides what response actions should be taken for an incident.
 * Read-only on policies table, write-only on response_actions table.
 */
class PolicyEngine {
  /**
   * Filters response_policies.rules by threat_type, score, target filter,
   * and threat intelligence conditions.
   *
   * @param {Object} incident
   * @param {Object} [client=null]
   * @returns {Promise<Array<Object>>} Matching rules with policy_id attached
   */
  static async getApplicablePolicies(incident, client = null) {
    if (!incident || !incident.organization_id) {
      return [];
    }

    const policies = await ResponsePolicy.findEnabledByOrg(incident.organization_id, client);
    const applicableRules = [];

    const incidentScore = Number(incident.risk_score ?? 0);
    const incidentThreatType = String(incident.threat_type || '').toLowerCase();

    // 1. Resolve Threat Intelligence IOC Matches
    let iocMatches = incident.ioc_matches || incident.threat_intel?.matches;
    if (!iocMatches && incident.id) {
      try {
        const dbClient = client || db;
        const matchRes = await dbClient.query(
          `SELECT iom.*, ti.indicator_type, ti.indicator_value, ti.severity, ti.confidence_score, ti.feed_id
           FROM public.incident_ioc_matches iom
           LEFT JOIN public.threat_indicators ti ON iom.indicator_id = ti.id
           WHERE iom.incident_id = $1;`,
          [incident.id]
        );
        iocMatches = matchRes.rows || [];
      } catch (err) {
        iocMatches = [];
      }
    }

    const localMatches = Array.isArray(iocMatches) ? iocMatches : [];
    const repMatches = Array.isArray(incident.threat_intel?.reputation_matches) ? incident.threat_intel.reputation_matches : [];
    const allMatches = [...localMatches, ...repMatches];

    const matchExists = allMatches.length > 0;
    const indicatorCount = allMatches.length;

    let maxConfidence = 0;
    let maxReputationScore = 0;

    for (const m of allMatches) {
      const conf = Number(m.confidence_score ?? m.confidence ?? m.reputation_score ?? 0);
      const rep = Number(m.reputation_score ?? m.confidence ?? 0);
      if (conf > maxConfidence) maxConfidence = conf;
      if (rep > maxReputationScore) maxReputationScore = rep;
    }

    if (incident.threat_intel?.highest_confidence_indicator?.confidence) {
      const c = Number(incident.threat_intel.highest_confidence_indicator.confidence);
      if (c > maxConfidence) maxConfidence = c;
      if (c > maxReputationScore) maxReputationScore = c;
    }
    if (incident.reputation_score !== undefined && incident.reputation_score !== null) {
      const r = Number(incident.reputation_score);
      if (r > maxReputationScore) maxReputationScore = r;
      if (r > maxConfidence) maxConfidence = r;
    }
    if (incident.confidence !== undefined && incident.confidence !== null) {
      const c = Number(incident.confidence);
      if (c > maxConfidence) maxConfidence = c;
    }

    // 2. Evaluate Custom Organization Policies
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

        // Condition A: threat_intel_match_exists
        if (rule.threat_intel_match_exists !== undefined && rule.threat_intel_match_exists !== null) {
          if (Boolean(rule.threat_intel_match_exists) !== matchExists) {
            continue;
          }
        }

        // Condition B: threat_intel_confidence_gte
        if (rule.threat_intel_confidence_gte !== undefined && rule.threat_intel_confidence_gte !== null) {
          if (maxConfidence < Number(rule.threat_intel_confidence_gte)) {
            continue;
          }
        }

        // Condition C: threat_intel_severity_equals
        if (rule.threat_intel_severity_equals !== undefined && rule.threat_intel_severity_equals !== null) {
          const reqSev = String(rule.threat_intel_severity_equals).toLowerCase().trim();
          const hasMatchingSeverity = allMatches.some(
            (m) => String(m.severity || '').toLowerCase().trim() === reqSev
          );
          if (!hasMatchingSeverity) {
            continue;
          }
        }

        // Condition D: reputation_score_gte
        if (rule.reputation_score_gte !== undefined && rule.reputation_score_gte !== null) {
          if (maxReputationScore < Number(rule.reputation_score_gte)) {
            continue;
          }
        }

        // Condition E: malicious_indicator_count_gte
        if (rule.malicious_indicator_count_gte !== undefined && rule.malicious_indicator_count_gte !== null) {
          if (indicatorCount < Number(rule.malicious_indicator_count_gte)) {
            continue;
          }
        }

        // Target filter match (e.g. user_roles)
        if (rule.target_filter && Array.isArray(rule.target_filter.user_roles)) {
          const roles = rule.target_filter.user_roles;
          if (!roles.includes('*') && incident.user_role && !roles.includes(incident.user_role)) {
            continue;
          }
        }

        applicableRules.push({
          ...rule,
          policy_id: policy.id,
          policy_name: policy.name,
          all_matches: allMatches
        });
      }
    }

    // 3. Automatic Action Proposal Generation for Threat Intel Findings (Deliverable 2)
    if (allMatches.length > 0) {
      for (const match of allMatches) {
        const indType = String(match.indicator_type || match.type || '').toLowerCase();
        const indVal = match.matched_value || match.indicator_value || match.value;
        const conf = Number(match.confidence_score ?? match.confidence ?? match.reputation_score ?? 0);
        const isMalicious = Boolean(
          match.malicious || conf >= 70 || ['critical', 'high'].includes(String(match.severity || '').toLowerCase())
        );

        if (!isMalicious || !indVal) continue;

        if (['ip', 'ipv4', 'ipv6'].includes(indType)) {
          const alreadyProposed = applicableRules.some(
            (r) => r.action_type === 'block_ip' &&
              (r.matched_indicator?.matched_value === indVal || r.matched_indicator?.indicator_value === indVal)
          );
          if (!alreadyProposed) {
            applicableRules.push({
              threat_type: '*',
              min_score: 0,
              action_type: 'block_ip',
              action_mode: 'shadow',
              requires_approval: true,
              policy_id: null,
              policy_name: 'Threat Intel Automated IP Containment',
              matched_indicator: match
            });
          }
        } else if (['domain', 'hostname'].includes(indType)) {
          const alreadyProposed = applicableRules.some(
            (r) => r.action_type === 'block_domain' &&
              (r.matched_indicator?.matched_value === indVal || r.matched_indicator?.indicator_value === indVal)
          );
          if (!alreadyProposed) {
            applicableRules.push({
              threat_type: '*',
              min_score: 0,
              action_type: 'block_domain',
              action_mode: 'shadow',
              requires_approval: true,
              policy_id: null,
              policy_name: 'Threat Intel Automated Domain Containment',
              matched_indicator: match
            });
          }
        } else if (['url'].includes(indType)) {
          const alreadyProposed = applicableRules.some(
            (r) => r.action_type === 'block_url' &&
              (r.matched_indicator?.matched_value === indVal || r.matched_indicator?.indicator_value === indVal)
          );
          if (!alreadyProposed) {
            applicableRules.push({
              threat_type: '*',
              min_score: 0,
              action_type: 'block_url',
              action_mode: 'shadow',
              requires_approval: true,
              policy_id: null,
              policy_name: 'Threat Intel Automated URL Containment',
              matched_indicator: match
            });
          }
        } else if (['md5', 'sha1', 'sha256', 'hash'].includes(indType)) {
          const alreadyProposed = applicableRules.some(
            (r) => r.action_type === 'isolate_device' || r.action_type === 'notify_admin'
          );
          if (!alreadyProposed && (incident.device_id || incident.target_device_id)) {
            applicableRules.push({
              threat_type: '*',
              min_score: 0,
              action_type: 'isolate_device',
              action_mode: 'shadow',
              requires_approval: true,
              policy_id: null,
              policy_name: 'Threat Intel Malicious Hash Device Isolation',
              matched_indicator: match
            });
          }
        }
      }

      // Notify admin for high-confidence/critical threat intelligence finding
      if (maxConfidence >= 80 || allMatches.some((m) => String(m.severity || '').toLowerCase() === 'critical')) {
        const hasNotifyAdmin = applicableRules.some((r) => r.action_type === 'notify_admin');
        if (!hasNotifyAdmin) {
          applicableRules.push({
            threat_type: '*',
            min_score: 0,
            action_type: 'notify_admin',
            action_mode: 'shadow',
            requires_approval: false,
            policy_id: null,
            policy_name: 'Threat Intel Critical Alert Notification'
          });
        }
      }
    }

    // 4. Built-in Platform Response Policy for exposed_secret incidents
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

    // 5. Built-in Platform Response Policy for attack_surface_exposure incidents
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

    if (!incident.ioc_matches && allMatches.length > 0) {
      incident.ioc_matches = allMatches;
    }

    return applicableRules;
  }

  /**
   * For each applicable rule, determines action_type, action_mode, target, and metadata.
   * Returns an array of proposed actions (intent only, no DB status yet).
   *
   * @param {Object} incident
   * @param {Array<Object>} applicablePolicies
   * @returns {Array<Object>} Proposed action intents
   */
  static calculateActions(incident, applicablePolicies = []) {
    const proposedActions = [];

    let localMatches = Array.isArray(incident.ioc_matches) ? incident.ioc_matches : (incident.threat_intel?.matches || []);
    if (localMatches.length === 0) {
      const ruleWithMatches = applicablePolicies.find((r) => Array.isArray(r.all_matches) && r.all_matches.length > 0);
      if (ruleWithMatches) {
        localMatches = ruleWithMatches.all_matches;
      }
    }
    const repMatches = Array.isArray(incident.threat_intel?.reputation_matches) ? incident.threat_intel.reputation_matches : [];
    const allMatches = [...localMatches, ...repMatches];

    for (const rule of applicablePolicies) {
      const actionMode = this.determineMode(rule.action_type, incident, rule);

      let requiresApproval = rule.requires_approval !== undefined ? Boolean(rule.requires_approval) : true;
      if (this._isOrgLevelAction(rule.action_type, incident)) {
        requiresApproval = true;
      }

      let scheduledAt = null;
      if (rule.auto_execute_after_mins && Number(rule.auto_execute_after_mins) > 0) {
        scheduledAt = new Date(Date.now() + Number(rule.auto_execute_after_mins) * 60000);
      }

      // If rule has an explicit matched_indicator attached
      if (rule.matched_indicator) {
        const match = rule.matched_indicator;
        const indVal = match.matched_value || match.indicator_value || match.value;
        const indType = match.indicator_type || match.type;
        const target = this._extractTargetForIndicator(rule.action_type, incident, match);
        const metadata = {
          matched_indicator_id: match.indicator_id || match.id || null,
          indicator_value: indVal,
          indicator_type: indType,
          reputation_score: match.reputation_score !== undefined ? match.reputation_score : (match.confidence_score || match.confidence || 0),
          confidence_score: match.confidence_score !== undefined ? match.confidence_score : (match.reputation_score || match.confidence || 0),
          source_feed: match.feed_source || match.source || 'Threat Intel Feed'
        };

        proposedActions.push({
          organization_id: incident.organization_id,
          incident_id: incident.id,
          policy_id: rule.policy_id,
          action_type: rule.action_type,
          action_mode: actionMode,
          requires_approval: requiresApproval,
          target,
          metadata,
          scheduled_at: scheduledAt,
          requested_by_id: null,
          target_device_id: rule.target_device_id || incident.target_device_id || incident.device_id || target.device_id || null
        });
        continue;
      }

      // If rule is an indicator action (block_ip, block_domain, block_url) and incident has matched indicators
      const isIndicatorAction = ['block_ip', 'block_domain', 'block_url'].includes(rule.action_type);
      let relevantMatches = [];
      if (isIndicatorAction && allMatches.length > 0) {
        if (rule.action_type === 'block_ip') {
          relevantMatches = allMatches.filter((m) =>
            ['ip', 'ipv4', 'ipv6'].includes(String(m.indicator_type || m.type || '').toLowerCase())
          );
        } else if (rule.action_type === 'block_domain') {
          relevantMatches = allMatches.filter((m) =>
            ['domain', 'hostname'].includes(String(m.indicator_type || m.type || '').toLowerCase())
          );
        } else if (rule.action_type === 'block_url') {
          relevantMatches = allMatches.filter((m) =>
            ['url'].includes(String(m.indicator_type || m.type || '').toLowerCase())
          );
        }
      }

      if (relevantMatches.length > 0) {
        for (const match of relevantMatches) {
          const indVal = match.matched_value || match.indicator_value || match.value;
          const indType = match.indicator_type || match.type;
          const target = this._extractTargetForIndicator(rule.action_type, incident, match);
          const metadata = {
            matched_indicator_id: match.indicator_id || match.id || null,
            indicator_value: indVal,
            indicator_type: indType,
            reputation_score: match.reputation_score !== undefined ? match.reputation_score : (match.confidence_score || match.confidence || 0),
            confidence_score: match.confidence_score !== undefined ? match.confidence_score : (match.reputation_score || match.confidence || 0),
            source_feed: match.feed_source || match.source || 'Threat Intel Feed'
          };

          proposedActions.push({
            organization_id: incident.organization_id,
            incident_id: incident.id,
            policy_id: rule.policy_id,
            action_type: rule.action_type,
            action_mode: actionMode,
            requires_approval: requiresApproval,
            target,
            metadata,
            scheduled_at: scheduledAt,
            requested_by_id: null,
            target_device_id: rule.target_device_id || incident.target_device_id || incident.device_id || target.device_id || null
          });
        }
      } else {
        const target = this._extractTarget(rule.action_type, incident);
        let metadata = {};
        if (allMatches.length > 0) {
          const topMatch = allMatches[0];
          metadata = {
            matched_indicator_id: topMatch.indicator_id || topMatch.id || null,
            indicator_value: topMatch.matched_value || topMatch.indicator_value || topMatch.value,
            indicator_type: topMatch.indicator_type || topMatch.type,
            reputation_score: topMatch.reputation_score !== undefined ? topMatch.reputation_score : (topMatch.confidence_score || topMatch.confidence || 0),
            confidence_score: topMatch.confidence_score !== undefined ? topMatch.confidence_score : (topMatch.reputation_score || topMatch.confidence || 0),
            source_feed: topMatch.feed_source || topMatch.source || 'Threat Intel Feed'
          };
        }

        proposedActions.push({
          organization_id: incident.organization_id,
          incident_id: incident.id,
          policy_id: rule.policy_id,
          action_type: rule.action_type,
          action_mode: actionMode,
          requires_approval: requiresApproval,
          target,
          metadata,
          scheduled_at: scheduledAt,
          requested_by_id: null,
          target_device_id: rule.target_device_id || incident.target_device_id || incident.device_id || target.device_id || null
        });
      }
    }

    return proposedActions;
  }

  /**
   * Determines operational mode for an action.
   * Supports 'live' mode when policy specifies live and safety guardrails permit;
   * otherwise defaults to 'shadow'.
   *
   * @param {string} action_type
   * @param {Object} incident
   * @param {Object} [rule={}]
   * @returns {'shadow'|'live'}
   */
  static determineMode(action_type, incident = {}, rule = {}) {
    if (rule.action_mode === 'live') {
      const guardrails = this.evaluateGuardrails(incident);
      if (guardrails.isLowConfidence) {
        return 'shadow';
      }
      return 'live';
    }
    return rule.action_mode || 'shadow';
  }

  /**
   * Checks if an action affects org-level resources (Guardrail C).
   * Actions touching org-level targets (block_domain, block_url, block_port, block_ip)
   * must require admin approval.
   *
   * @param {string} action_type
   * @param {Object} incident
   * @returns {boolean}
   */
  static _isOrgLevelAction(action_type, incident = {}) {
    if (action_type === 'block_domain' || action_type === 'block_url' || action_type === 'block_port') {
      return true;
    }
    if (action_type === 'block_ip') {
      const isUserDevice = Boolean(incident.device_id && incident.user_id && !incident.is_shared_network);
      return !isUserDevice;
    }
    return false;
  }

  /**
   * Evaluates guardrail conditions for safety and confidence checking.
   *
   * @param {Object} incident
   * @returns {{ isSystemEngine: boolean, isLowConfidence: boolean, forceShadow: boolean }}
   */
  static evaluateGuardrails(incident = {}) {
    const sourceType = String(incident.source_type || '').toLowerCase();
    const threatType = String(incident.threat_type || '').toLowerCase();
    const engine = String(incident.engine || '').toLowerCase();

    const isSystemEngine = sourceType === 'system_engine' ||
      engine === 'system_engine' ||
      threatType === 'technical_threat';

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
   * Helper to extract indicator-targeted action context.
   * @private
   */
  static _extractTargetForIndicator(action_type, incident, match) {
    const val = match.matched_value || match.indicator_value || match.value;
    switch (action_type) {
      case 'block_ip':
        return {
          ip_address: val,
          org_wide: true,
          indicator_value: val,
          indicator_type: match.indicator_type || match.type || 'ip',
          matched_indicator_id: match.indicator_id || match.id || null
        };
      case 'block_domain':
        return {
          domain: val,
          indicator_value: val,
          indicator_type: match.indicator_type || match.type || 'domain',
          matched_indicator_id: match.indicator_id || match.id || null
        };
      case 'block_url':
        return {
          url: val,
          indicator_value: val,
          indicator_type: match.indicator_type || match.type || 'url',
          matched_indicator_id: match.indicator_id || match.id || null
        };
      default:
        return this._extractTarget(action_type, incident);
    }
  }

  /**
   * Extracts target details for an action from incident context.
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
      case 'block_ip': {
        const ip = explicitTarget.ip_address || signals.ip_address || details.ip_address || incident.ip_address || signals.source_ip || details.source_ip || incident.source_ip || null;
        return {
          ip_address: ip,
          org_wide: explicitTarget.org_wide !== undefined ? explicitTarget.org_wide : true
        };
      }

      case 'block_domain':
        return {
          domain: explicitTarget.domain || signals.domain || details.domain || incident.domain || null
        };

      case 'block_url':
        return {
          url: explicitTarget.url || signals.url || details.url || incident.url || null
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
   * Validates policy rules structure and threat intelligence conditions.
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

      // Threat Intelligence Condition Validations
      if (rule.threat_intel_match_exists !== undefined && typeof rule.threat_intel_match_exists !== 'boolean') {
        throw new Error(`Rule at index ${i}: threat_intel_match_exists must be a boolean`);
      }

      if (rule.threat_intel_confidence_gte !== undefined && (isNaN(Number(rule.threat_intel_confidence_gte)) || Number(rule.threat_intel_confidence_gte) < 0 || Number(rule.threat_intel_confidence_gte) > 100)) {
        throw new Error(`Rule at index ${i}: threat_intel_confidence_gte must be a number between 0 and 100`);
      }

      if (rule.threat_intel_severity_equals !== undefined && (typeof rule.threat_intel_severity_equals !== 'string' || !['critical', 'high', 'medium', 'low', 'info'].includes(rule.threat_intel_severity_equals.toLowerCase()))) {
        throw new Error(`Rule at index ${i}: threat_intel_severity_equals must be one of: critical, high, medium, low, info`);
      }

      if (rule.reputation_score_gte !== undefined && (isNaN(Number(rule.reputation_score_gte)) || Number(rule.reputation_score_gte) < 0 || Number(rule.reputation_score_gte) > 100)) {
        throw new Error(`Rule at index ${i}: reputation_score_gte must be a number between 0 and 100`);
      }

      if (rule.malicious_indicator_count_gte !== undefined && (isNaN(Number(rule.malicious_indicator_count_gte)) || Number(rule.malicious_indicator_count_gte) < 0)) {
        throw new Error(`Rule at index ${i}: malicious_indicator_count_gte must be a non-negative number`);
      }
    }
  }

  /**
   * End-to-end evaluation & action proposal for an incident.
   * Creates rows in response_actions with status='proposed', metadata, and audit logging.
   * Never throws (fire-and-forget safe).
   *
   * @param {Object} incident
   * @param {Object} [client=null]
   * @returns {Promise<Array<Object>>} Proposed action records
   */
  static async evaluateAndProposeActions(incident, client = null) {
    if (!incident || !incident.organization_id || !incident.id) {
      return [];
    }

    try {
      if (client) {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`policy_eval:${incident.id}`]);
      }

      // Check if incident still exists in DB (guards against race conditions during immediate deletions/cleanup)
      const dbClient = client || db;
      const incCheck = await dbClient.query('SELECT id FROM public.incidents WHERE id = $1;', [incident.id]);
      if (!incCheck.rows || incCheck.rows.length === 0) {
        return [];
      }

      const applicablePolicies = await this.getApplicablePolicies(incident, client);
      if (!applicablePolicies || applicablePolicies.length === 0) {
        return [];
      }

      // Standard policy matched audit log
      await auditLog({
        organization_id: incident.organization_id,
        user_id: null,
        actor_type: 'system_policy',
        action: 'policy_matched',
        resource_type: 'incident',
        resource_id: incident.id,
        details: {
          matched_policies_count: applicablePolicies.length,
          policies: applicablePolicies.map((p) => ({ policy_id: p.policy_id, name: p.policy_name, action_type: p.action_type }))
        }
      }, client);

      // Threat Intel Policy Triggered Audit Log
      const tiRules = applicablePolicies.filter(
        (p) => p.threat_intel_match_exists !== undefined ||
               p.threat_intel_confidence_gte !== undefined ||
               p.threat_intel_severity_equals !== undefined ||
               p.reputation_score_gte !== undefined ||
               p.malicious_indicator_count_gte !== undefined ||
               p.matched_indicator ||
               p.policy_name?.includes('Threat Intel')
      );
      if (tiRules.length > 0) {
        await auditLog({
          organization_id: incident.organization_id,
          user_id: null,
          actor_type: 'system_policy',
          action: AUDIT_ACTIONS.THREAT_POLICY_TRIGGERED || 'threat_policy_triggered',
          resource_type: 'incident',
          resource_id: incident.id,
          details: {
            triggered_rules_count: tiRules.length,
            policies: tiRules.map((r) => ({ policy_id: r.policy_id, name: r.policy_name, action_type: r.action_type }))
          }
        }, client);
      }

      const calculatedActions = this.calculateActions(incident, applicablePolicies);
      const createdActions = [];
      const seenActionKeys = new Set();

      for (const action of calculatedActions) {
        const indVal = action.metadata?.indicator_value;
        const actionKey = indVal
          ? `${action.action_type}:${indVal}`
          : `${action.action_type}:${JSON.stringify(action.target || {})}`;

        if (seenActionKeys.has(actionKey)) {
          // In-memory duplicate suppressed within batch
          await auditLog({
            organization_id: action.organization_id,
            user_id: null,
            actor_type: 'system_policy',
            action: AUDIT_ACTIONS.THREAT_ACTION_SUPPRESSED_DUPLICATE || 'threat_action_suppressed_duplicate',
            resource_type: 'response_action',
            resource_id: null,
            details: {
              incident_id: incident.id,
              action_type: action.action_type,
              indicator_value: indVal || null,
              reason: 'in_batch_duplicate'
            }
          }, client);
          continue;
        }
        seenActionKeys.add(actionKey);

        const created = await ResponseAction.create({
          organization_id: action.organization_id,
          incident_id: action.incident_id,
          policy_id: action.policy_id,
          action_type: action.action_type,
          action_mode: action.action_mode || 'shadow',
          status: 'proposed',
          target: action.target,
          metadata: action.metadata || {},
          scheduled_at: action.scheduled_at,
          requested_by_id: action.requested_by_id,
          target_device_id: action.target_device_id || null
        }, client);

        if (created && created._is_duplicate) {
          // Database / service level duplicate suppressed
          await auditLog({
            organization_id: action.organization_id,
            user_id: null,
            actor_type: 'system_policy',
            action: AUDIT_ACTIONS.THREAT_ACTION_SUPPRESSED_DUPLICATE || 'threat_action_suppressed_duplicate',
            resource_type: 'response_action',
            resource_id: created.id,
            details: {
              incident_id: incident.id,
              action_type: action.action_type,
              indicator_value: indVal || null,
              reason: 'active_action_already_exists'
            }
          }, client);
          continue;
        }

        if (created) {
          createdActions.push(created);

          await auditLog({
            organization_id: action.organization_id,
            user_id: null,
            actor_type: 'system_policy',
            action: 'action_proposed',
            resource_type: 'response_action',
            resource_id: created.id,
            details: {
              action_type: created.action_type,
              target: created.target,
              incident_id: incident.id,
              policy_id: created.policy_id
            }
          }, client);

          if (action.metadata?.indicator_value) {
            await auditLog({
              organization_id: action.organization_id,
              user_id: null,
              actor_type: 'system_policy',
              action: AUDIT_ACTIONS.THREAT_ACTION_PROPOSED || 'threat_action_proposed',
              resource_type: 'response_action',
              resource_id: created.id,
              details: {
                action_type: created.action_type,
                indicator_value: action.metadata.indicator_value,
                indicator_type: action.metadata.indicator_type,
                confidence_score: action.metadata.confidence_score,
                reputation_score: action.metadata.reputation_score,
                source_feed: action.metadata.source_feed,
                incident_id: incident.id,
                action_mode: created.action_mode
              }
            }, client);
          }

          // Hook into response_actions creation (Notification Service)
          const matchingPolicy = applicablePolicies.find((p) => p.policy_id === action.policy_id);
          notificationService.sendActionNotification(created, incident, matchingPolicy).catch((nErr) => {
            console.error('[NotificationService Hook Error]', nErr.message);
          });
        }
      }

      return createdActions;
    } catch (err) {
      console.error('[PolicyEngine Proposal Error]', err.message);
      return [];
    }
  }
}

module.exports = PolicyEngine;
