const { persistDetectionIncident } = require('../incidentService');
const SiemDetectionRule = require('../../models/SiemDetectionRule');
const SiemDetectionHit = require('../../models/SiemDetectionHit');
const SiemAlert = require('../../models/SiemAlert');
const streamingService = require('./streamingService');
const { log: auditLog, AUDIT_ACTIONS } = require('../auditService');

/**
 * Correlation Rule Engine — Real-time multi-event correlation and threat detection platform
 *
 * Implements:
 * - RULE 1: Brute Force Detection (>= 10 failed logins, same user, within 5 min) -> T1110
 * - RULE 2: Password Spray (>= 10 different users, same source IP, within 15 min) -> T1110.003
 * - RULE 3: Privilege Escalation (successful login followed by admin group addition, same user, within 30 min) -> T1078/T1068
 * - RULE 4: PowerShell Abuse (powershell.exe AND encodedcommand | downloadstring | iex) -> T1059
 * - RULE 5: Audit Log Clearing (Windows Event ID 1102) -> T1070
 * - RULE 6: Persistence Registry Modification (Run Keys, Services, Startup Entries) -> T1547
 * - RULE 7: Suspicious Beaconing (repeated network connections to same destination >= 20 times within 1 hour) -> T1071
 */
class CorrelationRuleEngine {
  constructor() {
    this.WINDOWS = {
      FIVE_MIN: 5 * 60 * 1000,
      FIFTEEN_MIN: 15 * 60 * 1000,
      THIRTY_MIN: 30 * 60 * 1000,
      ONE_HOUR: 60 * 60 * 1000
    };

    // In-memory sliding window stores for stateful correlation rules
    // Map<key, { items: Array<{ timestamp: number, eventId: string, data: any }>, lastTriggered: number }>
    this.bruteForceStore = new Map();     // Rule 1: user failed logins (5m)
    this.passwordSprayStore = new Map();   // Rule 2: source_ip distinct users (15m)
    this.privEscStore = new Map();         // Rule 3: user login timestamp (30m)
    this.beaconStore = new Map();          // Rule 7: destination connection counts (1h)

    // Periodic sweep every 60 seconds to evict expired state
    this.sweepInterval = setInterval(() => {
      this.evictStaleWindows();
    }, 60000);
    if (this.sweepInterval.unref) {
      this.sweepInterval.unref();
    }
  }

  // =========================================================================
  // NORMALIZATION & EXTRACTION HELPERS
  // =========================================================================

  _extractUser(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.target_user || norm.user || norm.username || event.user_id || norm.details?.user || norm.details?.username || norm.details?.TargetUserName;
    if (!candidate) return null;
    const clean = String(candidate).trim();
    if (['-', '', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'].includes(clean)) return null;
    return clean;
  }

  _extractSourceIp(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.source_ip || norm.ip_address || norm.details?.source_ip || norm.details?.IpAddress;
    if (!candidate) return null;
    const clean = String(candidate).trim();
    if (['-', '', '127.0.0.1', '::1'].includes(clean)) return null;
    return clean;
  }

  _extractDest(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.dest_ip || norm.target_host || norm.host || norm.details?.dest_ip || norm.details?.DestinationIp;
    if (!candidate) return null;
    return String(candidate).trim();
  }

  _isFailedLogin(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);
    return (
      eventType === 'windows_logon_failure' ||
      eventType === 'linux_failed_login' ||
      action === 'login_failure' ||
      eventId === 4625 ||
      eventType.includes('failed_login')
    );
  }

  _isSuccessfulLogin(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);
    return (
      eventType === 'windows_logon_success' ||
      eventType === 'linux_ssh_login' ||
      action === 'login' ||
      action === 'logon' ||
      eventId === 4624
    );
  }

  _isAdminGroupAddition(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);
    return (
      eventType === 'windows_local_group_member_added' ||
      eventType === 'windows_security_group_member_added' ||
      eventType === 'linux_privilege_escalation' ||
      action === 'privilege_escalation' ||
      action === 'group_member_added' ||
      eventId === 4732 ||
      eventId === 4728
    );
  }

  // =========================================================================
  // CORE ENGINE EVALUATION
  // =========================================================================

  /**
   * Evaluates a single event against all active correlation rules.
   */
  async evaluateEvent(event, organizationId, client = null) {
    if (!event) return [];
    const orgId = organizationId || event.organization_id || event.organizationId;
    if (!orgId) return [];

    const hits = [];

    // Evaluate Rule 1: Brute Force Detection
    const hit1 = await this._evaluateRule1BruteForce(event, orgId, client);
    if (hit1) hits.push(hit1);

    // Evaluate Rule 2: Password Spraying
    const hit2 = await this._evaluateRule2PasswordSpray(event, orgId, client);
    if (hit2) hits.push(hit2);

    // Evaluate Rule 3: Privilege Escalation Sequence
    const hit3 = await this._evaluateRule3PrivilegeEscalation(event, orgId, client);
    if (hit3) hits.push(hit3);

    // Evaluate Rule 4: PowerShell Abuse Pattern
    const hit4 = await this._evaluateRule4PowerShellAbuse(event, orgId, client);
    if (hit4) hits.push(hit4);

    // Evaluate Rule 5: Audit Log Clearing Single Event
    const hit5 = await this._evaluateRule5AuditLogClearing(event, orgId, client);
    if (hit5) hits.push(hit5);

    // Evaluate Rule 6: Persistence Registry Modification
    const hit6 = await this._evaluateRule6PersistenceRegistry(event, orgId, client);
    if (hit6) hits.push(hit6);

    // Evaluate Rule 7: Suspicious Beaconing
    const hit7 = await this._evaluateRule7Beaconing(event, orgId, client);
    if (hit7) hits.push(hit7);

    return hits;
  }

  /**
   * Evaluates a batch of normalized events sequentially.
   */
  async evaluateBatch(events, organizationId, client = null) {
    if (!Array.isArray(events) || events.length === 0) return [];
    const allHits = [];
    for (const ev of events) {
      const hits = await this.evaluateEvent(ev, organizationId, client);
      if (hits.length > 0) {
        allHits.push(...hits);
      }
    }
    return allHits;
  }

  /**
   * Evaluates a collection of events within an explicit time window.
   */
  async evaluateWindow(events, windowMinutes = 15, organizationId, client = null) {
    if (!Array.isArray(events) || events.length === 0) return [];
    const windowMs = (parseInt(windowMinutes, 10) || 15) * 60 * 1000;
    const cutoff = Date.now() - windowMs;
    const filtered = events.filter(e => {
      const t = e.timestamp || e.event_timestamp || e.created_at;
      return t ? new Date(t).getTime() >= cutoff : true;
    });
    return this.evaluateBatch(filtered, organizationId, client);
  }

  // =========================================================================
  // RULE IMPLEMENTATIONS
  // =========================================================================

  /**
   * RULE 1: Brute Force Detection (>= 10 failed logins, same user, within 5 min) -> T1110
   */
  async _evaluateRule1BruteForce(event, orgId, client) {
    if (!this._isFailedLogin(event)) return null;

    const user = this._extractUser(event);
    if (!user) return null;

    const key = `${orgId}:r1:${user.toLowerCase()}`;
    const now = Date.now();
    let entry = this.bruteForceStore.get(key);
    if (!entry) {
      entry = { items: [], lastTriggered: 0 };
      this.bruteForceStore.set(key, entry);
    }

    const cutoff = now - this.WINDOWS.FIVE_MIN;
    while (entry.items.length > 0 && entry.items[0].timestamp < cutoff) {
      entry.items.shift();
    }
    entry.items.push({ timestamp: now, eventId: event.id || event.event_id || null, data: event });

    if (entry.items.length >= 10 && (now - entry.lastTriggered >= this.WINDOWS.FIVE_MIN)) {
      entry.lastTriggered = now;
      const eventIds = entry.items.map(i => i.eventId).filter(Boolean);

      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000101',
        ruleCode: 'SIEM-RULE-BRUTE',
        ruleName: 'Brute Force Detection',
        threatType: 'account_takeover',
        riskLevel: 'high',
        riskScore: 78,
        mitreTechnique: 'T1110',
        explanation: `Brute Force Detection: >= 10 failed login attempts (${entry.items.length} attempts) detected for user "${user}" within 5 minutes. MITRE ATT&CK T1110.`,
        signals: {
          target_user: user,
          failure_count: entry.items.length,
          window_minutes: 5,
          process_name: 'brute_force'
        },
        eventIds,
        client
      });
    }
    return null;
  }

  /**
   * RULE 2: Password Spray (>= 10 different users, same source IP, within 15 min) -> T1110.003
   */
  async _evaluateRule2PasswordSpray(event, orgId, client) {
    if (!this._isFailedLogin(event) && !this._isSuccessfulLogin(event)) return null;

    const sourceIp = this._extractSourceIp(event);
    const user = this._extractUser(event);
    if (!sourceIp || !user) return null;

    const key = `${orgId}:r2:${sourceIp}`;
    const now = Date.now();
    let entry = this.passwordSprayStore.get(key);
    if (!entry) {
      entry = { queue: [], userCounts: new Map(), lastTriggered: 0 };
      this.passwordSprayStore.set(key, entry);
    }

    const cutoff = now - this.WINDOWS.FIFTEEN_MIN;
    while (entry.queue.length > 0 && entry.queue[0].timestamp < cutoff) {
      const expired = entry.queue.shift();
      const current = entry.userCounts.get(expired.user) || 1;
      if (current <= 1) {
        entry.userCounts.delete(expired.user);
      } else {
        entry.userCounts.set(expired.user, current - 1);
      }
    }

    const normalizedUser = user.toLowerCase();
    entry.queue.push({ timestamp: now, user: normalizedUser, eventId: event.id || null });
    entry.userCounts.set(normalizedUser, (entry.userCounts.get(normalizedUser) || 0) + 1);

    const distinctUsersCount = entry.userCounts.size;

    if (distinctUsersCount >= 10 && (now - entry.lastTriggered >= this.WINDOWS.FIFTEEN_MIN)) {
      entry.lastTriggered = now;
      const eventIds = entry.queue.map(i => i.eventId).filter(Boolean);
      const distinctUsers = Array.from(entry.userCounts.keys());

      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000102',
        ruleCode: 'SIEM-RULE-SPRAY',
        ruleName: 'Password Spraying',
        threatType: 'account_takeover',
        riskLevel: 'high',
        riskScore: 78,
        mitreTechnique: 'T1110.003',
        explanation: `Password Spray: Authentication attempts targeting >= 10 different accounts (${distinctUsers.length} accounts: ${distinctUsers.slice(0, 5).join(', ')}...) originating from source IP ${sourceIp} within 15 minutes. MITRE ATT&CK T1110.003.`,
        signals: {
          source_ip: sourceIp,
          targeted_users_count: distinctUsers.length,
          targeted_users: distinctUsers.join(','),
          window_minutes: 15,
          process_name: 'password_spray'
        },
        eventIds,
        client
      });
    }
    return null;
  }

  /**
   * RULE 3: Privilege Escalation (successful login followed by admin group addition, same user, within 30 min) -> T1078/T1068
   */
  async _evaluateRule3PrivilegeEscalation(event, orgId, client) {
    const user = this._extractUser(event);
    if (!user) return null;

    const key = `${orgId}:r3:${user.toLowerCase()}`;
    const now = Date.now();

    // Stage 1: Record successful login
    if (this._isSuccessfulLogin(event)) {
      let entry = this.privEscStore.get(key);
      if (!entry) {
        entry = { loginTimestamp: now, loginEventId: event.id || null };
      } else {
        entry.loginTimestamp = now;
        entry.loginEventId = event.id || null;
      }
      this.privEscStore.set(key, entry);
      return null;
    }

    // Stage 2: Admin group addition
    if (this._isAdminGroupAddition(event)) {
      const entry = this.privEscStore.get(key);
      if (entry && (now - entry.loginTimestamp <= this.WINDOWS.THIRTY_MIN)) {
        // Trigger matched sequence!
        this.privEscStore.delete(key); // Clear matched sequence
        const eventIds = [entry.loginEventId, event.id || null].filter(Boolean);

        return this._recordHitAndIncident({
          organizationId: orgId,
          ruleId: '00000000-0000-0000-0000-000000000103',
          ruleCode: 'SIEM-RULE-PRV',
          ruleName: 'Privilege Escalation Sequence',
          threatType: 'account_takeover',
          riskLevel: 'critical',
          riskScore: 92,
          mitreTechnique: 'T1068',
          explanation: `Privilege Escalation: User "${user}" successfully logged in and subsequently added to an administrative security group within 30 minutes. Sequence indicates potential compromised credential elevation. MITRE ATT&CK T1078 & T1068.`,
          signals: {
            target_user: user,
            action: 'privilege_escalation',
            window_minutes: 30,
            process_name: 'privilege_escalation'
          },
          eventIds,
          client
        });
      }
    }
    return null;
  }

  /**
   * RULE 4: PowerShell Abuse (powershell.exe AND encodedcommand | downloadstring | iex) -> T1059
   */
  async _evaluateRule4PowerShellAbuse(event, orgId, client) {
    const norm = event.normalized_data || {};
    const processName = String(norm.process_name || norm.details?.Image || norm.details?.process_name || '').toLowerCase();
    const commandLine = String(norm.command_line || norm.details?.CommandLine || norm.details?.command_line || '').toLowerCase();

    if (!processName.includes('powershell') && !commandLine.includes('powershell')) {
      return null;
    }

    const hasSuspiciousParam =
      commandLine.includes('encodedcommand') ||
      commandLine.includes('-e ') ||
      commandLine.includes('-enc ') ||
      commandLine.includes('downloadstring') ||
      commandLine.includes('iex') ||
      commandLine.includes('invoke-expression');

    if (hasSuspiciousParam) {
      const eventIds = event.id ? [event.id] : [];
      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000104',
        ruleCode: 'SIEM-RULE-PWSH',
        ruleName: 'PowerShell Obfuscation & Download Abuse',
        threatType: 'technical_threat',
        riskLevel: 'high',
        riskScore: 78,
        mitreTechnique: 'T1059',
        explanation: `PowerShell Abuse: Suspicious PowerShell execution with encoded or remote download parameters detected: "${commandLine}". MITRE ATT&CK T1059.`,
        signals: {
          process_name: 'powershell.exe',
          command_line: commandLine,
          rule_id: 'SIEM-RULE-PWSH'
        },
        eventIds,
        client
      });
    }
    return null;
  }

  /**
   * RULE 5: Audit Log Clearing (Windows Event ID 1102) -> T1070
   */
  async _evaluateRule5AuditLogClearing(event, orgId, client) {
    const eventId = String(event.event_id || event.normalized_data?.event_id || '');
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();

    if (eventId === '1102' || eventType === 'windows_audit_log_cleared' || action === 'audit_log_cleared') {
      const targetHost = event.normalized_data?.target_host || event.device_id || 'unknown';
      const eventIds = event.id ? [event.id] : [];

      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000105',
        ruleCode: 'SIEM-RULE-LOGCLEAR',
        ruleName: 'Audit Log Clearing Defense Evasion',
        threatType: 'technical_threat',
        riskLevel: 'critical',
        riskScore: 95,
        mitreTechnique: 'T1070',
        explanation: `Audit Log Clearing: Windows Security Event ID 1102 detected on host ${targetHost}. Adversary cleared the security audit log to impair defensive visibility. MITRE ATT&CK T1070.`,
        signals: {
          event_id: '1102',
          target_host: targetHost,
          action: 'audit_log_cleared',
          process_name: 'audit_log_cleared'
        },
        eventIds,
        client
      });
    }
    return null;
  }

  /**
   * RULE 6: Persistence Registry Modification (Run Keys, Services, Startup Entries) -> T1547
   */
  async _evaluateRule6PersistenceRegistry(event, orgId, client) {
    const norm = event.normalized_data || {};
    const eventType = String(event.event_type || '').toLowerCase();
    const regKey = String(norm.registry_key || norm.target_object || norm.details?.TargetObject || norm.details?.registry_key || '');

    const isRegistryEvent =
      eventType.includes('registry') ||
      eventType.includes('reg') ||
      [12, 13, 14].includes(Number(event.event_id || norm.event_id));

    if (!isRegistryEvent && !regKey) return null;

    const lowerKey = regKey.toLowerCase();
    const isPersistencePath =
      lowerKey.includes('\\run') ||
      lowerKey.includes('\\runonce') ||
      lowerKey.includes('\\services\\') ||
      lowerKey.includes('\\startup') ||
      lowerKey.includes('\\runservices');

    if (isPersistencePath) {
      const eventIds = event.id ? [event.id] : [];
      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000106',
        ruleCode: 'SIEM-RULE-REG',
        ruleName: 'Persistence Registry Modification',
        threatType: 'technical_threat',
        riskLevel: 'high',
        riskScore: 78,
        mitreTechnique: 'T1547',
        explanation: `Persistence Registry Modification: Suspicious registry modification detected at persistence location "${regKey}". MITRE ATT&CK T1547.`,
        signals: {
          registry_key: regKey,
          process_name: 'registry_persistence',
          rule_id: 'SIEM-RULE-REG'
        },
        eventIds,
        client
      });
    }
    return null;
  }

  /**
   * RULE 7: Suspicious Beaconing (repeated network connections to same destination >= 20 times within 1 hour) -> T1071
   */
  async _evaluateRule7Beaconing(event, orgId, client) {
    const norm = event.normalized_data || {};
    const eventType = String(event.event_type || '').toLowerCase();

    if (!eventType.includes('network') && !norm.dest_ip && !norm.dest_port) {
      return null;
    }

    const dest = this._extractDest(event);
    if (!dest) return null;

    const key = `${orgId}:r7:${dest}`;
    const now = Date.now();
    let entry = this.beaconStore.get(key);
    if (!entry) {
      entry = { items: [], lastTriggered: 0 };
      this.beaconStore.set(key, entry);
    }

    const cutoff = now - this.WINDOWS.ONE_HOUR;
    while (entry.items.length > 0 && entry.items[0].timestamp < cutoff) {
      entry.items.shift();
    }
    entry.items.push({ timestamp: now, eventId: event.id || null });

    if (entry.items.length >= 20 && (now - entry.lastTriggered >= this.WINDOWS.ONE_HOUR)) {
      entry.lastTriggered = now;
      const eventIds = entry.items.map(i => i.eventId).filter(Boolean);

      return this._recordHitAndIncident({
        organizationId: orgId,
        ruleId: '00000000-0000-0000-0000-000000000107',
        ruleCode: 'SIEM-RULE-BEACON',
        ruleName: 'Suspicious C2 Beaconing',
        threatType: 'technical_threat',
        riskLevel: 'medium',
        riskScore: 50,
        mitreTechnique: 'T1071',
        explanation: `Suspicious Beaconing: Repeated network connections (>= 20 times: ${entry.items.length} outbound connections) to destination ${dest} within 1 hour. MITRE ATT&CK T1071.`,
        signals: {
          dest_ip: dest,
          connection_count: entry.items.length,
          window_minutes: 60,
          process_name: 'network_beaconing'
        },
        eventIds,
        client
      });
    }
    return null;
  }



  // =========================================================================
  // PERSISTENCE & PIPELINE DISPATCH
  // =========================================================================

  /**
   * Creates incident through persistDetectionIncident and stores detection hit.
   */
  async _recordHitAndIncident({
    organizationId,
    ruleId,
    ruleCode,
    ruleName,
    threatType,
    riskLevel,
    riskScore,
    mitreTechnique,
    explanation,
    signals,
    eventIds,
    client
  }) {
    // 1. Dispatch into standard incident pipeline
    const incidentPayload = {
      user: {
        organization_id: organizationId,
        role: 'analyst'
      },
      threatType,
      sourceType: 'siem',
      mlResult: {
        risk_level: riskLevel,
        risk_score: riskScore,
        explanation,
        signals: {
          ...signals,
          rule_id: ruleCode,
          rule_name: ruleName
        },
        details: {
          rule_id: ruleCode,
          rule_uuid: ruleId,
          mitre_technique: mitreTechnique,
          correlated_event_count: eventIds.length
        }
      },
      recommendedActions: [
        'Investigate matched security events across telemetry window',
        'Verify host and user authorization status',
        'Apply automated network/credential containment policies'
      ]
    };

    let incident = null;
    try {
      incident = await persistDetectionIncident(incidentPayload, client);
    } catch (incErr) {
      console.warn(`[CorrelationRuleEngine Warning] Failed to persist incident for rule ${ruleCode}:`, incErr.message);
    }

    // 2. Store detection hit record in siem_detection_hits
    let hit = null;
    try {
      hit = await SiemDetectionHit.create({
        organization_id: organizationId,
        rule_id: ruleId,
        incident_id: incident?.id || null,
        event_ids: eventIds,
        matched_at: new Date(),
        confidence_score: 1.0,
        metadata: {
          rule_code: ruleCode,
          rule_name: ruleName,
          mitre_technique: mitreTechnique,
          event_count: eventIds.length
        }
      }, client);
    } catch (hitErr) {
      console.warn(`[CorrelationRuleEngine Warning] Failed to create detection hit record:`, hitErr.message);
    }

    // 3. Create SIEM Alert for SOC lifecycle management (Phase 3)
    let alert = null;
    try {
      alert = await SiemAlert.create({
        organization_id: organizationId,
        hit_id: hit ? hit.id : null,
        incident_id: incident ? incident.id : null,
        rule_id: ruleId,
        title: ruleName,
        severity: riskLevel,
        status: 'new',
        mitre_technique: mitreTechnique,
        source_type: 'siem',
        rule_code: ruleCode,
        metadata: {
          explanation,
          event_count: eventIds.length
        }
      }, client);
    } catch (alertErr) {
      console.warn(`[CorrelationRuleEngine Warning] Failed to create alert record:`, alertErr.message);
    }

    // 4. Record Audit Log
    try {
      await auditLog({
        organization_id: organizationId,
        actor_type: 'system_guard',
        action: AUDIT_ACTIONS.SIEM_DETECTION_TRIGGERED,
        resource_type: 'siem_detection_hit',
        resource_id: hit ? hit.id : null,
        details: {
          rule_id: ruleId,
          rule_code: ruleCode,
          incident_id: incident?.id || null,
          alert_id: alert?.id || null,
          event_count: eventIds.length
        }
      }, client);
    } catch (auditErr) {
      // Non-critical audit error
    }

    // 5. Publish real-time notifications
    try {
      if (incident) {
        streamingService.publishIncident(incident, organizationId);
      }
      if (hit) {
        streamingService.publishDetection(hit, organizationId);
      }
      if (alert) {
        streamingService.publishAlertUpdate(alert, organizationId);
      }
    } catch (streamErr) {
      // Non-critical streaming error
    }

    return {
      rule_id: ruleId,
      rule_code: ruleCode,
      rule_name: ruleName,
      hit,
      incident,
      alert
    };
  }

  /**
   * Periodic eviction of stale sliding windows
   */
  evictStaleWindows() {
    const now = Date.now();

    const pruneItems = (store, windowMs) => {
      const cutoff = now - windowMs;
      for (const [k, v] of store.entries()) {
        if (v.items) {
          while (v.items.length > 0 && v.items[0].timestamp < cutoff) {
            v.items.shift();
          }
          if (v.items.length === 0 && now - v.lastTriggered > windowMs) {
            store.delete(k);
          }
        }
      }
    };

    pruneItems(this.bruteForceStore, this.WINDOWS.FIVE_MIN);
    pruneItems(this.beaconStore, this.WINDOWS.ONE_HOUR);

    // Prune password spray with userCounts map
    const sprayCutoff = now - this.WINDOWS.FIFTEEN_MIN;
    for (const [k, v] of this.passwordSprayStore.entries()) {
      if (v.queue) {
        while (v.queue.length > 0 && v.queue[0].timestamp < sprayCutoff) {
          const expired = v.queue.shift();
          const c = (v.userCounts.get(expired.user) || 1) - 1;
          if (c <= 0) v.userCounts.delete(expired.user);
          else v.userCounts.set(expired.user, c);
        }
        if (v.queue.length === 0 && now - v.lastTriggered > this.WINDOWS.FIFTEEN_MIN) {
          this.passwordSprayStore.delete(k);
        }
      }
    }

    // Prune priv esc
    for (const [k, v] of this.privEscStore.entries()) {
      if (v.loginTimestamp && now - v.loginTimestamp > this.WINDOWS.THIRTY_MIN) {
        this.privEscStore.delete(k);
      }
    }
  }

  /**
   * Resets in-memory sliding window state (for test isolation)
   */
  reset() {
    this.bruteForceStore.clear();
    this.passwordSprayStore.clear();
    this.privEscStore.clear();
    this.beaconStore.clear();
  }
}

// Singleton export
const correlationRuleEngine = new CorrelationRuleEngine();
module.exports = correlationRuleEngine;
