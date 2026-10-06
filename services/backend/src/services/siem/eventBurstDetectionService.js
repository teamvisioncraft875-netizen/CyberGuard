const { persistDetectionIncident } = require('../incidentService');
const streamingService = require('./streamingService');

/**
 * Event Burst Detection Service — Evaluates sliding window event velocity
 * to detect high-frequency telemetry floods, distributed brute force, and escalation bursts.
 *
 * Rules:
 * - B1: > 100 events from same source within 5 mins -> "Event Burst" alert
 * - B2: > 50 auth failures within 5 mins -> "Brute Force Attempt" incident (MITRE T1110)
 * - B3: > 20 privilege escalations within 10 mins -> "Privilege Escalation Campaign" incident (MITRE T1068)
 */
class EventBurstDetectionService {
  constructor() {
    this.B1_WINDOW_MS = 5 * 60 * 1000;  // 5 minutes
    this.B1_THRESHOLD = 100;

    this.B2_WINDOW_MS = 5 * 60 * 1000;  // 5 minutes
    this.B2_THRESHOLD = 50;

    this.B3_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
    this.B3_THRESHOLD = 20;

    // Sliding window stores: Map<key, { timestamps: number[], lastTriggered: number }>
    this.b1Store = new Map();
    this.b2Store = new Map();
    this.b3Store = new Map();

    // Periodic sweep every 60 seconds
    this.sweepInterval = setInterval(() => {
      this.evictStaleWindows();
    }, 60000);
    if (this.sweepInterval.unref) {
      this.sweepInterval.unref();
    }
  }

  /**
   * Helper to append timestamp and check threshold within sliding window with cooldown
   */
  _trackAndCheck(store, key, windowMs, threshold) {
    const now = Date.now();
    let entry = store.get(key);
    if (!entry) {
      entry = { timestamps: [], lastTriggered: 0 };
      store.set(key, entry);
    }

    // Prune entries older than sliding window
    const cutoff = now - windowMs;
    entry.timestamps = entry.timestamps.filter(t => t >= cutoff);
    entry.timestamps.push(now);

    // Limit array size to prevent unbounded memory growth
    if (entry.timestamps.length > threshold * 2) {
      entry.timestamps = entry.timestamps.slice(-threshold * 2);
    }

    // Check threshold and ensure cooldown of at least windowMs
    if (entry.timestamps.length > threshold) {
      if (now - entry.lastTriggered >= windowMs) {
        entry.lastTriggered = now;
        return { triggered: true, count: entry.timestamps.length };
      }
    }

    return { triggered: false, count: entry.timestamps.length };
  }

  /**
   * Identifies whether an event is an authentication failure
   */
  isAuthFailure(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);

    return (
      eventType === 'windows_logon_failure' ||
      eventType === 'linux_failed_login' ||
      action === 'login_failure' ||
      action === 'auth_failure' ||
      eventId === 4625 ||
      eventType.includes('failed_login') ||
      eventType.includes('logon_failure')
    );
  }

  /**
   * Identifies whether an event is a privilege escalation
   */
  isPrivilegeEscalation(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);
    const severity = String(event.severity || event.normalized_data?.severity || '').toLowerCase();

    return (
      eventType === 'windows_local_group_member_added' ||
      eventType === 'linux_privilege_escalation' ||
      action === 'privilege_escalation' ||
      eventId === 4732 ||
      (eventType === 'windows_security_group_member_added' && severity === 'high') ||
      (eventId === 4728 && severity === 'high')
    );
  }

  /**
   * Evaluates incoming event against burst rules
   */
  async processEvent(event, organizationId, client = null) {
    const startTime = process.hrtime.bigint();
    if (!event) return null;

    const orgId = organizationId || event.organization_id || event.organizationId;
    if (!orgId) return null;

    const norm = event.normalized_data || {};
    const sourceIdentifier = event.source_id || event.device_id || norm.source_ip || event.source_type || 'default';
    const triggeredIncidents = [];

    // --- RULE B1: > 100 events from same source within 5 minutes ---
    const b1Key = `${orgId}:b1:${sourceIdentifier}`;
    const b1Result = this._trackAndCheck(this.b1Store, b1Key, this.B1_WINDOW_MS, this.B1_THRESHOLD);
    if (b1Result.triggered) {
      try {
        const incidentPayload = {
          user: {
            id: event.user_id || null,
            organization_id: orgId,
            role: 'analyst',
            device_id: event.device_id || null
          },
          threatType: 'technical_threat',
          sourceType: 'siem',
          deviceId: event.device_id || null,
          mlResult: {
            risk_level: 'high',
            risk_score: 75,
            explanation: `Event Burst: High volume burst detected (${b1Result.count} events in 5 minutes) from source ${sourceIdentifier}. Potential telemetry flood, reconnaissance scan, or data exfiltration.`,
            signals: {
              source_id: sourceIdentifier,
              event_count: b1Result.count,
              window_minutes: 5,
              burst_type: 'source_volume',
              process_name: 'event_burst'
            },
            details: {
              rule_id: 'SIEM-BURST-VOLUME',
              process_name: 'event_burst',
              source_identifier: sourceIdentifier,
              burst_count: b1Result.count,
              window_ms: this.B1_WINDOW_MS
            }
          },
          recommendedActions: [
            'Audit event ingestion source for runaway telemetry loop or DDoS traffic',
            'Verify endpoint agent health and apply rate limiting at gateway',
            'Correlate burst timestamp with network firewall and egress flow logs'
          ]
        };

        const incident = await persistDetectionIncident(incidentPayload, client);
        streamingService.publishIncident(incident, orgId);
        triggeredIncidents.push({ rule_id: 'SIEM-BURST-VOLUME', incident });
      } catch (err) {
        console.warn('[EventBurst Warning] Failed to persist B1 burst incident:', err.message);
      }
    }

    // --- RULE B2: > 50 auth failures within 5 minutes ---
    if (this.isAuthFailure(event)) {
      const targetUser = norm.target_user || norm.user || event.user_id || 'unknown';
      const sourceIp = norm.source_ip || norm.ip_address || 'unknown';
      const b2Key = `${orgId}:b2:${targetUser}:${sourceIp}`;
      const b2Result = this._trackAndCheck(this.b2Store, b2Key, this.B2_WINDOW_MS, this.B2_THRESHOLD);
      if (b2Result.triggered) {
        try {
          const incidentPayload = {
            user: {
              id: event.user_id || null,
              organization_id: orgId,
              role: 'analyst',
              device_id: event.device_id || null
            },
            threatType: 'account_takeover',
            sourceType: 'siem',
            deviceId: event.device_id || null,
            mlResult: {
              risk_level: 'critical',
              risk_score: 92,
              explanation: `Brute Force Attempt: High frequency of authentication failures (${b2Result.count} failed logins in 5 minutes) targeting account ${targetUser} from source IP ${sourceIp}. MITRE ATT&CK T1110.`,
              signals: {
                target_user: targetUser,
                source_ip: sourceIp,
                failure_count: b2Result.count,
                window_minutes: 5,
                action: 'login_failure'
              },
              details: {
                rule_id: 'SIEM-BURST-BRUTE',
                mitre_technique: 'T1110',
                target_user: targetUser,
                source_ip: sourceIp,
                failure_count: b2Result.count
              }
            },
            recommendedActions: [
              'Enforce immediate temporary lock on targeted account',
              'Block originating IP address at perimeter firewall',
              'Enable mandatory multi-factor authentication prompt for subsequent sign-ins'
            ]
          };

          const incident = await persistDetectionIncident(incidentPayload, client);
          streamingService.publishIncident(incident, orgId);
          triggeredIncidents.push({ rule_id: 'SIEM-BURST-BRUTE', incident });
        } catch (err) {
          console.warn('[EventBurst Warning] Failed to persist B2 brute force incident:', err.message);
        }
      }
    }

    // --- RULE B3: > 20 privilege escalations within 10 minutes ---
    if (this.isPrivilegeEscalation(event)) {
      const targetHost = norm.target_host || norm.host || event.device_id || 'unknown';
      const targetUser = norm.target_user || norm.user || 'unknown';
      const b3Key = `${orgId}:b3:${targetHost}:${targetUser}`;
      const b3Result = this._trackAndCheck(this.b3Store, b3Key, this.B3_WINDOW_MS, this.B3_THRESHOLD);
      if (b3Result.triggered) {
        try {
          const incidentPayload = {
            user: {
              id: event.user_id || null,
              organization_id: orgId,
              role: 'analyst',
              device_id: event.device_id || null
            },
            threatType: 'account_takeover',
            sourceType: 'siem',
            deviceId: event.device_id || null,
            mlResult: {
              risk_level: 'critical',
              risk_score: 95,
              explanation: `Privilege Escalation Campaign: Rapid series of privilege escalations (${b3Result.count} attempts in 10 minutes) detected on host ${targetHost} by user ${targetUser}. MITRE ATT&CK T1068.`,
              signals: {
                target_host: targetHost,
                target_user: targetUser,
                escalation_count: b3Result.count,
                window_minutes: 10,
                action: 'privilege_escalation'
              },
              details: {
                rule_id: 'SIEM-BURST-PRV',
                mitre_technique: 'T1068',
                target_host: targetHost,
                target_user: targetUser,
                escalation_count: b3Result.count
              }
            },
            recommendedActions: [
              'Quarantine compromised host from the enterprise network',
              'Audit active directory and local administrator group memberships',
              'Revoke Kerberos ticket-granting tickets (TGT) for affected accounts'
            ]
          };

          const incident = await persistDetectionIncident(incidentPayload, client);
          streamingService.publishIncident(incident, orgId);
          triggeredIncidents.push({ rule_id: 'SIEM-BURST-PRV', incident });
        } catch (err) {
          console.warn('[EventBurst Warning] Failed to persist B3 privilege escalation incident:', err.message);
        }
      }
    }

    const durationMs = Number(process.hrtime.bigint() - startTime) / 1e6;
    return {
      triggered_incidents: triggeredIncidents,
      duration_ms: durationMs
    };
  }

  /**
   * Processes a batch of normalized events through burst detection
   */
  async processBatch(events, organizationId, client = null) {
    if (!Array.isArray(events) || events.length === 0) return [];
    const results = [];
    for (const ev of events) {
      const res = await this.processEvent(ev, organizationId, client);
      if (res && res.triggered_incidents.length > 0) {
        results.push(...res.triggered_incidents);
      }
    }
    return results;
  }

  /**
   * Evicts expired windows and reclaim memory
   */
  evictStaleWindows() {
    const now = Date.now();

    const pruneStore = (store, windowMs) => {
      const cutoff = now - windowMs;
      for (const [key, entry] of store.entries()) {
        entry.timestamps = entry.timestamps.filter(t => t >= cutoff);
        if (entry.timestamps.length === 0 && now - entry.lastTriggered > windowMs) {
          store.delete(key);
        }
      }
    };

    pruneStore(this.b1Store, this.B1_WINDOW_MS);
    pruneStore(this.b2Store, this.B2_WINDOW_MS);
    pruneStore(this.b3Store, this.B3_WINDOW_MS);
  }

  /**
   * Resets internal sliding window state (for test isolation)
   */
  reset() {
    this.b1Store.clear();
    this.b2Store.clear();
    this.b3Store.clear();
  }
}

// Singleton export
const eventBurstDetectionService = new EventBurstDetectionService();
module.exports = eventBurstDetectionService;
