const { persistDetectionIncident } = require('../incidentService');
const streamingService = require('./streamingService');

/**
 * Lateral Movement Detection Service — Identifies cross-host hopping,
 * anomalous user dispersion, and single-source multi-host credential reuse.
 *
 * Rules:
 * - LM1: Same user accesses 3+ devices within 15 mins -> "Potential Lateral Movement" (MITRE T1021)
 * - LM2: Same source IP authenticates to multiple hosts within 10 mins -> "Credential Reuse Activity" (MITRE T1078)
 */
class LateralMovementService {
  constructor() {
    this.LM1_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
    this.LM1_THRESHOLD = 3;              // 3+ devices

    this.LM2_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
    this.LM2_THRESHOLD = 2;              // multiple hosts (>= 2)

    // Sliding window stores: Map<key, { accesses: Array<{ timestamp: number, host: string }>, lastTriggered: number }>
    this.lm1Store = new Map();
    this.lm2Store = new Map();

    // Periodic sweep every 60 seconds
    this.sweepInterval = setInterval(() => {
      this.evictStaleWindows();
    }, 60000);
    if (this.sweepInterval.unref) {
      this.sweepInterval.unref();
    }
  }

  /**
   * Helper to append host access and check distinct hosts within sliding window with cooldown
   */
  _trackAndCheckHosts(store, key, host, windowMs, threshold) {
    if (!host) return { triggered: false, distinctHosts: [] };

    const now = Date.now();
    let entry = store.get(key);
    if (!entry) {
      entry = { accesses: [], lastTriggered: 0 };
      store.set(key, entry);
    }

    const cutoff = now - windowMs;
    entry.accesses = entry.accesses.filter(a => a.timestamp >= cutoff);
    entry.accesses.push({ timestamp: now, host: String(host).toLowerCase().trim() });

    // Limit array size to prevent unbounded memory growth
    if (entry.accesses.length > threshold * 5) {
      entry.accesses = entry.accesses.slice(-threshold * 5);
    }

    const distinctHosts = Array.from(new Set(entry.accesses.map(a => a.host)));

    if (distinctHosts.length >= threshold) {
      if (now - entry.lastTriggered >= windowMs) {
        entry.lastTriggered = now;
        return { triggered: true, distinctHosts };
      }
    }

    return { triggered: false, distinctHosts };
  }

  /**
   * Extracts target user from normalized event
   */
  _extractUser(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.target_user || norm.user || norm.username || event.user_id || norm.details?.user || norm.details?.username;
    if (!candidate) return null;
    const clean = String(candidate).trim();
    if (['-'].includes(clean)) return null;
    return clean;
  }

  /**
   * Extracts target device or host from normalized event
   */
  _extractHost(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.target_host || norm.host || event.device_id || norm.dest_ip || norm.device_name || norm.details?.host || norm.details?.computer_name;
    if (!candidate) return null;
    const clean = String(candidate).trim();
    if (['-'].includes(clean)) return null;
    return clean;
  }

  /**
   * Extracts source IP from normalized event
   */
  _extractSourceIp(event) {
    const norm = event.normalized_data || {};
    const candidate = norm.source_ip || norm.ip_address || norm.details?.source_ip;
    if (!candidate) return null;
    const clean = String(candidate).trim();
    if (['-'].includes(clean)) return null;
    return clean;
  }

  /**
   * Checks whether event is an authentication or logon attempt
   */
  _isAuthEvent(event) {
    const eventType = String(event.event_type || '').toLowerCase();
    const action = String(event.normalized_data?.action || event.action || '').toLowerCase();
    const eventId = Number(event.event_id || event.normalized_data?.event_id);

    return (
      eventType.includes('logon') ||
      eventType.includes('login') ||
      eventType.includes('auth') ||
      action.includes('logon') ||
      action.includes('login') ||
      action.includes('auth') ||
      eventId === 4624 ||
      eventId === 4625
    );
  }

  /**
   * Evaluates incoming event against lateral movement rules
   */
  async processEvent(event, organizationId, client = null) {
    const startTime = process.hrtime.bigint();
    if (!event) return null;

    const orgId = organizationId || event.organization_id || event.organizationId;
    if (!orgId) return null;

    const user = this._extractUser(event);
    const host = this._extractHost(event);
    const sourceIp = this._extractSourceIp(event);
    const triggeredIncidents = [];

    // --- RULE LM1: Same user accesses 3+ devices within 15 minutes ---
    if (user && host) {
      const lm1Key = `${orgId}:lm1:${user.toLowerCase()}`;
      const lm1Result = this._trackAndCheckHosts(this.lm1Store, lm1Key, host, this.LM1_WINDOW_MS, this.LM1_THRESHOLD);
      if (lm1Result.triggered) {
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
              risk_level: 'critical',
              risk_score: 90,
              explanation: `Potential Lateral Movement: User ${user} accessed ${lm1Result.distinctHosts.length} distinct devices (${lm1Result.distinctHosts.join(', ')}) within 15 minutes. Potential remote service exploitation or credential pivot. MITRE ATT&CK T1021.`,
              signals: {
                target_user: user,
                accessed_hosts: lm1Result.distinctHosts.join(','),
                host_count: lm1Result.distinctHosts.length,
                window_minutes: 15,
                rule_name: 'lateral_movement',
                process_name: 'lateral_movement'
              },
              details: {
                rule_id: 'SIEM-LM-DEVICE',
                process_name: 'lateral_movement',
                mitre_technique: 'T1021',
                target_user: user,
                distinct_hosts: lm1Result.distinctHosts,
                window_ms: this.LM1_WINDOW_MS
              }
            },
            recommendedActions: [
              'Isolate accessed workstations and check for active SMB/RDP sessions',
              'Terminate active Kerberos / NTLM authentication tickets for user',
              'Examine process creation events on all pivot target endpoints'
            ]
          };

          const incident = await persistDetectionIncident(incidentPayload, client);
          streamingService.publishIncident(incident, orgId);
          triggeredIncidents.push({ rule_id: 'SIEM-LM-DEVICE', incident });
        } catch (err) {
          console.warn('[LateralMovement Warning] Failed to persist LM1 incident:', err.message);
        }
      }
    }

    // --- RULE LM2: Same source IP authenticates to multiple hosts within 10 minutes ---
    if (sourceIp && host && this._isAuthEvent(event)) {
      const lm2Key = `${orgId}:lm2:${sourceIp.toLowerCase()}`;
      const lm2Result = this._trackAndCheckHosts(this.lm2Store, lm2Key, host, this.LM2_WINDOW_MS, this.LM2_THRESHOLD);
      if (lm2Result.triggered) {
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
              risk_level: 'high',
              risk_score: 75,
              explanation: `Credential Reuse Activity: Source IP ${sourceIp} authenticated to multiple distinct hosts (${lm2Result.distinctHosts.join(', ')}) within 10 minutes. Potential credential spraying, pass-the-hash, or automated pivot. MITRE ATT&CK T1078.`,
              signals: {
                source_ip: sourceIp,
                targeted_hosts: lm2Result.distinctHosts.join(','),
                host_count: lm2Result.distinctHosts.length,
                window_minutes: 10,
                rule_name: 'credential_reuse'
              },
              details: {
                rule_id: 'SIEM-LM-IP',
                mitre_technique: 'T1078',
                source_ip: sourceIp,
                distinct_hosts: lm2Result.distinctHosts,
                window_ms: this.LM2_WINDOW_MS
              }
            },
            recommendedActions: [
              'Apply immediate perimeter firewall block on source IP',
              'Force password reset across all accounts successfully accessed from source IP',
              'Review authentication protocols (NTLM vs Kerberos) and enforce Kerberos armoring'
            ]
          };

          const incident = await persistDetectionIncident(incidentPayload, client);
          streamingService.publishIncident(incident, orgId);
          triggeredIncidents.push({ rule_id: 'SIEM-LM-IP', incident });
        } catch (err) {
          console.warn('[LateralMovement Warning] Failed to persist LM2 incident:', err.message);
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
   * Processes a batch of normalized events through lateral movement detection
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
   * Evicts expired windows and reclaims memory
   */
  evictStaleWindows() {
    const now = Date.now();

    const pruneStore = (store, windowMs) => {
      const cutoff = now - windowMs;
      for (const [key, entry] of store.entries()) {
        entry.accesses = entry.accesses.filter(a => a.timestamp >= cutoff);
        if (entry.accesses.length === 0 && now - entry.lastTriggered > windowMs) {
          store.delete(key);
        }
      }
    };

    pruneStore(this.lm1Store, this.LM1_WINDOW_MS);
    pruneStore(this.lm2Store, this.LM2_WINDOW_MS);
  }

  /**
   * Resets internal sliding window state (for test isolation)
   */
  reset() {
    this.lm1Store.clear();
    this.lm2Store.clear();
  }
}

// Singleton export
const lateralMovementService = new LateralMovementService();
module.exports = lateralMovementService;
