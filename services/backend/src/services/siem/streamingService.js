const liveMetricsService = require('./liveMetricsService');

/**
 * Real-Time Event Streaming Service — In-memory, tenant-isolated pub/sub engine
 * for streaming SIEM security events and incident updates to SOC dashboards.
 */
class StreamingService {
  constructor() {
    this.SUPPORTED_STREAMS = new Set(['windows', 'sysmon', 'linux', 'agent', 'custom', 'all']);
    this.MAX_CONCURRENT_STREAMS_PER_ORG = 10;

    // Map<organizationId, Map<subscriptionId, { callback, streamTypes, userId, createdAt }>>
    this.subscribers = new Map();
  }

  /**
   * Registers a new subscriber for an organization
   */
  subscribe({ organizationId, userId = null, streamTypes = null, callback }) {
    if (!organizationId) {
      const err = new Error('Streaming Error: organizationId is required to subscribe');
      err.statusCode = 403;
      throw err;
    }

    if (typeof callback !== 'function') {
      const err = new Error('Streaming Error: callback must be a function');
      err.statusCode = 400;
      throw err;
    }

    let orgMap = this.subscribers.get(organizationId);
    if (!orgMap) {
      orgMap = new Map();
      this.subscribers.set(organizationId, orgMap);
    }

    // Rate Limiting: Max 10 concurrent streams per organization
    if (orgMap.size >= this.MAX_CONCURRENT_STREAMS_PER_ORG) {
      const err = new Error(`Rate Limit Exceeded: Maximum ${this.MAX_CONCURRENT_STREAMS_PER_ORG} concurrent streams reached for organization`);
      err.statusCode = 429;
      throw err;
    }

    const subscriptionId = `sub_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;

    let normalizedStreams = null;
    if (Array.isArray(streamTypes) && streamTypes.length > 0) {
      normalizedStreams = streamTypes.map(s => String(s).toLowerCase().trim());
    }

    orgMap.set(subscriptionId, {
      subscriptionId,
      organizationId,
      userId,
      streamTypes: normalizedStreams,
      callback,
      createdAt: Date.now()
    });

    return subscriptionId;
  }

  /**
   * Unsubscribes and cleans up an active stream subscription
   */
  unsubscribe(subscriptionId) {
    if (!subscriptionId) return false;

    for (const [orgId, orgMap] of this.subscribers.entries()) {
      if (orgMap.has(subscriptionId)) {
        orgMap.delete(subscriptionId);
        if (orgMap.size === 0) {
          this.subscribers.delete(orgId);
        }
        return true;
      }
    }
    return false;
  }

  /**
   * Returns current active stream count for an organization or platform total
   */
  getActiveStreamCount(organizationId = null) {
    if (organizationId) {
      const orgMap = this.subscribers.get(organizationId);
      return orgMap ? orgMap.size : 0;
    }

    let total = 0;
    for (const orgMap of this.subscribers.values()) {
      total += orgMap.size;
    }
    return total;
  }

  /**
   * Publishes an ingested security event to authorized tenant subscribers (< 10ms SLA)
   */
  publishEvent(event) {
    const startTime = process.hrtime.bigint();
    if (!event) return { delivered: 0, duration_ms: 0 };

    const orgId = event.organization_id || event.organizationId;
    if (!orgId) return { delivered: 0, duration_ms: 0 };

    // Record telemetry in live metrics service
    liveMetricsService.recordEvent(event);

    const orgMap = this.subscribers.get(orgId);
    if (!orgMap || orgMap.size === 0) {
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1e6;
      return { delivered: 0, duration_ms: durationMs };
    }

    const eventSourceType = (event.source_type || 'custom').toLowerCase();
    const payload = {
      type: 'new_event',
      event
    };

    let delivered = 0;
    for (const [subId, sub] of orgMap.entries()) {
      try {
        if (
          !sub.streamTypes ||
          sub.streamTypes.includes('all') ||
          sub.streamTypes.includes(eventSourceType)
        ) {
          sub.callback(payload);
          delivered++;
        }
      } catch (err) {
        console.warn(`[StreamingService Warning] Error delivering event to subscriber ${subId}:`, err.message);
      }
    }

    const durationMs = Number(process.hrtime.bigint() - startTime) / 1e6;
    return { delivered, duration_ms: durationMs };
  }

  /**
   * Publishes an incident notification to tenant subscribers
   */
  publishIncident(incident, organizationId = null) {
    if (!incident) return { delivered: 0 };

    const orgId = organizationId || incident.organization_id;
    if (!orgId) return { delivered: 0 };

    liveMetricsService.recordIncident(incident);

    const orgMap = this.subscribers.get(orgId);
    if (!orgMap || orgMap.size === 0) {
      return { delivered: 0 };
    }

    const payload = {
      type: 'new_incident',
      incident
    };

    let delivered = 0;
    for (const [subId, sub] of orgMap.entries()) {
      try {
        sub.callback(payload);
        delivered++;
      } catch (err) {
        console.warn(`[StreamingService Warning] Error delivering incident to subscriber ${subId}:`, err.message);
      }
    }

    return { delivered };
  }

  /**
   * Publishes an attack chain graph update to tenant subscribers
   */
  publishAttackChainUpdate(update, organizationId) {
    if (!update || !organizationId) return { delivered: 0 };

    const orgMap = this.subscribers.get(organizationId);
    if (!orgMap || orgMap.size === 0) {
      return { delivered: 0 };
    }

    const payload = {
      type: 'attack_chain_update',
      ...update
    };

    let delivered = 0;
    for (const [subId, sub] of orgMap.entries()) {
      try {
        sub.callback(payload);
        delivered++;
      } catch (err) {
        console.warn(`[StreamingService Warning] Error delivering attack chain update to subscriber ${subId}:`, err.message);
      }
    }

    return { delivered };
  }

  /**
   * Publishes a campaign / incident group update to tenant subscribers
   */
  publishCampaignUpdate(update, organizationId) {
    if (!update || !organizationId) return { delivered: 0 };

    const orgMap = this.subscribers.get(organizationId);
    if (!orgMap || orgMap.size === 0) {
      return { delivered: 0 };
    }

    const payload = {
      type: 'campaign_update',
      ...update
    };

    let delivered = 0;
    for (const [subId, sub] of orgMap.entries()) {
      try {
        sub.callback(payload);
        delivered++;
      } catch (err) {
        console.warn(`[StreamingService Warning] Error delivering campaign update to subscriber ${subId}:`, err.message);
      }
    }

    return { delivered };
  }

  /**
   * Resets all subscriber state (primarily for test cleanup)
   */
  reset() {
    this.subscribers.clear();
  }
}

// Singleton export
const streamingService = new StreamingService();
module.exports = streamingService;
