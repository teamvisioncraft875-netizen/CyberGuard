/**
 * Live Metrics Service — High-performance in-memory sliding window tracking
 * for real-time SIEM operational telemetry.
 *
 * Tracks:
 * - events_per_minute
 * - incidents_per_minute
 * - critical_events
 * - critical_incidents
 * - active_streams
 */

class LiveMetricsService {
  constructor() {
    this.WINDOW_MS = 60 * 1000; // 1-minute sliding window
    // Map<organizationId, { eventTimestamps: number[], incidentTimestamps: number[], criticalEventTimestamps: number[], criticalIncidentTimestamps: number[] }>
    this.orgTelemetry = new Map();
    this.MAX_TIMESTAMPS_PER_ORG = 10000;

    // Periodic sweep every 60 seconds to reclaim memory for inactive tenants
    this.sweepInterval = setInterval(() => {
      this.evictStaleWindows();
    }, 60000);

    // Ensure timer doesn't prevent Node process exit
    if (this.sweepInterval.unref) {
      this.sweepInterval.unref();
    }
  }

  /**
   * Retrieves or initializes telemetry state for a tenant
   */
  _getOrgState(organizationId) {
    if (!organizationId) return null;
    let state = this.orgTelemetry.get(organizationId);
    if (!state) {
      state = {
        eventTimestamps: [],
        incidentTimestamps: [],
        criticalEventTimestamps: [],
        criticalIncidentTimestamps: []
      };
      this.orgTelemetry.set(organizationId, state);
    }
    return state;
  }

  /**
   * Records an ingested or normalized event
   */
  recordEvent(event) {
    if (!event) return;
    const orgId = event.organization_id || event.organizationId;
    if (!orgId) return;

    const state = this._getOrgState(orgId);
    if (!state) return;

    const now = Date.now();
    state.eventTimestamps.push(now);
    if (state.eventTimestamps.length > this.MAX_TIMESTAMPS_PER_ORG) {
      state.eventTimestamps.shift();
    }

    const severity = (event.severity || event.normalized_data?.severity || '').toLowerCase();
    if (severity === 'critical') {
      state.criticalEventTimestamps.push(now);
      if (state.criticalEventTimestamps.length > this.MAX_TIMESTAMPS_PER_ORG) {
        state.criticalEventTimestamps.shift();
      }
    }
  }

  /**
   * Records a detected or persisted incident
   */
  recordIncident(incident) {
    if (!incident) return;
    const orgId = incident.organization_id;
    if (!orgId) return;

    const state = this._getOrgState(orgId);
    if (!state) return;

    const now = Date.now();
    state.incidentTimestamps.push(now);
    if (state.incidentTimestamps.length > this.MAX_TIMESTAMPS_PER_ORG) {
      state.incidentTimestamps.shift();
    }

    const riskLevel = (incident.risk_level || '').toLowerCase();
    const riskScore = Number(incident.risk_score || 0);
    if (riskLevel === 'critical' || riskScore >= 90) {
      state.criticalIncidentTimestamps.push(now);
      if (state.criticalIncidentTimestamps.length > this.MAX_TIMESTAMPS_PER_ORG) {
        state.criticalIncidentTimestamps.shift();
      }
    }
  }

  /**
   * Returns current live metrics for an organization
   */
  getLiveMetrics(organizationId, activeStreams = 0) {
    if (!organizationId) {
      return {
        events_per_minute: 0,
        incidents_per_minute: 0,
        critical_events: 0,
        critical_incidents: 0,
        active_streams: 0
      };
    }

    const state = this.orgTelemetry.get(organizationId);
    if (!state) {
      return {
        events_per_minute: 0,
        incidents_per_minute: 0,
        critical_events: 0,
        critical_incidents: 0,
        active_streams: activeStreams
      };
    }

    const cutoff = Date.now() - this.WINDOW_MS;

    // Prune stale timestamps within 1-minute window
    state.eventTimestamps = state.eventTimestamps.filter(t => t >= cutoff);
    state.incidentTimestamps = state.incidentTimestamps.filter(t => t >= cutoff);
    state.criticalEventTimestamps = state.criticalEventTimestamps.filter(t => t >= cutoff);
    state.criticalIncidentTimestamps = state.criticalIncidentTimestamps.filter(t => t >= cutoff);

    return {
      events_per_minute: state.eventTimestamps.length,
      incidents_per_minute: state.incidentTimestamps.length,
      critical_events: state.criticalEventTimestamps.length,
      critical_incidents: state.criticalIncidentTimestamps.length,
      active_streams: activeStreams
    };
  }

  /**
   * Periodic garbage collection for inactive organizations
   */
  evictStaleWindows() {
    const cutoff = Date.now() - this.WINDOW_MS;
    for (const [orgId, state] of this.orgTelemetry.entries()) {
      state.eventTimestamps = state.eventTimestamps.filter(t => t >= cutoff);
      state.incidentTimestamps = state.incidentTimestamps.filter(t => t >= cutoff);
      state.criticalEventTimestamps = state.criticalEventTimestamps.filter(t => t >= cutoff);
      state.criticalIncidentTimestamps = state.criticalIncidentTimestamps.filter(t => t >= cutoff);

      if (
        state.eventTimestamps.length === 0 &&
        state.incidentTimestamps.length === 0 &&
        state.criticalEventTimestamps.length === 0 &&
        state.criticalIncidentTimestamps.length === 0
      ) {
        this.orgTelemetry.delete(orgId);
      }
    }
  }

  /**
   * Resets all metrics (primarily for test fixture cleanup)
   */
  reset() {
    this.orgTelemetry.clear();
  }
}

// Singleton export
const liveMetricsService = new LiveMetricsService();
module.exports = liveMetricsService;
