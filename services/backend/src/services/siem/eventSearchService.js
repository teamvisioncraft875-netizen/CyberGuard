const SecurityEvent = require('../../models/SecurityEvent');

/**
 * Event Search Service — High-performance indexed search and aggregation for SOC teams
 */
const EventSearchService = {
  /**
   * Searches security events with strict tenant isolation and composite index utilization.
   */
  async searchEvents(organizationId, filters = {}, client = null) {
    if (!organizationId) {
      throw new Error('Search Error: organizationId is required for tenant isolation');
    }

    const {
      severity,
      sourceType,
      source_type,
      eventType,
      event_type,
      deviceId,
      device_id,
      userId,
      user_id,
      startTime,
      start_time,
      endTime,
      end_time,
      q,
      search,
      page = 1,
      limit = 20
    } = filters;

    // Validate and sanitize inputs
    const normalizedFilters = {
      severity: severity ? String(severity).trim().toLowerCase() : null,
      sourceType: (sourceType || source_type) ? String(sourceType || source_type).trim().toLowerCase() : null,
      eventType: eventType || event_type || null,
      deviceId: deviceId || device_id || null,
      userId: userId || user_id || null,
      startTime: startTime || start_time || null,
      endTime: endTime || end_time || null,
      q: q || search || null,
      page: Math.max(1, parseInt(page, 10) || 1),
      limit: Math.max(1, Math.min(100, parseInt(limit, 10) || 20))
    };

    return await SecurityEvent.search(organizationId, normalizedFilters, client);
  },

  /**
   * Retrieves single event by ID with tenant verification.
   */
  async getEventById(eventId, organizationId, client = null) {
    if (!organizationId) {
      throw new Error('Search Error: organizationId is required');
    }
    return await SecurityEvent.findById(eventId, organizationId, client);
  },

  /**
   * Retrieves summary telemetry statistics for SOC metrics dashboards.
   */
  async getStats(organizationId, client = null) {
    if (!organizationId) {
      throw new Error('Stats Error: organizationId is required');
    }
    return await SecurityEvent.getStats(organizationId, client);
  }
};

module.exports = EventSearchService;
