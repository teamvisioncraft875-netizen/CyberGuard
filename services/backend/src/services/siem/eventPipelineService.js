const IngestionService = require('./ingestionService');
const DetectionBridgeService = require('./detectionBridgeService');

/**
 * Event Pipeline Service — Master orchestrator for SIEM event intake:
 * Raw Events -> Normalization -> Storage Layer -> Detection Bridge -> Incident Generation
 */
const EventPipelineService = {
  /**
   * Executes the end-to-end SIEM ingestion and threat detection pipeline.
   */
  async processEvents({
    organizationId,
    sourceId = null,
    sourceTypeHint = null,
    events = [],
    userId = null,
    deviceId = null,
    runDetectionBridge = true,
    client = null
  }) {
    if (!organizationId) {
      throw new Error('Pipeline Error: organizationId is required');
    }

    // 1. Ingest, Normalize, and Store in Bulk
    const ingestionResult = await IngestionService.ingestEvents({
      organizationId,
      sourceId,
      sourceTypeHint,
      events,
      userId,
      deviceId,
      client
    });

    const {
      job_id,
      total,
      successful,
      failed,
      events: insertedEvents,
      normalized_events: normalizedEvents
    } = ingestionResult;

    // 2. Feed Normalized Events into Detection Bridge
    let detectedIncidents = [];
    if (runDetectionBridge && Array.isArray(normalizedEvents) && normalizedEvents.length > 0) {
      try {
        detectedIncidents = await DetectionBridgeService.processBatch(
          normalizedEvents,
          organizationId,
          client
        );
      } catch (bridgeErr) {
        console.error('[Pipeline Warning] Detection bridge processing error:', bridgeErr.message);
      }
    }

    return {
      job_id,
      total_events: total,
      successful_events: successful,
      failed_events: failed,
      stored_events: insertedEvents,
      detected_incidents: detectedIncidents
    };
  }
};

module.exports = EventPipelineService;
