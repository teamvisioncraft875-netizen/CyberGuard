const IngestionService = require('./ingestionService');
const DetectionBridgeService = require('./detectionBridgeService');
const EventBurstDetectionService = require('./eventBurstDetectionService');
const LateralMovementService = require('./lateralMovementService');
const streamingService = require('./streamingService');

/**
 * Event Pipeline Service — Master orchestrator for real-time SIEM event intake:
 * Raw Events -> Normalization -> Storage Layer -> Streaming Publish -> Burst Detection -> Lateral Movement -> Detection Bridge -> Incident Generation
 */
const EventPipelineService = {
  /**
   * Executes the end-to-end real-time SIEM ingestion, streaming, and threat detection pipeline.
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

    let detectedIncidents = [];

    if (Array.isArray(normalizedEvents) && normalizedEvents.length > 0) {
      // 2. Real-Time Streaming Publish (Fan-out to active tenant subscribers & live metrics)
      for (const normEv of normalizedEvents) {
        try {
          streamingService.publishEvent(normEv);
        } catch (streamErr) {
          console.warn('[Pipeline Warning] Streaming publish error:', streamErr.message);
        }
      }

      if (runDetectionBridge) {
        // 3. Sliding Window Event Burst Detection (Rules B1, B2, B3)
        try {
          const burstResults = await EventBurstDetectionService.processBatch(
            normalizedEvents,
            organizationId,
            client
          );
          if (Array.isArray(burstResults) && burstResults.length > 0) {
            detectedIncidents.push(...burstResults);
          }
        } catch (burstErr) {
          console.warn('[Pipeline Warning] Burst detection error:', burstErr.message);
        }

        // 4. Lateral Movement & Credential Reuse Detection (Rules LM1, LM2)
        try {
          const lmResults = await LateralMovementService.processBatch(
            normalizedEvents,
            organizationId,
            client
          );
          if (Array.isArray(lmResults) && lmResults.length > 0) {
            detectedIncidents.push(...lmResults);
          }
        } catch (lmErr) {
          console.warn('[Pipeline Warning] Lateral movement detection error:', lmErr.message);
        }

        // 5. Individual Threat Event Detection Bridge (Rules 1-6)
        try {
          const bridgeResults = await DetectionBridgeService.processBatch(
            normalizedEvents,
            organizationId,
            client
          );
          if (Array.isArray(bridgeResults) && bridgeResults.length > 0) {
            detectedIncidents.push(...bridgeResults);
          }
        } catch (bridgeErr) {
          console.warn('[Pipeline Warning] Detection bridge error:', bridgeErr.message);
        }
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
