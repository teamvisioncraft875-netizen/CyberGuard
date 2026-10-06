const IngestionService = require('./ingestionService');
const DetectionBridgeService = require('./detectionBridgeService');
const EventBurstDetectionService = require('./eventBurstDetectionService');
const LateralMovementService = require('./lateralMovementService');
const correlationRuleEngine = require('./correlationRuleEngine');
const streamingService = require('./streamingService');

/**
 * Event Pipeline Service — Master orchestrator for real-time SIEM event intake:
 * Raw Events -> Normalization -> Storage Layer -> Streaming Publish -> Burst Detection -> Lateral Movement -> Detection Bridge -> Correlation Engine -> Incident Generation
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

    // Attach inserted DB ids to normalized objects if available
    if (Array.isArray(insertedEvents) && Array.isArray(normalizedEvents)) {
      normalizedEvents.forEach((norm, idx) => {
        if (insertedEvents[idx]?.id) {
          norm.id = insertedEvents[idx].id;
        }
      });
    }

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
        const handledSingleEventTypes = new Set();
        try {
          const bridgeResults = await DetectionBridgeService.processBatch(
            normalizedEvents,
            organizationId,
            client
          );
          if (Array.isArray(bridgeResults) && bridgeResults.length > 0) {
            detectedIncidents.push(...bridgeResults);
            for (const b of bridgeResults) {
              if (b.rule_id === 'SIEM-DEF-1102') {
                handledSingleEventTypes.add('windows_audit_log_cleared');
              }
            }
          }
        } catch (bridgeErr) {
          console.warn('[Pipeline Warning] Detection bridge error:', bridgeErr.message);
        }

        // 6. Real-Time Multi-Event Correlation Rule Engine (Rules 1-7)
        try {
          const eventsForCorrelation = handledSingleEventTypes.size > 0
            ? normalizedEvents.filter(e => !handledSingleEventTypes.has(e.event_type) && String(e.event_id) !== '1102')
            : normalizedEvents;

          const correlationHits = await correlationRuleEngine.evaluateBatch(
            eventsForCorrelation,
            organizationId,
            client
          );
          if (Array.isArray(correlationHits) && correlationHits.length > 0) {
            for (const hit of correlationHits) {
              if (hit.incident) {
                detectedIncidents.push({
                  rule_id: hit.rule_code,
                  incident: hit.incident,
                  threat_type: hit.incident.threat_type,
                  risk_score: hit.incident.risk_score,
                  hit_id: hit.hit?.id
                });
              }
            }
          }
        } catch (corrErr) {
          console.warn('[Pipeline Warning] Correlation rule engine error:', corrErr.message);
        }
      }
    }

    // Deduplicate detected incidents by incident.id to ensure idempotency across correlation layers
    const deduplicatedIncidents = [];
    const seenIncidentIds = new Set();
    for (const item of detectedIncidents) {
      const incId = item.incident?.id;
      if (incId) {
        if (!seenIncidentIds.has(incId)) {
          seenIncidentIds.add(incId);
          deduplicatedIncidents.push(item);
        }
      } else {
        deduplicatedIncidents.push(item);
      }
    }

    return {
      job_id,
      total_events: total,
      successful_events: successful,
      failed_events: failed,
      stored_events: insertedEvents,
      detected_incidents: deduplicatedIncidents
    };
  }
};

module.exports = EventPipelineService;
