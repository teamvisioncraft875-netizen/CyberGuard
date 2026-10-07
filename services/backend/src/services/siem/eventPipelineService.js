const IngestionService = require('./ingestionService');
const DetectionBridgeService = require('./detectionBridgeService');
const EventBurstDetectionService = require('./eventBurstDetectionService');
const LateralMovementService = require('./lateralMovementService');
const correlationRuleEngine = require('./correlationRuleEngine');
const streamingService = require('./streamingService');
const performanceMetricsService = require('./performanceMetricsService');
const threatIntelService = require('./threatIntelService');
const ThreatIOC = require('../../models/ThreatIOC');
const SiemAlert = require('../../models/SiemAlert');

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

    const tIngestStart = Date.now();

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

    performanceMetricsService.recordIngestion(
      Array.isArray(events) ? events.length : 1,
      Date.now() - tIngestStart
    );

    const {
      job_id,
      total,
      successful,
      failed,
      events: insertedEvents,
      normalized_events: normalizedEvents
    } = ingestionResult;

    // Attach inserted DB ids and raw events to normalized objects if available
    if (Array.isArray(insertedEvents) && Array.isArray(normalizedEvents)) {
      normalizedEvents.forEach((norm, idx) => {
        if (insertedEvents[idx]?.id) {
          norm.id = insertedEvents[idx].id;
        }
        if (insertedEvents[idx]?.raw_event) {
          norm.raw_event = insertedEvents[idx].raw_event;
        } else if (events && events[idx]) {
          norm.raw_event = events[idx];
        }
      });
    }

    let detectedIncidents = [];

    if (Array.isArray(normalizedEvents) && normalizedEvents.length > 0) {
      // 2. Real-Time Streaming Publish & Threat Intelligence IOC Matching
      for (const normEv of normalizedEvents) {
        try {
          streamingService.publishEvent(normEv);
        } catch (streamErr) {
          console.warn('[Pipeline Warning] Streaming publish error:', streamErr.message);
        }

        // Threat Intelligence: IOC Match, Sighting Creation, and Alerting
        try {
          const normData = normEv.normalized_data || {};
          const details = normData.details || normEv.details || {};
          const raw = normEv.raw_event || {};

          const srcIp = normEv.source_ip || normData.source_ip || details.source_ip || details.src_ip || details.IpAddress || raw.source_ip || raw.src_ip || raw.ip || null;
          const dstIp = normEv.destination_ip || normData.dest_ip || normEv.dest_ip || details.destination_ip || details.dest_ip || details.dst_ip || raw.destination_ip || raw.dest_ip || null;
          const userName = normEv.user || normEv.user_name || normData.target_user || details.user || details.user_name || details.TargetUserName || raw.user || raw.user_name || raw.username || null;
          const assetName = normEv.device_name || normEv.target_host || normData.target_host || details.Computer || details.WorkstationName || raw.host || raw.hostname || null;

          if (!normEv.source_ip && srcIp) normEv.source_ip = srcIp;
          if (!normEv.destination_ip && dstIp) normEv.destination_ip = dstIp;
          if (!normEv.user && userName) normEv.user = userName;
          if (!normEv.device_name && assetName) normEv.device_name = assetName;

          const iocHits = await threatIntelService.matchEvent(normEv, organizationId, client);
          if (Array.isArray(iocHits) && iocHits.length > 0) {
            for (const hit of iocHits) {
              // A. Record Sighting
              const sighting = await ThreatIOC.recordSighting({
                organization_id: organizationId,
                ioc_id: hit.ioc_id,
                event_id: normEv.id || null,
                source_ip: srcIp,
                destination_ip: dstIp,
                user_name: userName,
                asset_name: assetName,
                metadata: {
                  ioc_type: hit.ioc_type,
                  ioc_value: hit.ioc_value,
                  threat_actor: hit.threat_actor,
                  malware_family: hit.malware_family,
                  campaign_name: hit.campaign_name,
                  risk_score: hit.risk_score
                }
              }, client);

              // B. Determine Severity based on IOC Risk Score
              let alertSeverity = 'medium';
              if (hit.risk_score > 80) {
                alertSeverity = 'critical';
              } else if (hit.risk_score > 60) {
                alertSeverity = 'high';
              } else if (hit.risk_score <= 30) {
                alertSeverity = 'low';
              }

              // C. Create SIEM Alert
              const alert = await SiemAlert.create({
                organization_id: organizationId,
                title: `Threat Intel Match: ${hit.ioc_type.toUpperCase()} ${hit.ioc_value} (${hit.malware_family || hit.threat_actor || 'Known Threat'})`,
                severity: alertSeverity,
                status: 'new',
                rule_code: 'THREAT-INTEL-IOC',
                source_type: normEv.source_type || 'threat_intel',
                mitre_technique: 'T1071',
                assigned_analyst: null
              }, client);

              // D. Broadcast Real-Time Threat Intel Streaming Events
              streamingService.publishIOCMatch({ ...hit, event_id: normEv.id, alert_id: alert.id }, organizationId);
              streamingService.publishSighting(sighting, organizationId);
            }
          }
        } catch (iocErr) {
          console.warn('[Pipeline Warning] Threat Intel match error:', iocErr.message);
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

          const tCorrStart = Date.now();
          const correlationHits = await correlationRuleEngine.evaluateBatch(
            eventsForCorrelation,
            organizationId,
            client
          );
          performanceMetricsService.recordDetection(Date.now() - tCorrStart);

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
