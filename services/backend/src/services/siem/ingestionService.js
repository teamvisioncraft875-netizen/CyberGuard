const SecurityEvent = require('../../models/SecurityEvent');
const EventSource = require('../../models/EventSource');
const EventIngestionJob = require('../../models/EventIngestionJob');
const NormalizationService = require('./normalizationService');
const { auditLog, AUDIT_ACTIONS } = require('../auditService');

/**
 * Ingestion Service — High-throughput event ingestion and batch persistence
 */
const IngestionService = {
  /**
   * Ingests single or bulk raw events for an organization.
   * Handles normalization, bulk database insertion, job tracking, and source telemetry.
   */
  async ingestEvents({
    organizationId,
    sourceId = null,
    sourceTypeHint = null,
    events = [],
    userId = null,
    deviceId = null,
    client = null
  }) {
    if (!organizationId) {
      throw new Error('Ingestion Error: organizationId is required');
    }

    const rawEvents = Array.isArray(events) ? events : [events];
    if (rawEvents.length === 0) {
      return {
        job_id: null,
        total: 0,
        successful: 0,
        failed: 0,
        events: []
      };
    }

    // 1. Create Ingestion Job Record
    let job = null;
    try {
      job = await EventIngestionJob.create({
        organization_id: organizationId,
        source_id: sourceId,
        total_events: rawEvents.length,
        status: 'in_progress'
      }, client);
    } catch (jobErr) {
      console.warn('[IngestionJob Warning] Failed to initialize job record:', jobErr.message);
    }

    // 2. Normalize and Prepare Events for Bulk Insertion
    const preparedEvents = [];
    const normalizedEventsList = [];
    let successfulCount = 0;
    let failedCount = 0;

    for (const raw of rawEvents) {
      try {
        const normalized = NormalizationService.normalize(raw, sourceTypeHint);
        normalizedEventsList.push(normalized);

        preparedEvents.push({
          organization_id: organizationId,
          source_id: sourceId,
          event_timestamp: normalized.timestamp ? new Date(normalized.timestamp) : new Date(),
          source_type: normalized.source_type,
          event_type: normalized.event_type,
          severity: normalized.severity,
          device_id: deviceId || normalized.device_id || null,
          user_id: userId || normalized.user_id || null,
          raw_event: raw,
          normalized_event: normalized
        });
        successfulCount++;
      } catch (normErr) {
        console.warn('[Normalization Warning] Failed to normalize event:', normErr.message);
        failedCount++;
      }
    }

    // 3. High-Performance Multi-Row Batch Insertion
    let insertedEvents = [];
    if (preparedEvents.length > 0) {
      try {
        insertedEvents = await SecurityEvent.createMany(preparedEvents, client);
      } catch (insertErr) {
        console.error('[Ingestion DB Error] Failed during bulk insert:', insertErr.message);
        if (job) {
          await EventIngestionJob.update(job.id, organizationId, {
            successful_events: 0,
            failed_events: rawEvents.length,
            status: 'failed',
            error_details: { message: insertErr.message }
          }, client);
        }
        throw insertErr;
      }
    }

    // 4. Update Event Source Telemetry
    if (sourceId) {
      try {
        await EventSource.touch(sourceId, organizationId, 'active', client);
      } catch (srcErr) {
        // Non-critical telemetry update error
      }
    }

    // 5. Finalize Ingestion Job Status
    if (job) {
      try {
        const finalStatus = failedCount === 0 ? 'completed' : (successfulCount > 0 ? 'partial' : 'failed');
        await EventIngestionJob.update(job.id, organizationId, {
          successful_events: successfulCount,
          failed_events: failedCount,
          status: finalStatus
        }, client);
      } catch (finalJobErr) {
        // Non-critical job update error
      }
    }

    // 6. Record Audit Log for Ingestion Activity
    try {
      await auditLog({
        organization_id: organizationId,
        actor_type: 'system_guard',
        action: 'SIEM_EVENTS_INGESTED',
        resource_type: 'security_event',
        resource_id: job ? job.id : null,
        details: {
          total_events: rawEvents.length,
          successful_events: successfulCount,
          failed_events: failedCount,
          source_id: sourceId
        }
      }, client);
    } catch (auditErr) {
      // Non-critical audit error
    }

    return {
      job_id: job ? job.id : null,
      total: rawEvents.length,
      successful: successfulCount,
      failed: failedCount,
      events: insertedEvents,
      normalized_events: normalizedEventsList
    };
  }
};

module.exports = IngestionService;
