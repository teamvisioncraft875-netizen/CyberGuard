const EventPipelineService = require('../services/siem/eventPipelineService');
const EventSearchService = require('../services/siem/eventSearchService');
const EventSource = require('../models/EventSource');
const EventIngestionJob = require('../models/EventIngestionJob');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for SIEM Ingestion & Event Intelligence
 */
const siemController = {
  /**
   * POST /api/v1/siem/events
   * Ingests single or bulk security events, normalizes them, stores them in bulk,
   * and dispatches threats into the detection incident pipeline.
   */
  async ingestEvents(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const {
        source_id,
        source_type,
        events,
        event,
        device_id,
        run_detection = true
      } = req.body;

      // Support either `events: [...]` or single `event: {...}` or raw body array
      let rawEventsList = [];
      if (Array.isArray(events)) {
        rawEventsList = events;
      } else if (Array.isArray(req.body)) {
        rawEventsList = req.body;
      } else if (event) {
        rawEventsList = [event];
      } else if (req.body && (req.body.EventID || req.body.event_type || req.body.message)) {
        rawEventsList = [req.body];
      }

      if (rawEventsList.length === 0) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'No events provided in request body. Provide "events" array or single "event" object.'
        });
      }

      if (source_id && !UUID_REGEX.test(source_id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'source_id must be a valid UUID'
        });
      }

      const result = await EventPipelineService.processEvents({
        organizationId: orgId,
        sourceId: source_id || null,
        sourceTypeHint: source_type || null,
        events: rawEventsList,
        userId: req.user.id || null,
        deviceId: device_id || null,
        runDetectionBridge: Boolean(run_detection)
      });

      return res.status(201).json({
        success: true,
        job_id: result.job_id,
        total_events: result.total_events,
        successful_events: result.successful_events,
        failed_events: result.failed_events,
        detected_incidents_count: result.detected_incidents.length,
        detected_incidents: result.detected_incidents.map(d => ({
          incident_id: d.incident?.id,
          threat_type: d.threat_type,
          risk_score: d.risk_score,
          rule_id: d.rule_id
        }))
      });
    } catch (err) {
      console.error('[SiemController.ingestEvents Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to ingest security events: ' + err.message
      });
    }
  },

  /**
   * GET /api/v1/siem/events
   * Searches and filters security events for the SOC team with pagination.
   */
  async searchEvents(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const {
        severity,
        source_type,
        event_type,
        device_id,
        user_id,
        start_time,
        end_time,
        q,
        page = 1,
        limit = 20
      } = req.query;

      if (device_id && !UUID_REGEX.test(device_id)) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'device_id must be a valid UUID' });
      }

      if (user_id && !UUID_REGEX.test(user_id)) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'user_id must be a valid UUID' });
      }

      const results = await EventSearchService.searchEvents(orgId, {
        severity,
        source_type,
        event_type,
        device_id,
        user_id,
        start_time,
        end_time,
        q,
        page,
        limit
      });

      return res.status(200).json({
        success: true,
        ...results
      });
    } catch (err) {
      console.error('[SiemController.searchEvents Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to search security events: ' + err.message
      });
    }
  },

  /**
   * GET /api/v1/siem/events/:id
   * Retrieves single security event details by ID.
   */
  async getEventById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Security event not found'
        });
      }

      const event = await EventSearchService.getEventById(id, orgId);
      if (!event) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Security event not found or belongs to another tenant'
        });
      }

      return res.status(200).json({
        success: true,
        event
      });
    } catch (err) {
      console.error('[SiemController.getEventById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve security event'
      });
    }
  },

  /**
   * GET /api/v1/siem/sources
   * Lists event sources registered for the organization.
   */
  async listSources(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const { source_type, status, limit = 50, offset = 0 } = req.query;
      const result = await EventSource.findByOrganization(orgId, {
        sourceType: source_type,
        status,
        limit,
        offset
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[SiemController.listSources Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to list event sources'
      });
    }
  },

  /**
   * POST /api/v1/siem/sources
   * Registers a new event source for the tenant organization.
   */
  async createSource(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const { source_name, source_type, metadata = {} } = req.body;
      if (!source_name || !source_type) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'source_name and source_type are required'
        });
      }

      const source = await EventSource.create({
        organization_id: orgId,
        source_name,
        source_type,
        metadata
      });

      return res.status(201).json({
        success: true,
        source
      });
    } catch (err) {
      console.error('[SiemController.createSource Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to register event source'
      });
    }
  },

  /**
   * GET /api/v1/siem/jobs/:id
   * Retrieves status of an event ingestion job.
   */
  async getJobById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Ingestion job not found' });
      }

      const job = await EventIngestionJob.findById(id, orgId);
      if (!job) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Ingestion job not found'
        });
      }

      return res.status(200).json({
        success: true,
        job
      });
    } catch (err) {
      console.error('[SiemController.getJobById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve ingestion job'
      });
    }
  },

  /**
   * GET /api/v1/siem/stats
   * Retrieves summary telemetry statistics for SOC metrics dashboards.
   */
  async getStats(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with a valid tenant organization'
        });
      }

      const stats = await EventSearchService.getStats(orgId);
      return res.status(200).json({
        success: true,
        stats
      });
    } catch (err) {
      console.error('[SiemController.getStats Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve SIEM statistics'
      });
    }
  }
};

module.exports = siemController;
