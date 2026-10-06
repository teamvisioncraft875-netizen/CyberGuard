const SiemAlert = require('../models/SiemAlert');
const socMetricsService = require('../services/siem/socMetricsService');
const timelineService = require('../services/siem/timelineService');
const streamingService = require('../services/siem/streamingService');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for SIEM Phase 3 — Real-Time SOC Monitoring Platform
 */
const siemSocController = {
  /**
   * 1. GET /api/v1/siem/live
   * Real-Time Alert Feed via Server-Sent Events (SSE) with auto-reconnect support
   */
  async liveStream(req, res) {
    const orgId = req.user?.organization_id;
    if (!orgId) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Access denied: Valid organization_id is required'
      });
    }

    // Initialize SSE Headers with Reconnect support
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    // Auto-reconnect retry instruction for SSE clients
    res.write('retry: 5000\n\n');

    let subscriptionId = null;

    try {
      subscriptionId = streamingService.subscribe({
        organizationId: orgId,
        userId: req.user.id || null,
        callback: (payload) => {
          try {
            const eventId = Date.now();
            res.write(`id: ${eventId}\n`);
            res.write(`event: ${payload.type || 'message'}\n`);
            res.write(`data: ${JSON.stringify(payload)}\n\n`);
          } catch (writeErr) {
            console.warn('[SSE liveStream] Error writing data to client:', writeErr.message);
          }
        }
      });

      // Send initial connection handshake
      const initialHandshake = {
        type: 'handshake',
        status: 'connected',
        subscription_id: subscriptionId,
        organization_id: orgId,
        timestamp: new Date().toISOString()
      };
      res.write(`id: ${Date.now()}\n`);
      res.write(`event: handshake\n`);
      res.write(`data: ${JSON.stringify(initialHandshake)}\n\n`);

      // Heartbeat every 25 seconds to keep connection alive through proxies
      const heartbeatInterval = setInterval(() => {
        try {
          res.write(': heartbeat\n\n');
        } catch {
          clearInterval(heartbeatInterval);
        }
      }, 25000);

      req.on('close', () => {
        clearInterval(heartbeatInterval);
        if (subscriptionId) {
          streamingService.unsubscribe(subscriptionId);
        }
      });
    } catch (err) {
      if (err.statusCode === 429) {
        return res.status(429).json({
          error: 'RATE_LIMIT_EXCEEDED',
          message: err.message
        });
      }
      console.error('[SSE liveStream Error]', err);
      if (!res.headersSent) {
        return res.status(500).json({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to establish live SSE stream'
        });
      }
      res.end();
    }
  },

  /**
   * 2. Alert Lifecycle Management
   * GET /api/v1/siem/alerts
   */
  async listAlerts(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        status,
        severity,
        assigned_analyst,
        limit = 50,
        offset = 0,
        start_date,
        end_date
      } = req.query;

      const [alerts, total] = await Promise.all([
        SiemAlert.findByOrg(orgId, {
          status: status || null,
          severity: severity || null,
          assigned_analyst: assigned_analyst || null,
          limit: parseInt(limit, 10) || 50,
          offset: parseInt(offset, 10) || 0,
          startDate: start_date || null,
          endDate: end_date || null
        }),
        SiemAlert.countByOrg(orgId, {
          status: status || null,
          severity: severity || null,
          assigned_analyst: assigned_analyst || null,
          startDate: start_date || null,
          endDate: end_date || null
        })
      ]);

      return res.status(200).json({
        data: alerts,
        pagination: {
          total,
          limit: parseInt(limit, 10) || 50,
          offset: parseInt(offset, 10) || 0
        }
      });
    } catch (err) {
      console.error('[siemSocController listAlerts Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve SIEM alerts'
      });
    }
  },

  /**
   * GET /api/v1/siem/alerts/:id
   */
  async getAlertById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Alert ID must be a valid UUID'
        });
      }

      const alert = await SiemAlert.findById(id, orgId);
      if (!alert) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Alert not found in your organization'
        });
      }

      return res.status(200).json({ data: alert });
    } catch (err) {
      console.error('[siemSocController getAlertById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve alert details'
      });
    }
  },

  /**
   * PATCH /api/v1/siem/alerts/:id
   * Updates alert status, assigned_analyst, notes, and resolution
   */
  async updateAlert(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Alert ID must be a valid UUID'
        });
      }

      const existingAlert = await SiemAlert.findById(id, orgId);
      if (!existingAlert) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Alert not found in your organization'
        });
      }

      const { status, assigned_analyst, notes, resolution, severity } = req.body;

      if (status && !SiemAlert.VALID_STATUSES.includes(status)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: `Invalid status. Valid values: ${SiemAlert.VALID_STATUSES.join(', ')}`
        });
      }

      if (assigned_analyst && !UUID_REGEX.test(assigned_analyst)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'assigned_analyst must be a valid UUID'
        });
      }

      const updated = await SiemAlert.update(id, orgId, {
        status,
        assigned_analyst,
        notes,
        resolution,
        severity
      });

      // Audit Logging
      if (status && status !== existingAlert.status) {
        await auditLog({
          organization_id: orgId,
          user_id: req.user.id || null,
          actor_type: 'user',
          action: AUDIT_ACTIONS.SIEM_ALERT_STATUS_UPDATED,
          resource_type: 'siem_alert',
          resource_id: id,
          details: {
            old_status: existingAlert.status,
            new_status: status
          }
        });
      }

      if (assigned_analyst && assigned_analyst !== existingAlert.assigned_analyst) {
        await auditLog({
          organization_id: orgId,
          user_id: req.user.id || null,
          actor_type: 'user',
          action: AUDIT_ACTIONS.SIEM_ALERT_ASSIGNED,
          resource_type: 'siem_alert',
          resource_id: id,
          details: {
            assigned_analyst
          }
        });
      }

      // Stream alert update
      streamingService.publishAlertUpdate(updated, orgId);

      return res.status(200).json({
        message: 'Alert updated successfully',
        data: updated
      });
    } catch (err) {
      console.error('[siemSocController updateAlert Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to update alert'
      });
    }
  },

  /**
   * 3. SOC Metrics Dashboard
   * GET /api/v1/siem/dashboard/metrics
   */
  async getDashboardMetrics(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const metrics = await socMetricsService.getMetrics(orgId);
      return res.status(200).json({ data: metrics });
    } catch (err) {
      console.error('[siemSocController getDashboardMetrics Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to compute SOC dashboard metrics'
      });
    }
  },

  /**
   * GET /api/v1/siem/dashboard/trends
   */
  async getDashboardTrends(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { days = 7 } = req.query;
      const trends = await socMetricsService.getTrends(orgId, parseInt(days, 10) || 7);
      return res.status(200).json({ data: trends });
    } catch (err) {
      console.error('[siemSocController getDashboardTrends Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve SOC dashboard trends'
      });
    }
  },

  /**
   * 4. Analyst Queue
   * GET /api/v1/siem/queue
   */
  async getQueue(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { status = 'new,investigating', severity, limit = 50, offset = 0 } = req.query;

      const statusFilter = typeof status === 'string'
        ? status.split(',').map(s => s.trim()).filter(Boolean)
        : status;

      const queue = await SiemAlert.getQueue(orgId, {
        status: statusFilter,
        severity: severity || null,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({
        data: queue,
        total: queue.length
      });
    } catch (err) {
      console.error('[siemSocController getQueue Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve analyst queue'
      });
    }
  },

  /**
   * 5. Timeline API
   * GET /api/v1/siem/timeline
   */
  async getTimeline(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { limit = 50, offset = 0, start_date, end_date, types } = req.query;

      const typesFilter = typeof types === 'string'
        ? types.split(',').map(t => t.trim()).filter(Boolean)
        : null;

      const timeline = await timelineService.getUnifiedTimeline(orgId, {
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0,
        startDate: start_date || null,
        endDate: end_date || null,
        types: typesFilter
      });

      return res.status(200).json({
        data: timeline,
        count: timeline.length
      });
    } catch (err) {
      console.error('[siemSocController getTimeline Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve unified security timeline'
      });
    }
  }
};

module.exports = siemSocController;
