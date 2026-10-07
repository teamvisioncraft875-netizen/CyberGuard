const streamingService = require('../services/siem/streamingService');
const liveMetricsService = require('../services/siem/liveMetricsService');

/**
 * Controller for Real-Time SIEM Streaming & Live Analytics (Phase 2)
 */
const siemStreamingController = {
  /**
   * GET /api/v1/siem/stream
   * Real-time Server-Sent Events (SSE) stream for live security events,
   * incidents, and attack graph notifications.
   */
  async stream(req, res) {
    const orgId = req.user?.organization_id;
    if (!orgId) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Access denied: Valid organization_id is required'
      });
    }

    // Rate Limiting: Maximum 10 concurrent streams per organization
    const activeStreams = streamingService.getActiveStreamCount(orgId);
    if (activeStreams >= 10) {
      return res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: 'Maximum 10 concurrent streams reached for organization'
      });
    }

    // Establish Server-Sent Events (SSE) HTTP Headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    // Send initial handshake confirmation
    res.write(`data: ${JSON.stringify({
      type: 'connected',
      message: 'Connected to CyberGuard SIEM live stream',
      organization_id: orgId,
      timestamp: new Date().toISOString()
    })}\n\n`);

    let subId = null;
    let heartbeatInterval = null;

    try {
      const streamFilter = req.query.streams ? req.query.streams.split(',').map(s => s.trim()) : null;

      subId = streamingService.subscribe({
        organizationId: orgId,
        userId: req.user?.id || null,
        streamTypes: streamFilter,
        callback: (payload) => {
          try {
            res.write(`data: ${JSON.stringify(payload)}\n\n`);
          } catch (writeErr) {
            // Write failed due to dropped connection
          }
        }
      });

      // Heartbeat timer every 30 seconds
      heartbeatInterval = setInterval(() => {
        try {
          res.write(`data: ${JSON.stringify({
            type: 'heartbeat',
            timestamp: new Date().toISOString()
          })}\n\n`);
        } catch (e) {
          clearInterval(heartbeatInterval);
        }
      }, 30000);

      // Clean up on client connection termination
      const cleanup = () => {
        if (heartbeatInterval) {
          clearInterval(heartbeatInterval);
          heartbeatInterval = null;
        }
        if (subId) {
          streamingService.unsubscribe(subId);
          subId = null;
        }
      };

      req.on('close', cleanup);
      req.on('end', cleanup);
      res.on('close', cleanup);
      res.on('finish', cleanup);
    } catch (err) {
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (subId) streamingService.unsubscribe(subId);

      if (!res.headersSent) {
        const statusCode = err.statusCode || 500;
        return res.status(statusCode).json({
          error: 'STREAM_ERROR',
          message: err.message
        });
      }
    }
  },

  /**
   * GET /api/v1/siem/live-metrics
   * Returns instantaneous rolling telemetry for live SOC operations.
   */
  async getLiveMetrics(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const activeStreams = streamingService.getActiveStreamCount(orgId);
      const metrics = liveMetricsService.getLiveMetrics(orgId, activeStreams);

      return res.status(200).json(metrics);
    } catch (err) {
      console.error('[siemStreamingController getLiveMetrics Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve live SIEM metrics'
      });
    }
  }
};

module.exports = siemStreamingController;
