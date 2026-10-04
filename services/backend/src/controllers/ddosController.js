const db = require('../config/db');
const ddosDetectionService = require('../services/ddosDetectionService');
const { log: auditLog } = require('../services/auditService');

const VALID_SCAN_TYPES = new Set(['request_spike', 'post_flood', 'login_abuse', 'ip_flooding']);

/**
 * DDoS Controller — Exposes administrative detection and monitoring APIs.
 * Allows administrators to trigger manual heuristic scans and review active threats.
 *
 * ARCHITECTURAL SKETCH — Background DDoS Check (Planned):
 * Periodic job (every 5 minutes via schedulerService):
 *   cron.schedule('star-slash-5 * * * *', async () => {
 *     const orgs = await Organization.findAll();
 *     for (const org of orgs) {
 *       const threats = await Promise.all([
 *         ddosDetectionService.detectRequestSpike(org.id, 5),
 *         ddosDetectionService.detectPostFlood(org.id, null, 5),
 *         ddosDetectionService.detectLoginAbuse(org.id, 15),
 *         ddosDetectionService.detectIPFlooding(org.id, 5)
 *       ]);
 *       // For each detected threat exceeding threshold:
 *       //   const incidentId = await ddosDetectionService.createDDoSIncident(...);
 *       //   io.to(`org:${org.id}`).emit('incident:new', ...);
 *     }
 *   });
 */
const ddosController = {
  /**
   * POST /api/v1/admin/ddos/scan
   * Triggers a targeted DDoS pattern detection scan.
   */
  async scan(req, res) {
    try {
      const { scan_type, endpoint = null, window_minutes } = req.body || {};

      if (!scan_type || !VALID_SCAN_TYPES.has(scan_type)) {
        return res.status(400).json({
          error: 'INVALID_SCAN_TYPE',
          message: `scan_type must be one of: ${Array.from(VALID_SCAN_TYPES).join(', ')}`
        });
      }

      const orgId = req.user?.organization_id || null;
      let rawResults = [];
      let threats = [];

      switch (scan_type) {
        case 'request_spike': {
          const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
          rawResults = await ddosDetectionService.detectRequestSpike(orgId, windowMinutes);
          threats = rawResults.filter((r) => r.threshold_exceeded);
          break;
        }

        case 'post_flood': {
          const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
          rawResults = await ddosDetectionService.detectPostFlood(orgId, endpoint, windowMinutes);
          threats = rawResults;
          break;
        }

        case 'login_abuse': {
          const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 15);
          rawResults = await ddosDetectionService.detectLoginAbuse(orgId, windowMinutes);
          threats = rawResults;
          break;
        }

        case 'ip_flooding': {
          const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
          rawResults = await ddosDetectionService.detectIPFlooding(orgId, windowMinutes);
          threats = rawResults;
          break;
        }
      }

      // Automatically create DDoS incidents for identified threats (if not already created by detector)
      let incidentsCreated = 0;
      for (const threat of threats) {
        if (threat.incident_id) {
          incidentsCreated++;
          continue;
        }
        try {
          const inc = await ddosDetectionService.createDDoSIncident(orgId, scan_type, threat.source_ip, {
            ...threat,
            user_id: req.user?.id || null,
            scan_type,
            triggered_by: req.user?.id || 'admin'
          });
          threat.incident_id = inc?.id || inc;
          incidentsCreated++;
        } catch (incidentErr) {
          console.warn('[ddosController.scan Incident Creation Note]', incidentErr.message);
        }
      }

      // Record audit log entry
      try {
        await auditLog({
          organization_id: orgId,
          user_id: req.user?.id || null,
          actor_type: 'admin',
          action: 'ddos_scan_triggered',
          resource_type: 'ddos_detection',
          resource_id: scan_type,
          details: {
            scan_type,
            threats_count: threats.length,
            incidents_created: incidentsCreated,
            window_minutes: window_minutes || (scan_type === 'login_abuse' ? 15 : 5),
            endpoint
          },
          ip_address: req.ip || req.connection?.remoteAddress || null
        });
      } catch (auditErr) {
        console.warn('[ddosController.scan Audit Log Note]', auditErr.message);
      }

      return res.status(200).json({
        metric_type: scan_type,
        threats,
        incidents_created: incidentsCreated
      });
    } catch (err) {
      console.error('[ddosController.scan Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to complete DDoS detection scan'
      });
    }
  },

  /**
   * GET /api/v1/admin/ddos/threats
   * Lists historical and active DDoS threat observations scoped to the admin's organization.
   */
  async getThreats(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Admin must belong to an organization to view DDoS threats'
        });
      }

      const scanType = req.query.scan_type || req.query.metric_type || null;
      if (scanType && !VALID_SCAN_TYPES.has(scanType)) {
        return res.status(400).json({
          error: 'INVALID_SCAN_TYPE',
          message: `scan_type must be one of: ${Array.from(VALID_SCAN_TYPES).join(', ')}`
        });
      }

      const limit = Math.min(Math.max(1, parseInt(req.query.limit, 10) || 50), 100);
      const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

      const whereClauses = ['organization_id = $1'];
      const params = [orgId];

      if (scanType) {
        params.push(scanType);
        whereClauses.push(`metric_type = $${params.length}`);
      }

      const whereSql = whereClauses.join(' AND ');

      // Total count query
      const countRes = await db.query(
        `SELECT COUNT(*)::INT AS total FROM public.ddos_metrics WHERE ${whereSql};`,
        params
      );
      const total = countRes.rows[0]?.total || 0;

      // Paged records query
      params.push(limit);
      const limitIdx = params.length;
      params.push(offset);
      const offsetIdx = params.length;

      const listRes = await db.query(
        `SELECT id, source_ip, metric_type, count, endpoint, threshold_exceeded, metadata, created_at
         FROM public.ddos_metrics
         WHERE ${whereSql}
         ORDER BY created_at DESC
         LIMIT $${limitIdx} OFFSET $${offsetIdx};`,
        params
      );

      const threats = listRes.rows.map((row) => ({
        id: row.id,
        source_ip: row.source_ip,
        metric_type: row.metric_type,
        count: row.count,
        endpoint: row.endpoint,
        threshold_exceeded: row.threshold_exceeded,
        metadata: row.metadata,
        created_at: row.created_at
      }));

      return res.status(200).json({
        threats,
        total
      });
    } catch (err) {
      console.error('[ddosController.getThreats Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve DDoS threats'
      });
    }
  }
};

module.exports = ddosController;
