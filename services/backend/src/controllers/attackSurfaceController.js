const attackSurfaceService = require('../services/attackSurfaceService');

/**
 * Controller for Attack Surface Discovery Admin APIs (Phase B)
 */
const attackSurfaceController = {
  /**
   * GET /api/v1/admin/attack-surface/exposures
   * Query parameters: severity, status, device_id, limit, offset
   */
  async getExposures(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { severity, status, device_id, limit, offset } = req.query;

      const result = await attackSurfaceService.getExposures({
        organization_id,
        severity,
        status,
        device_id,
        limit,
        offset
      });

      return res.json(result);
    } catch (err) {
      console.error('[attackSurfaceController.getExposures Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/admin/attack-surface/overview
   */
  async getOverview(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const overview = await attackSurfaceService.getOverview({ organization_id });
      return res.json(overview);
    } catch (err) {
      console.error('[attackSurfaceController.getOverview Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/admin/attack-surface/scan
   * Body: { device_id?: string }
   */
  async triggerScan(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { device_id } = req.body || {};
      const requested_by_id = req.user?.id || null;

      const result = await attackSurfaceService.queueScan({
        organization_id,
        device_id,
        requested_by_id
      });

      return res.status(202).json(result);
    } catch (err) {
      console.error('[attackSurfaceController.triggerScan Error]', err.message);
      return res.status(400).json({ error: 'BAD_REQUEST', message: err.message });
    }
  }
};

module.exports = attackSurfaceController;
