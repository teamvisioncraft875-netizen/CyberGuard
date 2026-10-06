const dashboardAggregationService = require('../services/dashboardAggregationService');

/**
 * Controller for SOC Dashboard Aggregation APIs
 */
const dashboardController = {
  /**
   * GET /api/v1/dashboard/overview
   */
  async getOverview(req, res) {
    try {
      const organizationId = req.user.organization_id;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const overview = await dashboardAggregationService.getOverview(organizationId, {
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        ...overview
      });
    } catch (err) {
      console.error('[DashboardController Error] getOverview failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/dashboard/trends
   */
  async getTrends(req, res) {
    try {
      const organizationId = req.user.organization_id;
      const { days } = req.query;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const trends = await dashboardAggregationService.getTrends(organizationId, {
        days,
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        days: days || 14,
        count: trends.length,
        trends
      });
    } catch (err) {
      console.error('[DashboardController Error] getTrends failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  },

  /**
   * GET /api/v1/dashboard/metrics
   */
  async getMetrics(req, res) {
    try {
      const organizationId = req.user.organization_id;

      if (!organizationId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'User is not associated with an organization'
        });
      }

      const metrics = await dashboardAggregationService.getMetrics(organizationId, {
        actorUserId: req.user.id
      });

      return res.status(200).json({
        status: 'success',
        ...metrics
      });
    } catch (err) {
      console.error('[DashboardController Error] getMetrics failed:', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  }
};

module.exports = dashboardController;
