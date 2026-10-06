const threatIntelService = require('../services/threatIntelService');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Controller for Threat Intelligence APIs & SOC Dashboard Integration
 */
const threatIntelController = {
  /**
   * GET /api/v1/threat-intel/dashboard
   * Returns SOC metrics: indicator totals, feed health counts, recent matches, and breakdown by type.
   */
  async getDashboard(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;

      const dashboard = await threatIntelService.getThreatDashboard(organizationId);

      // Audit log viewing the threat dashboard
      auditLog({
        organization_id: organizationId,
        actor_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_DASHBOARD_VIEWED,
        resource_type: 'threat_intel',
        details: {
          total_indicators: dashboard.total_indicators,
          active_indicators: dashboard.active_indicators,
          total_feeds: dashboard.total_feeds
        }
      });

      return res.status(200).json(dashboard);
    } catch (err) {
      console.error('[threatIntelController.getDashboard Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/indicators
   * Returns paginated indicators with multi-field filtering (type, severity, search, active).
   */
  async listIndicators(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const {
        type,
        indicator_type,
        severity,
        is_active,
        search,
        q,
        sort_by,
        sort_order,
        limit,
        offset
      } = req.query;

      const result = await threatIntelService.getIndicators({
        organization_id: organizationId,
        type: type || indicator_type,
        severity,
        is_active,
        search: search || q,
        sort_by,
        sort_order,
        limit,
        offset
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[threatIntelController.listIndicators Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/indicators/:id
   * Returns a single threat indicator by UUID with tenant access scoping.
   */
  async getIndicator(req, res) {
    try {
      const { id } = req.params;
      const organizationId = req.user?.organization_id || null;

      if (!id || !UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'INVALID_ID',
          message: 'Indicator ID must be a valid UUID'
        });
      }

      const indicator = await threatIntelService.getIndicatorById(id, organizationId);
      if (!indicator) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: `Threat indicator with ID ${id} not found`
        });
      }

      // Audit log indicator access
      auditLog({
        organization_id: organizationId,
        actor_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_INDICATOR_VIEWED,
        resource_type: 'threat_indicator',
        resource_id: String(id),
        details: {
          indicator_type: indicator.indicator_type,
          indicator_value: indicator.indicator_value,
          severity: indicator.severity
        }
      });

      return res.status(200).json(indicator);
    } catch (err) {
      console.error('[threatIntelController.getIndicator Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/feed-health
   * Returns operational sync health and circuit-breaker status across threat feeds.
   */
  async getFeedHealth(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;

      const health = await threatIntelService.getFeedHealth(organizationId);

      auditLog({
        organization_id: organizationId,
        actor_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_FEED_HEALTH_VIEWED,
        resource_type: 'threat_feed',
        details: {
          total_feeds: health.total_feeds,
          active_feeds: health.active_feeds,
          failed_feeds: health.failed_feeds
        }
      });

      return res.status(200).json(health);
    } catch (err) {
      console.error('[threatIntelController.getFeedHealth Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/feed-statistics
   * Returns aggregate statistics on sync success rate, total indicators ingested, and last sync.
   */
  async getFeedStatistics(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;

      const stats = await threatIntelService.getFeedStatistics(organizationId);
      return res.status(200).json(stats);
    } catch (err) {
      console.error('[threatIntelController.getFeedStatistics Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/matches
   * Returns paginated incident IOC matches for correlation visibility in the SOC.
   */
  async getRecentMatches(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const { limit, offset } = req.query;

      const result = await threatIntelService.getRecentMatches(organizationId, {
        limit,
        offset
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[threatIntelController.getRecentMatches Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  }
};

module.exports = threatIntelController;
