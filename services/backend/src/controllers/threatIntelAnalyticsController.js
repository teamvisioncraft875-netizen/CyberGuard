const threatIntelAnalyticsService = require('../services/threatIntelAnalyticsService');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

/**
 * Controller for Threat Intelligence Analytics & Executive Reporting
 */
const threatIntelAnalyticsController = {
  /**
   * GET /api/v1/threat-intel/analytics/trends
   * Returns threat trends over 24h, 7d, and 30d.
   */
  async getTrends(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const trends = await threatIntelAnalyticsService.getThreatTrends(organizationId);

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'trends' }
      });

      return res.status(200).json(trends);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getTrends Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/top-indicators
   * Returns top indicator types aggregated by count.
   */
  async getTopIndicators(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const limit = req.query.limit ? parseInt(req.query.limit, 10) : 10;
      const results = await threatIntelAnalyticsService.getTopIndicators(organizationId, { limit });

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'top_indicators', limit }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getTopIndicators Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/top-domains
   * Returns top malicious domains correlated with incidents.
   */
  async getTopDomains(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const limit = req.query.limit ? parseInt(req.query.limit, 10) : 10;
      const results = await threatIntelAnalyticsService.getTopMaliciousDomains(organizationId, { limit });

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'top_domains', limit }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getTopDomains Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/top-ips
   * Returns top malicious IPs correlated with incidents.
   */
  async getTopIPs(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const limit = req.query.limit ? parseInt(req.query.limit, 10) : 10;
      const results = await threatIntelAnalyticsService.getTopMaliciousIPs(organizationId, { limit });

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'top_ips', limit }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getTopIPs Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/feed-performance
   * Returns feed performance and health statistics.
   */
  async getFeedPerformance(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const results = await threatIntelAnalyticsService.getFeedPerformanceMetrics(organizationId);

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'feed_performance' }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getFeedPerformance Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/ioc-stats
   * Returns IOC correlation effectiveness metrics.
   */
  async getIOCStats(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const results = await threatIntelAnalyticsService.getIOCMatchStatistics(organizationId);

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'ioc_stats' }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getIOCStats Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/provider-metrics
   * Returns reputation provider query, hit, and latency metrics.
   */
  async getProviderMetrics(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const results = await threatIntelAnalyticsService.getReputationProviderMetrics(organizationId);

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_ANALYTICS_VIEWED,
        resource_type: 'threat_intel_analytics',
        details: { type: 'provider_metrics' }
      });

      return res.status(200).json(results);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getProviderMetrics Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/threat-intel/analytics/executive-summary
   * Returns executive-level threat operations summary with metrics-derived recommendations.
   */
  async getExecutiveSummary(req, res) {
    try {
      const organizationId = req.user?.organization_id || null;
      const period = req.query.period || req.query.period_days || 'last_30_days';
      const summary = await threatIntelAnalyticsService.getExecutiveSummary(organizationId, { period });

      await auditLog({
        organization_id: organizationId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.THREAT_EXECUTIVE_REPORT_VIEWED,
        resource_type: 'threat_intel_executive_summary',
        details: {
          reporting_period: summary.reporting_period,
          total_indicators: summary.total_indicators,
          malicious_iocs_detected: summary.malicious_iocs_detected
        }
      });

      return res.status(200).json(summary);
    } catch (err) {
      console.error('[threatIntelAnalyticsController.getExecutiveSummary Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  }
};

module.exports = threatIntelAnalyticsController;
