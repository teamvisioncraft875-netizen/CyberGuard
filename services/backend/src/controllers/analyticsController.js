const db = require('../config/db');
const MitreMapping = require('../models/MitreMapping');

/**
 * Analytics Controller — Powers Command Dashboard aggregate metric cards, charts, and MITRE maps.
 */
const analyticsController = {
  /**
   * GET /api/v1/analytics/overview
   */
  async getOverview(req, res) {
    const isAdmin = req.user?.role === 'admin';
    const scopeClause = isAdmin ? 'WHERE organization_id = $1' : 'WHERE user_id = $1';
    const scopeParam = isAdmin ? req.user?.organization_id : req.user?.id;

    const text = `
      SELECT
        COUNT(*)::int AS total_incidents,
        COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::int AS active_threats,
        COUNT(*) FILTER (WHERE status = 'resolved')::int AS resolved_threats,
        COUNT(*) FILTER (WHERE risk_level = 'safe')::int AS safe_count,
        COUNT(*) FILTER (WHERE risk_level = 'low')::int AS low_count,
        COUNT(*) FILTER (WHERE risk_level = 'medium')::int AS medium_count,
        COUNT(*) FILTER (WHERE risk_level = 'high')::int AS high_count,
        COUNT(*) FILTER (WHERE risk_level = 'critical')::int AS critical_count,
        COUNT(*) FILTER (WHERE threat_type = 'phishing')::int AS phishing_count,
        COUNT(*) FILTER (WHERE threat_type = 'malicious_url')::int AS malicious_url_count,
        COUNT(*) FILTER (WHERE threat_type = 'deepfake')::int AS deepfake_count,
        COUNT(*) FILTER (WHERE threat_type = 'account_takeover')::int AS account_takeover_count,
        COUNT(*) FILTER (WHERE threat_type IN ('impersonation', 'technical_threat'))::int AS system_anomaly_count
      FROM incidents
      ${scopeClause};
    `;

    try {
      const { rows } = await db.query(text, [scopeParam]);
      const row = rows[0] || {};

      return res.status(200).json({
        total_incidents: row.total_incidents || 0,
        active_threats: row.active_threats || 0,
        resolved_threats: row.resolved_threats || 0,
        risk_breakdown: {
          Safe: row.safe_count || 0,
          Low: row.low_count || 0,
          Medium: row.medium_count || 0,
          High: row.high_count || 0,
          Critical: row.critical_count || 0
        },
        category_breakdown: {
          phishing: row.phishing_count || 0,
          malicious_url: row.malicious_url_count || 0,
          deepfake: row.deepfake_count || 0,
          account_takeover: row.account_takeover_count || 0,
          system_anomaly: row.system_anomaly_count || 0
        }
      });
    } catch (err) {
      console.error('[analyticsController.getOverview error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve analytics overview' });
    }
  },

  /**
   * GET /api/v1/analytics/trends
   */
  async getTrends(req, res) {
    const isAdmin = req.user?.role === 'admin';
    const scopeClause = isAdmin ? 'WHERE i.organization_id = $1' : 'WHERE i.user_id = $1';
    const scopeParam = isAdmin ? req.user?.organization_id : req.user?.id;

    const text = `
      SELECT
        TO_CHAR(DATE_TRUNC('day', i.created_at), 'YYYY-MM-DD') AS date,
        COUNT(*)::int AS incidents,
        COUNT(*) FILTER (WHERE i.risk_level IN ('high', 'critical'))::int AS high_critical
      FROM incidents i
      ${scopeClause}
      GROUP BY DATE_TRUNC('day', i.created_at)
      ORDER BY DATE_TRUNC('day', i.created_at) ASC;
    `;

    try {
      const { rows } = await db.query(text, [scopeParam]);
      const trends = (rows || []).map(r => ({
        date: r.date,
        incidents: r.incidents,
        high_critical: r.high_critical
      }));
      return res.status(200).json(trends);
    } catch (err) {
      console.error('[analyticsController.getTrends error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve analytics trends' });
    }
  },

  /**
   * GET /api/v1/analytics/mitre
   */
  async getMitreBreakdown(req, res) {
    const isAdmin = req.user?.role === 'admin';
    const filter = isAdmin
      ? { organization_id: req.user?.organization_id }
      : { user_id: req.user?.id };

    try {
      const aggregates = await MitreMapping.getTechniqueAggregates(filter);
      return res.status(200).json((aggregates || []).map(row => ({
        technique_id: row.technique_id,
        technique_name: row.technique_name,
        incident_count: parseInt(row.incident_count, 10)
      })));
    } catch (err) {
      console.error('[analyticsController.getMitreBreakdown error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve MITRE breakdown' });
    }
  }
};

module.exports = analyticsController;
