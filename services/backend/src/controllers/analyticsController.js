/**
 * Analytics Controller — Powers Command Dashboard aggregate metric cards, charts, and MITRE maps.
 *
 * NOTE ON MOCK DATA:
 * The hardcoded values below serve strictly as temporary testing and demonstration mock data.
 * They allow the React Command Dashboard (overview stat cards, Recharts time-series graphs,
 * and MITRE ATT&CK coverage grids) to render correctly during prototype development before live
 * telemetry accumulates in PostgreSQL.
 *
 * FUTURE DATABASE INTEGRATION:
 * Once live incident ingestion is active, all metrics must be dynamically aggregated from:
 * 1. 'incidents' table: total counts, risk tiers, threat scenarios, and time-bucketed trends.
 * 2. 'mitre_mappings' table: technique frequencies and ATT&CK prevalence matrix.
 */

// Safely attempt to load database connection and models (handles offline / uninstalled dependencies gracefully)
let db = null;
let MitreMapping = null;
try {
  db = require('../config/db');
  MitreMapping = require('../models/MitreMapping');
} catch (err) {
  // Dependencies such as 'pg' may not be installed in lightweight or frontend-only dev environments
  db = null;
  MitreMapping = null;
}

/**
 * Temporary mock dataset representing baseline aggregate statistics.
 * TODO: Replace completely with dynamic SQL aggregation against the 'incidents' table.
 */
const FALLBACK_OVERVIEW_MOCK = {
  total_incidents: 142,
  active_threats: 8,
  resolved_threats: 134,
  risk_breakdown: {
    Safe: 45,
    Low: 32,
    Medium: 35,
    High: 22,
    Critical: 8
  },
  category_breakdown: {
    phishing: 54,
    malicious_url: 38,
    deepfake: 16,
    account_takeover: 21,
    system_anomaly: 13
  }
};

/**
 * Temporary mock dataset representing 7-day daily incident velocity.
 * TODO: Replace with dynamic daily time-bucketed COUNT(*) query grouped by created_at::date.
 */
const FALLBACK_TRENDS_MOCK = [
  { date: '2026-09-03', incidents: 12, high_critical: 2 },
  { date: '2026-09-04', incidents: 18, high_critical: 5 },
  { date: '2026-09-05', incidents: 9,  high_critical: 1 },
  { date: '2026-09-06', incidents: 24, high_critical: 8 },
  { date: '2026-09-07', incidents: 31, high_critical: 7 },
  { date: '2026-09-08', incidents: 19, high_critical: 3 },
  { date: '2026-09-09', incidents: 29, high_critical: 4 }
];

/**
 * Temporary mock dataset representing the 5 core threat scenarios mapped to MITRE ATT&CK techniques.
 * TODO: Replace with MitreMapping.getTechniqueAggregates() querying the 'mitre_mappings' table.
 */
const FALLBACK_MITRE_MOCK = [
  { technique_id: 'T1566', technique_name: 'Phishing', incident_count: 54 },
  { technique_id: 'T1110', technique_name: 'Brute Force / Credential Stuffing', incident_count: 21 },
  { technique_id: 'T1204', technique_name: 'User Execution - Malicious URL', incident_count: 38 },
  { technique_id: 'T1585', technique_name: 'Establish Accounts / Impersonation', incident_count: 16 },
  { technique_id: 'T1071', technique_name: 'Application Layer Protocol Anomaly', incident_count: 13 }
];

const analyticsController = {
  /**
   * GET /api/v1/analytics/overview
   * Returns high-level metrics: total incidents, active vs resolved, risk breakdown, and category breakdown.
   */
  async getOverview(req, res) {
    // TODO: Sourced from persisted PostgreSQL records in 'incidents' table once live data is stored.
    if (db && process.env.SUPABASE_DB_URL) {
      try {
        const { organization_id } = req.query;
        const queryText = `
          SELECT
            COUNT(*)::int AS total_incidents,
            COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::int AS active_threats,
            COUNT(*) FILTER (WHERE status = 'resolved')::int AS resolved_threats,
            COUNT(*) FILTER (WHERE risk_tier = 'Safe')::int AS safe_count,
            COUNT(*) FILTER (WHERE risk_tier = 'Low')::int AS low_count,
            COUNT(*) FILTER (WHERE risk_tier = 'Medium')::int AS medium_count,
            COUNT(*) FILTER (WHERE risk_tier = 'High')::int AS high_count,
            COUNT(*) FILTER (WHERE risk_tier = 'Critical')::int AS critical_count,
            COUNT(*) FILTER (WHERE threat_scenario = 'phishing')::int AS phishing_count,
            COUNT(*) FILTER (WHERE threat_scenario = 'malicious_url')::int AS malicious_url_count,
            COUNT(*) FILTER (WHERE threat_scenario = 'deepfake')::int AS deepfake_count,
            COUNT(*) FILTER (WHERE threat_scenario = 'account_takeover')::int AS account_takeover_count,
            COUNT(*) FILTER (WHERE threat_scenario = 'system_anomaly')::int AS system_anomaly_count
          FROM incidents
          ${organization_id ? 'WHERE org_id = $1' : ''};
        `;
        const params = organization_id ? [organization_id] : [];
        const { rows } = await db.query(queryText, params);

        if (rows && rows.length > 0 && rows[0].total_incidents > 0) {
          const row = rows[0];
          return res.status(200).json({
            total_incidents: row.total_incidents,
            active_threats: row.active_threats,
            resolved_threats: row.resolved_threats,
            risk_breakdown: {
              Safe: row.safe_count,
              Low: row.low_count,
              Medium: row.medium_count,
              High: row.high_count,
              Critical: row.critical_count
            },
            category_breakdown: {
              phishing: row.phishing_count,
              malicious_url: row.malicious_url_count,
              deepfake: row.deepfake_count,
              account_takeover: row.account_takeover_count,
              system_anomaly: row.system_anomaly_count
            }
          });
        }
      } catch (dbErr) {
        // Safe fallback if database is unseeded or temporarily unreachable in offline dev
        console.warn('[AnalyticsController] PostgreSQL query failed, using fallback mock data:', dbErr.message);
      }
    }

    // Return documented mock data for development, testing, and initial demo state
    return res.status(200).json(FALLBACK_OVERVIEW_MOCK);
  },

  /**
   * GET /api/v1/analytics/trends
   * Returns daily incident counts and high/critical counts over the last 7 days for trend charts.
   */
  async getTrends(req, res) {
    // TODO: Sourced from persisted PostgreSQL records in 'incidents' table once live data is stored.
    if (db && process.env.SUPABASE_DB_URL) {
      try {
        const { organization_id } = req.query;
        const queryText = `
          SELECT
            TO_CHAR(created_at::date, 'YYYY-MM-DD') AS date,
            COUNT(*)::int AS incidents,
            COUNT(*) FILTER (WHERE risk_tier IN ('High', 'Critical'))::int AS high_critical
          FROM incidents
          WHERE created_at >= NOW() - INTERVAL '7 days'
          ${organization_id ? 'AND org_id = $1' : ''}
          GROUP BY created_at::date
          ORDER BY date ASC;
        `;
        const params = organization_id ? [organization_id] : [];
        const { rows } = await db.query(queryText, params);

        if (rows && rows.length > 0) {
          return res.status(200).json(rows);
        }
      } catch (dbErr) {
        console.warn('[AnalyticsController] PostgreSQL trends query failed, using fallback mock data:', dbErr.message);
      }
    }

    // Return documented mock data for development, testing, and initial demo state
    return res.status(200).json(FALLBACK_TRENDS_MOCK);
  },

  /**
   * GET /api/v1/analytics/mitre
   * Returns frequency of detected MITRE ATT&CK techniques across all incidents.
   */
  async getMitreBreakdown(req, res) {
    // TODO: Sourced from persisted PostgreSQL records in 'mitre_mappings' table once live data is stored.
    if (MitreMapping && process.env.SUPABASE_DB_URL) {
      try {
        const rows = await MitreMapping.getTechniqueAggregates(10);
        if (rows && rows.length > 0) {
          return res.status(200).json(rows.map(r => ({
            technique_id: r.technique_id,
            technique_name: r.technique_name,
            incident_count: parseInt(r.incident_count, 10)
          })));
        }
      } catch (dbErr) {
        console.warn('[AnalyticsController] MITRE aggregates query failed, using fallback mock data:', dbErr.message);
      }
    }

    // Return documented mock data for development, testing, and initial demo state
    return res.status(200).json(FALLBACK_MITRE_MOCK);
  }
};

module.exports = analyticsController;
