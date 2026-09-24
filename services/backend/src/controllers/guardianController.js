const GuardianLink = require('../models/GuardianLink');
const db = require('../config/db');

/**
 * Guardian Controller — Supports Guardian Mode for family and dependent protection.
 */
const guardianController = {
  /**
   * POST /api/v1/guardian/link
   */
  async linkDependent(req, res) {
    const { guardian_user_id, dependent_user_id } = req.body;

    // Validate request shape
    if (!guardian_user_id || !dependent_user_id) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'Both guardian_user_id and dependent_user_id are required'
      });
    }
    if (guardian_user_id === dependent_user_id) {
      return res.status(400).json({
        error: 'INVALID_LINK',
        message: 'A user cannot link to themselves as a dependent'
      });
    }

    // Reject unless req.user.id matches either guardian_user_id or dependent_user_id
    if (req.user?.id !== guardian_user_id && req.user?.id !== dependent_user_id) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'You can only link your own account as either guardian or dependent'
      });
    }

    try {
      const link = await GuardianLink.create({
        guardian_user_id,
        dependent_user_id,
        status: 'active'
      });

      return res.status(201).json({
        link_id: link?.link_id || link?.id || 'lnk_' + Date.now(),
        status: link?.status || 'active',
        guardian_user_id: link?.guardian_user_id || guardian_user_id,
        dependent_user_id: link?.dependent_user_id || dependent_user_id,
        created_at: link?.created_at || new Date().toISOString()
      });
    } catch (err) {
      console.error('[guardianController.linkDependent error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to create guardian link' });
    }
  },

  /**
   * GET /api/v1/guardian/alerts
   */
  async getDependentAlerts(req, res) {
    try {
      // 1. Retrieve active dependents via GuardianLink.findByGuardianId(req.user.id)
      const activeLinks = await GuardianLink.findByGuardianId(req.user?.id);
      const dependentIds = (activeLinks || []).map(l => l.dependent_user_id);

      if (dependentIds.length === 0) {
        return res.status(200).json([]);
      }

      // 2. Query high/critical incidents scoped with WHERE user_id = ANY(dependentIds) AND risk_level IN ('high', 'critical')
      const text = `
        SELECT i.id AS alert_id,
               i.user_id AS dependent_user_id,
               u.email AS dependent_email,
               split_part(u.email, '@', 1) AS dependent_name,
               i.risk_level,
               i.threat_type,
               i.explanation,
               i.created_at AS timestamp
        FROM incidents i
        JOIN users u ON u.id = i.user_id
        WHERE i.user_id = ANY($1::uuid[]) AND i.risk_level IN ('high', 'critical')
        ORDER BY i.created_at DESC;
      `;
      const result = await db.query(text, [dependentIds]);

      const alerts = result.rows.map(row => ({
        alert_id: row.alert_id,
        dependent_user_id: row.dependent_user_id,
        dependent_name: row.dependent_name || row.dependent_email || 'Dependent',
        risk_level: row.risk_level ? row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1) : 'High',
        threat_type: row.threat_type,
        explanation: row.explanation,
        recommended_action: 'Review threat details and contact dependent immediately.',
        timestamp: row.timestamp
      }));

      return res.status(200).json(alerts);
    } catch (err) {
      console.error('[guardianController.getDependentAlerts error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve dependent alerts' });
    }
  }
};

module.exports = guardianController;
