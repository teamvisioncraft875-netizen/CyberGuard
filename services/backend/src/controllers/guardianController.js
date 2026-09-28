const GuardianLink = require('../models/GuardianLink');
const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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
        status: 'pending'
      });

      return res.status(201).json({
        link_id: link?.link_id || link?.id || 'lnk_' + Date.now(),
        status: link?.status || 'pending',
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
   * POST /api/v1/guardian/link/:id/accept
   */
  async acceptGuardianLink(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Guardian link not found'
      });
    }

    try {
      const link = await GuardianLink.findById(id);

      // Dependent verification: only dependent_user_id on this link can accept
      if (!link || link.dependent_user_id !== req.user?.id) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Guardian link not found'
        });
      }

      // Check current link status
      if (link.status !== 'pending') {
        return res.status(400).json({
          error: 'INVALID_STATUS',
          message: `Cannot accept guardian link with status '${link.status}'`
        });
      }

      const updated = await GuardianLink.updateStatus(id, 'active');
      return res.status(200).json({
        link_id: updated?.link_id || updated?.id || id,
        status: updated?.status || 'active',
        guardian_user_id: updated?.guardian_user_id || link.guardian_user_id,
        dependent_user_id: updated?.dependent_user_id || link.dependent_user_id,
        created_at: updated?.created_at || link.created_at
      });
    } catch (err) {
      console.error('[guardianController.acceptGuardianLink error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to accept guardian link' });
    }
  },

  /**
   * POST /api/v1/guardian/link/:id/decline
   */
  async declineGuardianLink(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Guardian link not found'
      });
    }

    try {
      const link = await GuardianLink.findById(id);

      // Dependent verification: only dependent_user_id on this link can decline
      if (!link || link.dependent_user_id !== req.user?.id) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Guardian link not found'
        });
      }

      // Check current link status
      if (link.status !== 'pending') {
        return res.status(400).json({
          error: 'INVALID_STATUS',
          message: `Cannot decline guardian link with status '${link.status}'`
        });
      }

      const updated = await GuardianLink.updateStatus(id, 'revoked');
      return res.status(200).json({
        link_id: updated?.link_id || updated?.id || id,
        status: updated?.status || 'revoked',
        guardian_user_id: updated?.guardian_user_id || link.guardian_user_id,
        dependent_user_id: updated?.dependent_user_id || link.dependent_user_id,
        created_at: updated?.created_at || link.created_at
      });
    } catch (err) {
      console.error('[guardianController.declineGuardianLink error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to decline guardian link' });
    }
  },

  /**
   * Alias for declineGuardianLink
   */
  revokeGuardianLink(req, res) {
    return guardianController.declineGuardianLink(req, res);
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
