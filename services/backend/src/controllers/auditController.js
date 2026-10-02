const AuditLog = require('../models/AuditLog');

/**
 * Audit Controller — Query organization audit trails.
 */
const auditController = {
  /**
   * GET /api/v1/audit-logs
   * Retrieves paginated audit logs scoped strictly to the requesting administrator's organization.
   * Admins with no organization get an empty result set.
   */
  async listAuditLogs(req, res) {
    const orgId = req.user?.organization_id;

    const parsedLimit = parseInt(req.query.limit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit > 0
      ? Math.min(parsedLimit, 100)
      : 25;

    const parsedOffset = parseInt(req.query.offset, 10);
    const offset = Number.isInteger(parsedOffset) && parsedOffset >= 0
      ? parsedOffset
      : 0;

    // An admin with no organization gets an empty result
    if (!orgId) {
      return res.status(200).json({
        total: 0,
        limit,
        offset,
        logs: []
      });
    }

    const { action, resource_type, user_id, from, to } = req.query;

    try {
      const result = await AuditLog.list({
        organization_id: orgId,
        action,
        resource_type,
        user_id,
        from,
        to,
        limit,
        offset
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[auditController.listAuditLogs Error]', err.message);
      return res.status(500).json({
        error: 'DB_ERROR',
        message: 'Failed to retrieve audit logs'
      });
    }
  }
};

module.exports = auditController;
