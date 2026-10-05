const attackSurfaceService = require('../services/attackSurfaceService');
const ResponseAction = require('../models/ResponseAction');
const db = require('../config/db');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for Attack Surface Discovery APIs (Phase B + Phase C)
 */
const attackSurfaceController = {

  // ─────────────────────────────────────────────
  // PHASE B ENDPOINTS (unchanged)
  // ─────────────────────────────────────────────

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
  },

  // ─────────────────────────────────────────────
  // PHASE C ENDPOINTS
  // ─────────────────────────────────────────────

  /**
   * GET /api/v1/admin/attack-surface/dashboard
   * Returns summary cards, risk distribution, category breakdown, top risky assets.
   */
  async getDashboard(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const data = await attackSurfaceService.getDashboard({ organization_id });
      return res.json(data);
    } catch (err) {
      console.error('[attackSurfaceController.getDashboard Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/admin/attack-surface/exposures/:id
   * Returns full exposure detail: port metadata, MITRE mappings, linked incident.
   */
  async getExposureById(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { id } = req.params;
      if (!id || !UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Exposure not found' });
      }

      const exposure = await attackSurfaceService.getExposureById({
        organization_id,
        exposure_id: id
      });

      if (!exposure) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Exposure not found' });
      }

      return res.json(exposure);
    } catch (err) {
      console.error('[attackSurfaceController.getExposureById Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/admin/attack-surface/analytics
   * Query parameters: days (default 30, max 90)
   * Returns time-series trend data: exposure_trend, incident_trend, mitigation_trend, category_breakdown.
   */
  async getAnalytics(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { days } = req.query;

      const data = await attackSurfaceService.getAnalytics({ organization_id, days });
      return res.json(data);
    } catch (err) {
      console.error('[attackSurfaceController.getAnalytics Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/admin/attack-surface/scans
   * Query parameters: device_id, limit, offset
   * Returns paginated fleet scan history (agent_commands of type scan_attack_surface).
   */
  async getScanHistory(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { device_id, limit, offset } = req.query;

      const result = await attackSurfaceService.getScanHistory({
        organization_id,
        device_id,
        limit,
        offset
      });

      return res.json(result);
    } catch (err) {
      console.error('[attackSurfaceController.getScanHistory Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/admin/response-actions
   * Alias list delegated to responseAdminController; this method exists for direct Phase C test coverage.
   * Query parameters: incident_id, status, limit, offset
   */
  async listResponseActions(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { incident_id, status, limit, offset } = req.query;

      const result = await ResponseAction.list({
        organization_id,
        incident_id,
        status,
        limit,
        offset
      });

      return res.status(200).json({
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        actions: result.actions
      });
    } catch (err) {
      console.error('[attackSurfaceController.listResponseActions Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/admin/attack-surface/response-actions/:id
   * Allows an analyst to approve or reject a proposed response action (shadow mode).
   * Body: { action: 'approve' | 'reject', reason?: string }
   *
   * SAFETY: All actions remain in shadow/proposed mode until this endpoint explicitly approves them.
   * No automatic execution occurs — analyst approval is required.
   */
  async updateResponseAction(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { id } = req.params;
      if (!id || !UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Response action not found' });
      }

      const { action, reason } = req.body || {};
      if (!action || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: "action must be 'approve' or 'reject'"
        });
      }

      // Fetch existing action and verify tenant ownership
      const existing = await db.query(
        `SELECT * FROM public.response_actions WHERE id = $1 AND organization_id = $2;`,
        [id, organization_id]
      );

      if (existing.rows.length === 0) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Response action not found' });
      }

      const currentAction = existing.rows[0];

      // Only proposed/pending_approval actions can be approved or rejected
      if (!['proposed', 'pending_approval'].includes(currentAction.status)) {
        return res.status(409).json({
          error: 'CONFLICT',
          message: `Cannot ${action} a response action in status '${currentAction.status}'`
        });
      }

      const newStatus = action === 'approve' ? 'approved' : 'rejected';
      const now = new Date().toISOString();

      const updated = await db.query(
        `UPDATE public.response_actions
         SET status = $1,
             approved_by_id = $2,
             approved_at = $3,
             result = COALESCE(result, '{}'::jsonb) || $4::jsonb
         WHERE id = $5 AND organization_id = $6
         RETURNING *;`,
        [
          newStatus,
          req.user.id,
          now,
          JSON.stringify({ analyst_reason: reason || null }),
          id,
          organization_id
        ]
      );

      if (updated.rows.length === 0) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Response action not found' });
      }

      // Audit log
      auditLog({
        organization_id,
        user_id: req.user.id,
        actor_type: 'admin',
        action: action === 'approve'
          ? AUDIT_ACTIONS.RESPONSE_ACTION_APPROVED
          : AUDIT_ACTIONS.RESPONSE_ACTION_REJECTED,
        resource_type: 'response_action',
        resource_id: id,
        details: {
          action_type: currentAction.action_type,
          previous_status: currentAction.status,
          new_status: newStatus,
          reason: reason || null
        },
        ip_address: req.ip
      });

      return res.json({
        id: updated.rows[0].id,
        status: updated.rows[0].status,
        approved_by_id: updated.rows[0].approved_by_id,
        approved_at: updated.rows[0].approved_at,
        action_type: updated.rows[0].action_type,
        action_mode: updated.rows[0].action_mode
      });
    } catch (err) {
      console.error('[attackSurfaceController.updateResponseAction Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  /**
   * PATCH /api/v1/admin/attack-surface/incidents/:id
   * Allows an analyst to update status, assign the incident, or add a note.
   * Body: { status?: string, assigned_to_id?: string, note?: string }
   */
  async updateIncident(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Organization identity required' });
      }

      const { id } = req.params;
      if (!id || !UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Incident not found' });
      }

      const { status, assigned_to_id, note } = req.body || {};

      const VALID_STATUSES = ['open', 'investigating', 'resolved'];
      if (status && !VALID_STATUSES.includes(status)) {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: `status must be one of: ${VALID_STATUSES.join(', ')}`
        });
      }

      // Verify tenant ownership
      const existing = await db.query(
        `SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;`,
        [id, organization_id]
      );

      if (existing.rows.length === 0) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Incident not found' });
      }

      const currentIncident = existing.rows[0];

      // Build the update dynamically — only set fields provided in body
      const setClauses = [];
      const params = [];
      let idx = 1;

      if (status) {
        setClauses.push(`status = $${idx++}`);
        params.push(status);
        if (status === 'resolved') {
          setClauses.push(`resolved_by = $${idx++}`);
          params.push(req.user.id);
          setClauses.push(`resolved_at = NOW()`);
        }
      }

      // NOTE: incidents table does not have an assigned_to_id column.
      // Analyst assignment is recorded as an audit event for forensic traceability.
      if (assigned_to_id) {
        if (!UUID_REGEX.test(assigned_to_id)) {
          return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'Invalid assigned_to_id' });
        }
        const assigneeRes = await db.query(
          `SELECT id FROM public.users WHERE id = $1 AND organization_id = $2;`,
          [assigned_to_id, organization_id]
        );
        if (assigneeRes.rows.length === 0) {
          return res.status(400).json({
            error: 'VALIDATION_ERROR',
            message: 'Assignee not found in your organization'
          });
        }
        // Record assignment as an audit event
        auditLog({
          organization_id,
          user_id: req.user.id,
          actor_type: 'admin',
          action: 'incident:analyst_assigned',
          resource_type: 'incident',
          resource_id: id,
          details: { assigned_to_id, assigned_by_id: req.user.id },
          ip_address: req.ip
        });
      }

      if (setClauses.length === 0 && !note && !assigned_to_id) {
        return res.status(400).json({
          error: 'VALIDATION_ERROR',
          message: 'Provide at least one of: status, assigned_to_id, note'
        });
      }

      let updatedIncident = currentIncident;

      if (setClauses.length > 0) {
        params.push(id, organization_id);
        const updateRes = await db.query(
          `UPDATE public.incidents
           SET ${setClauses.join(', ')}
           WHERE id = $${idx++} AND organization_id = $${idx++}
           RETURNING *;`,
          params
        );

        if (updateRes.rows.length === 0) {
          return res.status(404).json({ error: 'NOT_FOUND', message: 'Incident not found' });
        }
        updatedIncident = updateRes.rows[0];
      }

      // Append analyst note to audit log (used as note trail since incidents table
      // does not have a native notes column — stored as audit events)
      if (note && typeof note === 'string' && note.trim()) {
        auditLog({
          organization_id,
          user_id: req.user.id,
          actor_type: 'admin',
          action: 'incident:note_added',
          resource_type: 'incident',
          resource_id: id,
          details: {
            note: note.trim().substring(0, 1000),
            analyst_id: req.user.id
          },
          ip_address: req.ip
        });
      }

      // Audit status change
      if (status && status !== currentIncident.status) {
        auditLog({
          organization_id,
          user_id: req.user.id,
          actor_type: 'admin',
          action: AUDIT_ACTIONS.INCIDENT_STATUS_UPDATED,
          resource_type: 'incident',
          resource_id: id,
          details: {
            previous_status: currentIncident.status,
            new_status: status
          },
          ip_address: req.ip
        });
      }

      return res.json({
        id: updatedIncident.id,
        status: updatedIncident.status,
        assigned_to_id: assigned_to_id || null,
        resolved_by: updatedIncident.resolved_by || null,
        resolved_at: updatedIncident.resolved_at || null,
        updated: true
      });
    } catch (err) {
      console.error('[attackSurfaceController.updateIncident Error]', err.message);
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  }
};

module.exports = attackSurfaceController;
