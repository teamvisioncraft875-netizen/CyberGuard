const SiemDetectionRule = require('../models/SiemDetectionRule');
const SiemDetectionHit = require('../models/SiemDetectionHit');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for SIEM Correlation Rules & Detection Hits
 */
const siemDetectionController = {
  /**
   * GET /api/v1/siem/detections
   * Lists correlation detection hits with pagination and optional filters
   */
  async listDetections(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { rule_id, limit = 50, offset = 0, start_date, end_date } = req.query;

      if (rule_id && !UUID_REGEX.test(rule_id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'rule_id must be a valid UUID'
        });
      }

      const [hits, total] = await Promise.all([
        SiemDetectionHit.findByOrg(orgId, {
          rule_id: rule_id || null,
          limit: parseInt(limit, 10) || 50,
          offset: parseInt(offset, 10) || 0,
          startDate: start_date || null,
          endDate: end_date || null
        }),
        SiemDetectionHit.countByOrg(orgId, {
          rule_id: rule_id || null,
          startDate: start_date || null,
          endDate: end_date || null
        })
      ]);

      return res.status(200).json({
        data: hits,
        pagination: {
          total,
          limit: parseInt(limit, 10) || 50,
          offset: parseInt(offset, 10) || 0
        }
      });
    } catch (err) {
      console.error('[siemDetectionController listDetections Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve detection hits'
      });
    }
  },

  /**
   * GET /api/v1/siem/detections/:id
   * Returns a single detection hit by ID with associated rule & incident details
   */
  async getDetectionById(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Detection hit ID must be a valid UUID'
        });
      }

      const hit = await SiemDetectionHit.findById(id, orgId);
      if (!hit) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Detection hit not found in your organization'
        });
      }

      return res.status(200).json({ data: hit });
    } catch (err) {
      console.error('[siemDetectionController getDetectionById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve detection hit details'
      });
    }
  },

  /**
   * GET /api/v1/siem/rules
   * Lists active and template detection rules available to the tenant
   */
  async listRules(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const enabledOnly = req.query.enabled === 'true';
      const rules = await SiemDetectionRule.findByOrg(orgId, { enabledOnly });

      return res.status(200).json({
        data: rules,
        total: rules.length
      });
    } catch (err) {
      console.error('[siemDetectionController listRules Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve detection rules'
      });
    }
  },

  /**
   * POST /api/v1/siem/rules
   * Creates a new custom detection rule for the tenant
   */
  async createRule(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { name, description, enabled = true, severity = 'medium', rule_type, conditions = {} } = req.body;

      if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Rule name is required'
        });
      }

      if (!rule_type || typeof rule_type !== 'string' || !rule_type.trim()) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'rule_type is required (e.g., threshold, sequence, pattern)'
        });
      }

      const validSeverities = ['low', 'medium', 'high', 'critical'];
      const resolvedSeverity = validSeverities.includes(String(severity).toLowerCase())
        ? String(severity).toLowerCase()
        : 'medium';

      const rule = await SiemDetectionRule.create({
        organization_id: orgId,
        name: name.trim(),
        description: description ? String(description).trim() : '',
        enabled: Boolean(enabled),
        severity: resolvedSeverity,
        rule_type: rule_type.trim(),
        conditions
      });

      // Audit log
      await auditLog({
        organization_id: orgId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.SIEM_RULE_CREATED,
        resource_type: 'siem_detection_rule',
        resource_id: rule.id,
        details: {
          name: rule.name,
          rule_type: rule.rule_type,
          severity: rule.severity
        }
      });

      return res.status(201).json({
        message: 'Detection rule created successfully',
        data: rule
      });
    } catch (err) {
      console.error('[siemDetectionController createRule Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to create detection rule'
      });
    }
  },

  /**
   * PATCH /api/v1/siem/rules/:id
   * Updates an existing detection rule (enable/disable, conditions, severity)
   */
  async updateRule(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Rule ID must be a valid UUID'
        });
      }

      const existingRule = await SiemDetectionRule.findById(id, orgId);
      if (!existingRule) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Detection rule not found'
        });
      }

      const updatedRule = await SiemDetectionRule.update(id, orgId, req.body);

      // Audit log
      await auditLog({
        organization_id: orgId,
        user_id: req.user?.id || null,
        actor_type: 'user',
        action: AUDIT_ACTIONS.SIEM_RULE_UPDATED,
        resource_type: 'siem_detection_rule',
        resource_id: id,
        details: {
          changes: req.body,
          rule_name: updatedRule.name
        }
      });

      return res.status(200).json({
        message: 'Detection rule updated successfully',
        data: updatedRule
      });
    } catch (err) {
      console.error('[siemDetectionController updateRule Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to update detection rule'
      });
    }
  }
};

module.exports = siemDetectionController;
