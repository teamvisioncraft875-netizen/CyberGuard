const ThreatIOC = require('../models/ThreatIOC');
const threatIntelService = require('../services/siem/threatIntelService');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const threatIntelController = {
  /**
   * POST /api/v1/threat-intel/iocs
   */
  async createIOC(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        ioc_type,
        ioc_value,
        confidence = 50,
        risk_score = null,
        threat_actor = null,
        malware_family = null,
        campaign_name = null,
        source_name = 'analyst',
        expiration_date = null,
        tags = []
      } = req.body;

      if (!ioc_type || !ThreatIOC.VALID_TYPES.includes(ioc_type.toLowerCase())) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: `Valid ioc_type is required. Supported: ${ThreatIOC.VALID_TYPES.join(', ')}`
        });
      }

      if (!ioc_value || typeof ioc_value !== 'string' || !ioc_value.trim()) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'ioc_value string is required'
        });
      }

      // Calculate dynamic risk score if not explicitly overridden
      const computedRisk = risk_score !== null && risk_score !== undefined
        ? parseInt(risk_score, 10)
        : threatIntelService.calculateRiskScore({
            confidence,
            campaignName: campaign_name,
            threatActor: threat_actor
          });

      const ioc = await ThreatIOC.createIOC({
        organization_id: orgId,
        ioc_type,
        ioc_value,
        confidence,
        risk_score: computedRisk,
        threat_actor,
        malware_family,
        campaign_name,
        source_name,
        expiration_date,
        tags
      });

      // Audit Log
      await auditLog({
        organization_id: orgId,
        user_id: req.user.id,
        action: AUDIT_ACTIONS.IOC_CREATED,
        resource_type: 'threat_ioc',
        resource_id: ioc.id,
        details: { ioc_type: ioc.ioc_type, ioc_value: ioc.ioc_value, risk_score: ioc.risk_score }
      });

      return res.status(201).json({
        data: ioc,
        message: 'Threat IOC registered successfully'
      });
    } catch (err) {
      console.error('[threatIntelController createIOC Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message || 'Failed to create IOC'
      });
    }
  },

  /**
   * GET /api/v1/threat-intel/iocs
   */
  async listIOCs(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        ioc_type,
        q,
        min_risk,
        include_expired,
        limit = 50,
        offset = 0
      } = req.query;

      const results = await ThreatIOC.searchIOCs({
        organization_id: orgId,
        ioc_type,
        q,
        min_risk,
        include_expired: include_expired === 'true' || include_expired === true,
        limit,
        offset
      });

      return res.status(200).json({
        data: results.data,
        total: results.total,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });
    } catch (err) {
      console.error('[threatIntelController listIOCs Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to search IOCs'
      });
    }
  },

  /**
   * GET /api/v1/threat-intel/iocs/:id
   */
  async getIOCById(req, res) {
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
          error: 'INVALID_ID',
          message: 'Invalid IOC UUID format'
        });
      }

      const ioc = await ThreatIOC.getIOC(id, orgId);
      if (!ioc) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'IOC not found'
        });
      }

      return res.status(200).json({ data: ioc });
    } catch (err) {
      console.error('[threatIntelController getIOCById Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve IOC'
      });
    }
  },

  /**
   * PATCH /api/v1/threat-intel/iocs/:id
   */
  async updateIOC(req, res) {
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
          error: 'INVALID_ID',
          message: 'Invalid IOC UUID format'
        });
      }

      const existing = await ThreatIOC.getIOC(id, orgId);
      if (!existing) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'IOC not found'
        });
      }

      const updated = await ThreatIOC.updateIOC(id, orgId, req.body);

      // Audit Log
      await auditLog({
        organization_id: orgId,
        user_id: req.user.id,
        action: AUDIT_ACTIONS.IOC_UPDATED,
        resource_type: 'threat_ioc',
        resource_id: id,
        details: req.body
      });

      return res.status(200).json({
        data: updated,
        message: 'IOC updated successfully'
      });
    } catch (err) {
      console.error('[threatIntelController updateIOC Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to update IOC'
      });
    }
  },

  /**
   * DELETE /api/v1/threat-intel/iocs/:id
   */
  async deleteIOC(req, res) {
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
          error: 'INVALID_ID',
          message: 'Invalid IOC UUID format'
        });
      }

      const deleted = await ThreatIOC.deleteIOC(id, orgId);
      if (!deleted) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'IOC not found'
        });
      }

      // Audit Log
      await auditLog({
        organization_id: orgId,
        user_id: req.user.id,
        action: AUDIT_ACTIONS.IOC_DELETED,
        resource_type: 'threat_ioc',
        resource_id: id,
        details: { deleted: true }
      });

      return res.status(200).json({
        message: 'IOC deleted successfully',
        id
      });
    } catch (err) {
      console.error('[threatIntelController deleteIOC Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to delete IOC'
      });
    }
  },

  /**
   * GET /api/v1/threat-intel/sightings
   */
  async listSightings(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const {
        ioc_id,
        start_date,
        end_date,
        limit = 50,
        offset = 0
      } = req.query;

      const results = await ThreatIOC.getSightings({
        organization_id: orgId,
        ioc_id,
        startDate: start_date,
        endDate: end_date,
        limit,
        offset
      });

      return res.status(200).json({
        data: results.data,
        total: results.total,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });
    } catch (err) {
      console.error('[threatIntelController listSightings Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve sightings'
      });
    }
  },

  /**
   * GET /api/v1/threat-intel/dashboard
   */
  async getDashboard(req, res) {
    try {
      const orgId = req.user?.organization_id;
      if (!orgId) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Access denied: Valid organization_id is required'
        });
      }

      const stats = await ThreatIOC.getIOCStatistics(orgId);
      return res.status(200).json(stats);
    } catch (err) {
      console.error('[threatIntelController getDashboard Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve threat intelligence statistics'
      });
    }
  },

  // Legacy Threat Feed API Handlers (Backward Compatibility)
  async listIndicators(req, res) {
    try {
      const legacyService = require('../services/threatIntelService');
      const orgId = req.user?.organization_id;
      const result = await legacyService.getIndicators({ organization_id: orgId, ...req.query });
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  async getIndicator(req, res) {
    try {
      const legacyService = require('../services/threatIntelService');
      const orgId = req.user?.organization_id;
      const indicator = await legacyService.getIndicatorById(req.params.id, orgId);
      if (!indicator) return res.status(404).json({ error: 'NOT_FOUND', message: 'Indicator not found' });
      return res.status(200).json(indicator);
    } catch (err) {
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  async getFeedHealth(req, res) {
    try {
      const legacyService = require('../services/threatIntelService');
      const health = await legacyService.getFeedHealth(req.user?.organization_id);
      return res.status(200).json(health);
    } catch (err) {
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  async getFeedStatistics(req, res) {
    try {
      const legacyService = require('../services/threatIntelService');
      const stats = await legacyService.getFeedStatistics(req.user?.organization_id);
      return res.status(200).json(stats);
    } catch (err) {
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  },

  async getRecentMatches(req, res) {
    try {
      const legacyService = require('../services/threatIntelService');
      const matches = await legacyService.getRecentMatches(req.user?.organization_id, req.query);
      return res.status(200).json(matches);
    } catch (err) {
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
    }
  }
};

module.exports = threatIntelController;
