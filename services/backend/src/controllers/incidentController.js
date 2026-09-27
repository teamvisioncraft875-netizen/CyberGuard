const Incident = require('../models/Incident');
const DetectionSignal = require('../models/DetectionSignal');
const RecommendedAction = require('../models/RecommendedAction');
const MitreMapping = require('../models/MitreMapping');
const IncidentEvidence = require('../models/IncidentEvidence');

const VALID_INCIDENT_STATUSES = Object.freeze(['open', 'investigating', 'resolved']);

/**
 * Incident Controller — Triage and investigation endpoints for Command Dashboard.
 */
const incidentController = {
  /**
   * GET /api/v1/incidents
   */
  async listIncidents(req, res) {
    const parsedLimit = parseInt(req.query.limit, 10);
    const limit = Number.isInteger(parsedLimit) && parsedLimit > 0
      ? Math.min(parsedLimit, 100)
      : 25;

    const parsedOffset = parseInt(req.query.offset, 10);
    const offset = Number.isInteger(parsedOffset) && parsedOffset >= 0
      ? parsedOffset
      : 0;

    const { risk_level, status } = req.query;
    const category = req.query.threat_type || req.query.category;

    // Strict tenant isolation:
    // Non-admin (individual / employee) is forced to their own user_id.
    // Admin is forced to their own organization_id (ignoring any client-supplied organization_id).
    const filter = { risk_level, category, status, limit, offset };
    if (req.user?.role === 'admin') {
      filter.organization_id = req.user.organization_id;
    } else {
      filter.user_id = req.user?.id;
    }

    try {
      const [incidents, total] = await Promise.all([
        Incident.findAll(filter),
        Incident.count(filter)
      ]);

      if (incidents.length === 0) {
        return res.status(200).json({
          total,
          limit,
          offset,
          incidents: [],
          data: []
        });
      }

      // Batch-fetch child records for all incidents in this page (no N+1 queries)
      const incidentIds = incidents.map((inc) => inc.id);
      const [actions, mitre] = await Promise.all([
        RecommendedAction.findByIncidentIds(incidentIds),
        MitreMapping.findByIncidentIds(incidentIds)
      ]);

      const actionsByIncident = new Map();
      for (const action of actions) {
        if (!actionsByIncident.has(action.incident_id)) {
          actionsByIncident.set(action.incident_id, []);
        }
        actionsByIncident.get(action.incident_id).push({
          id: action.id,
          action_type: action.action_type,
          action_status: action.action_status,
          created_at: action.created_at
        });
      }

      const mitreByIncident = new Map();
      for (const mapping of mitre) {
        if (!mitreByIncident.has(mapping.incident_id)) {
          mitreByIncident.set(mapping.incident_id, []);
        }
        mitreByIncident.get(mapping.incident_id).push({
          id: mapping.id,
          technique_id: mapping.technique_id,
          technique_name: mapping.technique_name
        });
      }

      const formattedIncidents = incidents.map((inc) => ({
        id: inc.id,
        threat_type: inc.threat_type,
        source_type: inc.source_type,
        risk_level: inc.risk_level,
        risk_score: typeof inc.risk_score === 'number' ? inc.risk_score : Number(inc.risk_score),
        explanation: inc.explanation,
        status: inc.status,
        created_at: inc.created_at,
        recommended_actions: actionsByIncident.get(inc.id) || [],
        mitre_mappings: mitreByIncident.get(inc.id) || []
      }));

      return res.status(200).json({
        total,
        limit,
        offset,
        incidents: formattedIncidents,
        data: formattedIncidents
      });
    } catch (err) {
      console.error('[incidentController.listIncidents error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve incidents' });
    }
  },

  /**
   * GET /api/v1/incidents/:id
   */
  async getIncidentById(req, res) {
    const { id } = req.params;

    // UUID format check: return 404 cleanly instead of triggering DB type syntax error
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident not found'
      });
    }

    // Strict tenant isolation:
    // Non-admin can only fetch their own incident (404 if it belongs to someone else).
    // Admin can only fetch incidents within their own organization_id (404 if outside org).
    const scope = {};
    if (req.user?.role === 'admin') {
      scope.organization_id = req.user.organization_id || null;
      if (!scope.organization_id) {
        scope.user_id = req.user.id;
      }
    } else {
      scope.user_id = req.user?.id;
    }

    try {
      const incident = await Incident.findByIdAndScope(id, scope);
      if (!incident) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      // Concurrently fetch detection signals, evidence, recommended actions, and MITRE mappings
      const [signalsRows, evidenceRows, actionsRows, mitreRows] = await Promise.all([
        DetectionSignal.findByIncidentId(incident.id),
        IncidentEvidence.findByIncidentId(incident.id),
        RecommendedAction.findByIncidentId(incident.id),
        MitreMapping.findByIncidentId(incident.id)
      ]);

      const detection_signals = signalsRows.map((s) => ({
        signal_name: s.signal_name,
        signal_value: s.signal_value,
        weight: s.weight !== null && s.weight !== undefined ? Number(s.weight) : null
      }));

      const recommended_actions = actionsRows.map((a) => ({
        id: a.id,
        action_type: a.action_type,
        action_status: a.action_status,
        created_at: a.created_at
      }));

      const mitre_mappings = mitreRows.map((m) => ({
        id: m.id,
        technique_id: m.technique_id,
        technique_name: m.technique_name
      }));

      return res.status(200).json({
        id: incident.id,
        user_id: incident.user_id,
        organization_id: incident.organization_id,
        threat_type: incident.threat_type,
        source_type: incident.source_type,
        risk_level: incident.risk_level,
        risk_score: typeof incident.risk_score === 'number' ? incident.risk_score : Number(incident.risk_score),
        explanation: incident.explanation,
        status: incident.status,
        resolved_by: incident.resolved_by,
        resolved_at: incident.resolved_at,
        created_at: incident.created_at,
        recommended_actions,
        mitre_mappings,
        detection_signals,
        evidence: evidenceRows || []
      });
    } catch (err) {
      console.error('[incidentController.getIncidentById error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to retrieve incident details' });
    }
  },

  /**
   * PATCH /api/v1/incidents/:id
   */
  async updateIncidentStatus(req, res) {
    const { id } = req.params;
    const { status } = req.body;

    if (!status || !VALID_INCIDENT_STATUSES.includes(status)) {
      return res.status(400).json({
        error: 'INVALID_STATUS',
        message: "Status must be one of: 'open', 'investigating', 'resolved'"
      });
    }

    // Force organization scope: admin can only update incidents within their own organization
    const orgId = req.user?.organization_id || null;

    try {
      const updated = await Incident.updateStatus(id, status, req.user?.id, orgId);
      if (!updated) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found or does not belong to your organization'
        });
      }

      return res.status(200).json({
        id: updated.id,
        status: updated.status,
        resolved_by: updated.resolved_by || req.user?.id,
        updated_at: updated.resolved_at || updated.updated_at || new Date().toISOString()
      });
    } catch (err) {
      console.error('[incidentController.updateIncidentStatus error]', err.message);
      return res.status(500).json({ error: 'DB_ERROR', message: 'Failed to update incident status' });
    }
  }
};

module.exports = incidentController;
