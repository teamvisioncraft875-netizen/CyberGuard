/**
 * Incident Controller — Triage and investigation endpoints for Command Dashboard.
 */
const incidentController = {
  /**
   * GET /api/v1/incidents
   */
  async listIncidents(req, res) {
    const { risk_level, category, status, organization_id } = req.query;

    // RBAC check: Non-admin users cannot query cross-tenant org data
    if (organization_id && req.user && req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Non-admin users cannot query organization-wide incidents'
      });
    }

    // TODO: Query PostgreSQL via Incident.findAll({ risk_level, category, status, organization_id })
    return res.status(200).json([
      {
        id: 'inc_f72a19b4-3c81-49e0-81f3-241b2c1a89d2',
        type: 'phishing',
        risk_level: 'High',
        explanation: 'High Risk: Message demands immediate credential verification under threat of suspension.',
        recommended_action: 'Quarantine email and block sender domain.',
        status: 'open',
        timestamp: '2026-09-09T08:10:00Z'
      },
      {
        id: 'inc_b12c84e1-2f73-42a9-91a0-384c2f1a91e4',
        type: 'malicious_url',
        risk_level: 'Critical',
        explanation: 'Critical Risk: Domain flagged on active malware blacklists.',
        recommended_action: 'Block domain network-wide.',
        status: 'investigating',
        timestamp: '2026-09-09T07:45:00Z'
      }
    ]);
  },

  /**
   * PATCH /api/v1/incidents/:id
   */
  async updateIncidentStatus(req, res) {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['open', 'investigating', 'resolved'];
    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({
        error: 'INVALID_STATUS',
        message: "Status must be one of: 'open', 'investigating', 'resolved'"
      });
    }

    // TODO: Invoke Incident.updateStatus(id, status, req.user?.id) and broadcast triage update via WebSocket

    return res.status(200).json({
      id,
      status,
      resolved_by: req.user?.id || 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d',
      updated_at: new Date().toISOString()
    });
  }
};

module.exports = incidentController;
