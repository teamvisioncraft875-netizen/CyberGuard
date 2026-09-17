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

    // TODO: Verify existence of dependent user, insert link via GuardianLink.create(), and send mobile confirmation notification

    return res.status(201).json({
      link_id: 'lnk_3821f92a',
      status: 'active',
      guardian_user_id,
      dependent_user_id,
      created_at: new Date().toISOString()
    });
  },

  /**
   * GET /api/v1/guardian/alerts
   */
  async getDependentAlerts(req, res) {
    // TODO: Retrieve active dependents via GuardianLink.findByGuardianId(req.user.id)
    // and query high/critical incidents matching those dependent IDs

    return res.status(200).json([
      {
        alert_id: 'alt_847192',
        dependent_user_id: 'c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f',
        dependent_name: 'Grandpa Joe',
        risk_level: 'Critical',
        threat_type: 'phishing',
        explanation: 'Critical Risk: Urgent SMS claiming bank card suspension with fraudulent verification link.',
        recommended_action: 'Contact Grandpa Joe immediately to ensure no card details were entered.',
        timestamp: '2026-09-09T08:15:00Z'
      }
    ]);
  }
};

module.exports = guardianController;
