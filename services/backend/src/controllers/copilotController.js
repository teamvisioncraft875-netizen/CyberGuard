const copilotService = require('../services/copilot/copilotService');

/**
 * Copilot Controller — REST API handler for AI Security Copilot queries
 */
const copilotController = {
  /**
   * POST /api/v1/copilot/query
   */
  async query(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({
          error: 'FORBIDDEN',
          message: 'Valid organization_id required'
        });
      }

      const { type, entity_id, question, timeoutMs } = req.body || {};
      if (!type) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Field "type" is required'
        });
      }

      const result = await copilotService.query({
        organization_id,
        user_id: req.user?.id,
        type,
        entity_id,
        question,
        timeoutMs
      });

      return res.status(200).json({
        answer: result.answer,
        sources: result.sources,
        tokens_used: result.tokens_used
      });
    } catch (err) {
      console.error('[copilotController.query] Error:', err);
      if (err.message && (err.message.includes('Invalid') || err.message.includes('Unsupported'))) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: err.message
        });
      }
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message
      });
    }
  }
};

module.exports = copilotController;
