const db = require('../config/db');
const attackChainService = require('../services/attackChainService');
const { log: auditLog, AUDIT_ACTIONS } = require('../services/auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Controller for Attack Chain Engine & MITRE Progression Analysis
 */
const attackChainController = {
  /**
   * GET /api/v1/incidents/:id/attack-chain
   * Retrieves the attack chain timeline, confidence score, and root incident.
   */
  async getAttackChain(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident not found'
      });
    }

    try {
      const orgId = req.user?.organization_id;

      // Verify incident exists and belongs to the user's organization
      const incRes = await db.query(
        `SELECT id, organization_id FROM public.incidents WHERE id = $1;`,
        [id]
      );

      if (incRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      const incident = incRes.rows[0];
      if (orgId && incident.organization_id && incident.organization_id !== orgId) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      const effectiveOrgId = orgId || incident.organization_id;
      const chain = await attackChainService.getAttackChain(id, effectiveOrgId);

      // Audit log: ATTACK_CHAIN_VIEWED
      await auditLog({
        organization_id: effectiveOrgId,
        user_id: req.user?.id || null,
        actor_type: req.user?.role === 'admin' ? 'admin' : 'user',
        action: AUDIT_ACTIONS.ATTACK_CHAIN_VIEWED || 'ATTACK_CHAIN_VIEWED',
        resource_type: 'incident',
        resource_id: id,
        details: {
          incident_id: id,
          chain_length: chain.chain_length,
          confidence_score: chain.confidence_score
        }
      });

      return res.status(200).json({
        root_incident: chain.root_incident,
        chain_length: chain.chain_length,
        confidence_score: chain.confidence_score,
        timeline: chain.timeline
      });
    } catch (err) {
      console.error('[AttackChainController.getAttackChain Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve attack chain'
      });
    }
  },

  /**
   * GET /api/v1/incidents/:id/attack-chain/graph
   * Returns React Flow / Cytoscape formatted graph visualization payload.
   */
  async getAttackChainGraph(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Incident not found'
      });
    }

    try {
      const orgId = req.user?.organization_id;

      // Verify incident exists and belongs to user's organization
      const incRes = await db.query(
        `SELECT id, organization_id FROM public.incidents WHERE id = $1;`,
        [id]
      );

      if (incRes.rows.length === 0) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      const incident = incRes.rows[0];
      if (orgId && incident.organization_id && incident.organization_id !== orgId) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Incident not found'
        });
      }

      const effectiveOrgId = orgId || incident.organization_id;
      const graph = await attackChainService.getAttackChainGraph(id, effectiveOrgId);

      return res.status(200).json(graph);
    } catch (err) {
      console.error('[AttackChainController.getAttackChainGraph Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve attack chain graph'
      });
    }
  }
};

module.exports = attackChainController;
