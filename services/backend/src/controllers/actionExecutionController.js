const ResponseAction = require('../models/ResponseAction');
const executionService = require('../services/executionService');
const { log: auditLog } = require('../services/auditService');
const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Read-only model safety: Ensure ResponseAction helper methods exist
if (typeof ResponseAction.findById !== 'function') {
  ResponseAction.findById = async function (id) {
    const text = 'SELECT * FROM public.response_actions WHERE id = $1;';
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  };
}

if (typeof ResponseAction.updateExecutionResult !== 'function') {
  ResponseAction.updateExecutionResult = async function (id, { status, result, executed_at = new Date() }) {
    const text = `
      UPDATE public.response_actions
      SET status = $1,
          result = $2,
          executed_at = $3
      WHERE id = $4
      RETURNING *;
    `;
    const res = await db.query(text, [
      status,
      typeof result === 'string' ? result : JSON.stringify(result || {}),
      executed_at,
      id
    ]);
    return res.rows[0] || null;
  };
}

/**
 * Action Execution Controller — Phase 2B Live Action Execution Endpoint.
 */
const actionExecutionController = {
  /**
   * POST /api/v1/admin/actions/:id/execute
   * Executes an approved response action in live mode.
   */
  async executeAction(req, res) {
    const { id } = req.params;

    if (!id || !UUID_REGEX.test(id)) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Response action not found'
      });
    }

    try {
      // 1. Fetch action
      const action = await ResponseAction.findById(id);
      if (!action) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Response action not found'
        });
      }

      // 2. Tenant isolation check (return 404 to avoid confirming existence across orgs)
      if (action.organization_id !== req.user?.organization_id) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Response action not found'
        });
      }

      // 3. Pre-flight guardrail checks
      if (action.action_mode !== 'live') {
        return res.status(400).json({
          error: 'EXECUTION_GUARD_REJECTED',
          message: `Cannot execute action in '${action.action_mode}' mode. Only 'live' mode actions can be executed.`
        });
      }

      if (action.status !== 'approved' && action.status !== 'scheduled') {
        return res.status(400).json({
          error: 'EXECUTION_GUARD_REJECTED',
          message: `Cannot execute action with status '${action.status}'. Action must be 'approved' or 'scheduled'.`
        });
      }

      // 4. Trigger executionService
      let execResult;
      try {
        execResult = await executionService.execute(action, 'admin');
      } catch (guardErr) {
        return res.status(400).json({
          error: 'EXECUTION_GUARD_REJECTED',
          message: guardErr.message
        });
      }

      // 5. Handle executor failure or guard rejection
      if (!execResult || execResult.success === false) {
        const errorMsg = execResult?.error || 'Execution failed';
        const isGuardRejection =
          errorMsg.toLowerCase().includes('protected') ||
          errorMsg.toLowerCase().includes('guard') ||
          errorMsg.toLowerCase().includes('status must be') ||
          errorMsg.toLowerCase().includes('mode must be') ||
          errorMsg.toLowerCase().includes('retry') ||
          errorMsg.toLowerCase().includes('exceeded');

        if (isGuardRejection) {
          return res.status(400).json({
            error: 'EXECUTION_GUARD_REJECTED',
            message: errorMsg
          });
        }

        return res.status(500).json({
          error: 'EXECUTION_FAILED',
          message: errorMsg
        });
      }

      // 6. Update action record with execution results
      const updatedAction = await ResponseAction.updateExecutionResult(id, {
        status: 'executed',
        result: execResult.result,
        executed_at: new Date()
      });

      // 7. Audit log execution
      await auditLog({
        organization_id: req.user.organization_id,
        user_id: req.user.id,
        actor_type: 'admin',
        action: 'action_executed',
        resource_type: 'response_action',
        resource_id: action.id,
        details: {
          action_type: action.action_type,
          result: execResult.result,
          actor_id: req.user.id
        }
      });

      return res.status(200).json({
        success: true,
        action: updatedAction || action,
        result: execResult.result
      });
    } catch (err) {
      console.error('[ActionExecutionController Error]', err);
      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: err.message || 'An unexpected error occurred during action execution'
      });
    }
  }
};

module.exports = actionExecutionController;
