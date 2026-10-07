const CopilotSession = require('../models/CopilotSession');
const CopilotMessage = require('../models/CopilotMessage');
const CopilotSessionAction = require('../models/CopilotSessionAction');
const copilotService = require('../services/copilot/copilotService');
const socSearchService = require('../services/copilot/socSearchService');
const mitreReasoningService = require('../services/copilot/mitreReasoningService');
const { log: auditLog } = require('../services/auditService');

/**
 * Copilot Controller — REST API handler for AI Security Copilot queries, sessions, and multi-turn investigations.
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
        tokens_used: result.tokens_used,
        search_results: result.search_results,
        mitre_data: result.mitre_data
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
  },

  /**
   * POST /api/v1/copilot/sessions
   */
  async createSession(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { title, entity_type, entity_id, status } = req.body || {};
      const session = await CopilotSession.create({
        organization_id,
        created_by: req.user?.id,
        title: title || 'New Investigation Session',
        entity_type: entity_type || null,
        entity_id: entity_id || null,
        status: status || 'active'
      });

      await auditLog({
        organization_id,
        user_id: req.user?.id,
        action: 'COPILOT_SESSION_CREATED',
        resource_type: 'copilot_session',
        resource_id: session.id,
        details: { title: session.title, entity_type, entity_id }
      });

      return res.status(201).json({ success: true, data: session });
    } catch (err) {
      console.error('[copilotController.createSession] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/sessions
   */
  async listSessions(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { status, limit = 50, offset = 0 } = req.query;
      const sessions = await CopilotSession.findMany({
        organization_id,
        status,
        limit: parseInt(limit, 10) || 50,
        offset: parseInt(offset, 10) || 0
      });

      return res.status(200).json({ success: true, data: sessions });
    } catch (err) {
      console.error('[copilotController.listSessions] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/sessions/:id
   */
  async getSessionById(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const session = await CopilotSession.findById(id, organization_id);
      if (!session) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Session not found' });
      }

      const messages = await CopilotMessage.findBySessionId(id, 50);
      return res.status(200).json({
        success: true,
        data: {
          ...session,
          messages
        }
      });
    } catch (err) {
      console.error('[copilotController.getSessionById] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * DELETE /api/v1/copilot/sessions/:id
   */
  async deleteSession(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const deleted = await CopilotSession.delete(id, organization_id);
      if (!deleted) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Session not found' });
      }

      await auditLog({
        organization_id,
        user_id: req.user?.id,
        action: 'COPILOT_SESSION_DELETED',
        resource_type: 'copilot_session',
        resource_id: id,
        details: { session_id: id }
      });

      return res.status(200).json({ success: true, message: 'Session deleted successfully' });
    } catch (err) {
      console.error('[copilotController.deleteSession] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/sessions/:id/message
   */
  async postMessage(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const session = await CopilotSession.findById(id, organization_id);
      if (!session) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Session not found' });
      }

      const questionText = req.body.content || req.body.question;
      if (!questionText || typeof questionText !== 'string' || !questionText.trim()) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Message content is required' });
      }

      const type = req.body.type || 'session_chat';
      const timeoutMs = req.body.timeoutMs;

      // 1. Store user message in database
      const userMsg = await CopilotMessage.create({
        session_id: id,
        role: 'user',
        content: questionText.trim(),
        metadata: { client_ip: req.ip }
      });

      await auditLog({
        organization_id,
        user_id: req.user?.id,
        action: 'COPILOT_MESSAGE_CREATED',
        resource_type: 'copilot_message',
        resource_id: userMsg.id,
        details: { session_id: id, role: 'user', message_length: questionText.length }
      });

      // 2. Retrieve recent session history and recorded session actions
      const history = await CopilotMessage.findRecent(id, 10);
      const sessionActions = await CopilotSessionAction.findBySession(id, organization_id);

      // 3. Query Copilot Service with history, actions & retrieved context
      const queryResult = await copilotService.query({
        organization_id,
        user_id: req.user?.id,
        type,
        entity_id: session.entity_id || null,
        question: questionText.trim(),
        history,
        sessionActions,
        timeoutMs
      });

      // 4. Store assistant response in database
      const assistantMsg = await CopilotMessage.create({
        session_id: id,
        role: 'assistant',
        content: queryResult.answer,
        metadata: {
          sources: queryResult.sources,
          tokens_used: queryResult.tokens_used
        }
      });

      await auditLog({
        organization_id,
        user_id: req.user?.id,
        action: 'COPILOT_MESSAGE_CREATED',
        resource_type: 'copilot_message',
        resource_id: assistantMsg.id,
        details: { session_id: id, role: 'assistant', tokens_used: queryResult.tokens_used }
      });

      return res.status(200).json({
        success: true,
        answer: queryResult.answer,
        sources: queryResult.sources,
        tokens_used: queryResult.tokens_used,
        message_id: assistantMsg.id,
        session_id: id
      });
    } catch (err) {
      console.error('[copilotController.postMessage] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/recommend-actions
   */
  async recommendActions(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const actionRecommendationService = require('../services/copilot/actionRecommendationService');
      const result = await actionRecommendationService.recommendActions({
        organization_id,
        ...req.body,
        actor_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      console.error('[copilotController.recommendActions] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/recommend-playbooks
   */
  async recommendPlaybooks(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const playbookRecommendationService = require('../services/copilot/playbookRecommendationService');
      const result = await playbookRecommendationService.recommendPlaybooks({
        organization_id,
        ...req.body,
        actor_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      console.error('[copilotController.recommendPlaybooks] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/execute-action
   */
  async executeAction(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { action_type, payload = {}, session_id = null, reason = '' } = req.body || {};
      if (!action_type) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "action_type" is required' });
      }

      const copilotActionService = require('../services/copilot/copilotActionService');
      const result = await copilotActionService.executeAction({
        organization_id,
        session_id,
        action_type,
        payload,
        reason,
        user: req.user
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.executeAction] Error:', err);
      const statusCode = err.statusCode || 500;
      return res.status(statusCode).json({ error: err.statusCode === 403 ? 'FORBIDDEN' : 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/sessions/:id/actions
   */
  async getSessionActions(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const session = await CopilotSession.findById(id, organization_id);
      if (!session) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Session not found' });
      }

      const copilotActionService = require('../services/copilot/copilotActionService');
      const result = await copilotActionService.getSessionActions({
        session_id: id,
        organization_id
      });

      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      console.error('[copilotController.getSessionActions] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/command
   */
  async command(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { command, session_id, options } = req.body || {};
      if (!command) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "command" is required' });
      }

      const naturalLanguageExecutionService = require('../services/copilot/naturalLanguageExecutionService');
      const result = await naturalLanguageExecutionService.executeCommand({
        command,
        session_id: session_id || null,
        organization_id,
        user: req.user,
        options: options || req.body
      });

      return res.status(200).json(result);
    } catch (err) {
      console.error('[copilotController.command] Error:', err);
      const code = err.statusCode || 500;
      return res.status(code).json({
        error: code === 403 ? 'FORBIDDEN' : (code === 404 ? 'NOT_FOUND' : 'INTERNAL_SERVER_ERROR'),
        message: err.message
      });
    }
  },

  /**
   * POST /api/v1/copilot/plan
   */
  async plan(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { command, context } = req.body || {};
      if (!command) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "command" is required' });
      }

      const intentDetectionService = require('../services/copilot/intentDetectionService');
      const entityExtractionService = require('../services/copilot/entityExtractionService');
      const commandPlannerService = require('../services/copilot/commandPlannerService');

      const { intent, intents } = await intentDetectionService.detectIntent(command, {
        organization_id,
        actor_id: req.user?.id
      });
      const entities = await entityExtractionService.extractEntities(command, {
        organization_id,
        actor_id: req.user?.id
      });

      const planResult = await commandPlannerService.createPlan({
        intent,
        intents,
        entities,
        raw_command: command,
        organization_id,
        actor_id: req.user?.id,
        context: context || {}
      });

      return res.status(200).json({
        success: true,
        command,
        intent,
        intents,
        entities,
        ...planResult
      });
    } catch (err) {
      console.error('[copilotController.plan] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/explain
   */
  async explain(req, res) {
    try {
      const naturalLanguageExecutionService = require('../services/copilot/naturalLanguageExecutionService');
      const result = naturalLanguageExecutionService.explainAction(req.body || {});

      return res.status(200).json({
        success: true,
        explanation: result
      });
    } catch (err) {
      console.error('[copilotController.explain] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/sessions/:id/timeline
   */
  async getSessionTimeline(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { id } = req.params;
      const naturalLanguageExecutionService = require('../services/copilot/naturalLanguageExecutionService');
      const result = await naturalLanguageExecutionService.getSessionTimeline({
        session_id: id,
        organization_id
      });

      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      console.error('[copilotController.getSessionTimeline] Error:', err);
      const code = err.statusCode || 500;
      return res.status(code).json({
        error: code === 404 ? 'NOT_FOUND' : (code === 403 ? 'FORBIDDEN' : 'INTERNAL_SERVER_ERROR'),
        message: err.message
      });
    }
  }
};

module.exports = copilotController;
