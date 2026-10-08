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

      const messages = await CopilotMessage.findBySessionId(id, 50, organization_id);
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
      const history = await CopilotMessage.findRecent(id, 10, organization_id);
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
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

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
  },

  /**
   * POST /api/v1/copilot/hunt
   */
  async hunt(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { query, session_id } = req.body || {};
      if (!query) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "query" is required' });
      }

      if (session_id) {
        const session = await CopilotSession.findById(session_id, organization_id);
        if (!session) {
          return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${session_id} not found` });
        }
      }

      const threatHuntingService = require('../services/copilot/threatHuntingService');
      const result = await threatHuntingService.hunt({
        query,
        organization_id,
        session_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.hunt] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/investigate/ioc
   */
  async investigateIoc(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { ioc, session_id } = req.body || {};
      if (!ioc) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "ioc" is required' });
      }

      if (session_id) {
        const session = await CopilotSession.findById(session_id, organization_id);
        if (!session) {
          return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${session_id} not found` });
        }
      }

      const iocInvestigationService = require('../services/copilot/iocInvestigationService');
      const result = await iocInvestigationService.investigate({
        ioc,
        organization_id,
        session_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.investigateIoc] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/investigate/incident
   */
  async investigateIncident(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { incident_id, session_id } = req.body || {};
      if (!incident_id) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "incident_id" is required' });
      }

      if (session_id) {
        const session = await CopilotSession.findById(session_id, organization_id);
        if (!session) {
          return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${session_id} not found` });
        }
      }

      const autonomousInvestigationService = require('../services/copilot/autonomousInvestigationService');
      const result = await autonomousInvestigationService.investigate({
        incident_id,
        organization_id,
        session_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.investigateIncident] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/investigate/alert
   */
  async investigateAlert(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { alert_id, session_id } = req.body || {};
      if (!alert_id) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "alert_id" is required' });
      }

      if (session_id) {
        const session = await CopilotSession.findById(session_id, organization_id);
        if (!session) {
          return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${session_id} not found` });
        }
      }

      const autonomousInvestigationService = require('../services/copilot/autonomousInvestigationService');
      const result = await autonomousInvestigationService.investigate({
        alert_id,
        organization_id,
        session_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.investigateAlert] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/correlate
   */
  async correlate(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { incident_id, alert_id, session_id } = req.body || {};
      if (!incident_id && !alert_id) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'incident_id or alert_id is required' });
      }

      if (session_id) {
        const session = await CopilotSession.findById(session_id, organization_id);
        if (!session) {
          return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${session_id} not found` });
        }
      }

      const incidentCorrelationService = require('../services/copilot/incidentCorrelationService');
      const result = await incidentCorrelationService.correlate({
        incident_id,
        alert_id,
        organization_id,
        session_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.correlate] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/report
   */
  async generateReport(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const investigationReportService = require('../services/copilot/investigationReportService');
      const result = await investigationReportService.generateReport({
        ...req.body,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        report: result
      });
    } catch (err) {
      console.error('[copilotController.generateReport] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/investigations/:sessionId
   */
  async getInvestigations(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { sessionId } = req.params;
      const session = await CopilotSession.findById(sessionId, organization_id);
      if (!session) {
        return res.status(404).json({ error: 'NOT_FOUND', message: `Session ${sessionId} not found` });
      }

      const CopilotInvestigation = require('../models/CopilotInvestigation');
      const investigations = await CopilotInvestigation.findBySession(sessionId, organization_id);

      return res.status(200).json({
        success: true,
        session_id: sessionId,
        count: investigations.length,
        investigations
      });
    } catch (err) {
      console.error('[copilotController.getInvestigations] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/executive-briefing
   */
  async executiveBriefing(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const executiveBriefingService = require('../services/copilot/executiveBriefingService');
      const result = await executiveBriefingService.generateBriefing({
        ...req.body,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.executiveBriefing] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/handover
   */
  async shiftHandover(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const shiftHandoverService = require('../services/copilot/shiftHandoverService');
      const result = await shiftHandoverService.generateHandover({
        ...req.body,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.shiftHandover] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/reconstruct
   */
  async reconstructTimeline(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const { incident_id, alert_id } = req.body || {};
      if (!incident_id && !alert_id) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'incident_id or alert_id is required' });
      }

      const timelineReconstructionService = require('../services/copilot/timelineReconstructionService');
      const result = await timelineReconstructionService.reconstruct({
        incident_id,
        alert_id,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.reconstructTimeline] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/threat-actor
   */
  async profileThreatActor(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const threatActorService = require('../services/copilot/threatActorService');
      const result = await threatActorService.profileActor({
        ...req.body,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.profileThreatActor] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/posture
   */
  async getSecurityPosture(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const securityPostureService = require('../services/copilot/securityPostureService');
      const result = await securityPostureService.evaluatePosture({
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.getSecurityPosture] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/dashboard
   */
  async generateDashboard(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const query = req.body?.query || req.body?.prompt;
      if (!query) {
        return res.status(400).json({ error: 'BAD_REQUEST', message: 'Field "query" is required' });
      }

      const dashboardGenerationService = require('../services/copilot/dashboardGenerationService');
      const result = await dashboardGenerationService.generateDashboard({
        query,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        dashboard: result
      });
    } catch (err) {
      console.error('[copilotController.generateDashboard] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * POST /api/v1/copilot/cross-investigation
   */
  async crossInvestigation(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const crossInvestigationService = require('../services/copilot/crossInvestigationService');
      const result = await crossInvestigationService.correlateAcrossInvestigations({
        ...req.body,
        organization_id,
        user_id: req.user?.id
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.crossInvestigation] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  },

  /**
   * GET /api/v1/copilot/analyst-metrics
   */
  async getAnalystMetrics(req, res) {
    try {
      const organization_id = req.user?.organization_id;
      if (!organization_id) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Valid organization_id required' });
      }

      const timeframe_days = parseInt(req.query?.timeframe_days, 10) || 30;
      const analystMetricsService = require('../services/copilot/analystMetricsService');
      const result = await analystMetricsService.getMetrics({
        organization_id,
        user_id: req.user?.id,
        timeframe_days
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    } catch (err) {
      console.error('[copilotController.getAnalystMetrics] Error:', err);
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  }
};

module.exports = copilotController;
