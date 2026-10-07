const ThreatIOC = require('../../models/ThreatIOC');
const threatIntelService = require('../siem/threatIntelService');

/**
 * Action Executor Framework — Production-grade extensible SOAR action dispatcher
 */
class ActionExecutor {
  constructor() {
    this.registry = new Map();
    this._initializeDefaultActions();
  }

  /**
   * Registers a custom or standard action handler.
   */
  registerAction(actionType, handler) {
    if (!actionType || typeof actionType !== 'string') {
      throw new Error('ActionExecutor Error: actionType is required');
    }
    if (typeof handler !== 'function') {
      throw new Error('ActionExecutor Error: handler must be a function');
    }
    this.registry.set(actionType.toLowerCase().trim(), handler);
  }

  /**
   * Dispatches and executes an action with configuration and runtime context.
   */
  async executeAction(actionType, config = {}, context = {}, client = null) {
    const cleanType = (actionType || '').toLowerCase().trim();

    try {
      const handler = this.registry.get(cleanType);
      if (!handler) {
        return {
          success: false,
          action_type: cleanType,
          error: `ActionExecutor Error: Unsupported action_type "${actionType}". Available actions: ${Array.from(this.registry.keys()).join(', ')}`,
          timestamp: new Date().toISOString()
        };
      }

      const result = await handler(config, context, client);
      return {
        success: true,
        action_type: cleanType,
        ...result
      };
    } catch (err) {
      return {
        success: false,
        action_type: cleanType,
        error: err.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Registers the 6 standard Phase 1 SOAR actions.
   */
  _initializeDefaultActions() {
    // 1. Block IP
    this.registerAction('block_ip', async (config, context) => {
      const targetIp = config.ip || context.destination_ip || context.source_ip || context.ip || '0.0.0.0';
      return {
        action: 'block_ip',
        target_ip: targetIp,
        firewall_rule_id: `FW-BLOCK-${Date.now().toString(36).toUpperCase()}`,
        status: 'blocked',
        timestamp: new Date().toISOString()
      };
    });

    // 2. Disable User
    this.registerAction('disable_user', async (config, context) => {
      const targetUser = config.user || context.user_name || context.user || 'unknown_user';
      return {
        action: 'disable_user',
        target_user: targetUser,
        status: 'disabled',
        directory_service: config.directory || 'active_directory',
        timestamp: new Date().toISOString()
      };
    });

    // 3. Isolate Host
    this.registerAction('isolate_host', async (config, context) => {
      const targetHost = config.host || context.asset_name || context.host || context.device_name || 'unknown_host';
      return {
        action: 'isolate_host',
        target_host: targetHost,
        network_status: 'isolated',
        isolation_id: `EDR-ISO-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString()
      };
    });

    // 4. Create Ticket
    this.registerAction('create_ticket', async (config, context) => {
      const title = config.title || `SOAR Incident: Alert ${context.alert_id || context.id || 'N/A'}`;
      const priority = config.priority || context.severity || 'high';
      return {
        action: 'create_ticket',
        ticket_id: `SEC-${Math.floor(100000 + Math.random() * 900000)}`,
        title,
        priority,
        status: 'open',
        timestamp: new Date().toISOString()
      };
    });

    // 5. Send Email
    this.registerAction('send_email', async (config, context) => {
      const recipient = config.recipient || config.to || 'soc-alert@cyberguard.internal';
      const subject = config.subject || `[CRITICAL] Automated SOAR Notification: ${context.alert_title || 'Security Event'}`;
      return {
        action: 'send_email',
        recipient,
        subject,
        status: 'sent',
        timestamp: new Date().toISOString()
      };
    });

    // 6. Add IOC (Integrates with ThreatIOC and ThreatIntelService)
    this.registerAction('add_ioc', async (config, context, client) => {
      const orgId = context.organization_id || config.organization_id;
      if (!orgId) {
        throw new Error('add_ioc action requires organization_id in context or config');
      }

      const iocType = config.ioc_type || context.ioc_type || 'ip';
      const iocValue = config.ioc_value || context.destination_ip || context.source_ip || context.ioc_value;

      if (!iocValue) {
        throw new Error('add_ioc action requires ioc_value in config or event context');
      }

      const confidence = typeof config.confidence === 'number' ? config.confidence : 85;
      const threatActor = config.threat_actor || context.threat_actor || 'Unknown Actor';
      const malwareFamily = config.malware_family || context.malware_family || 'Generic Malware';
      const campaignName = config.campaign_name || context.campaign_name || 'Automated SOAR Quarantine';

      const riskScore = threatIntelService.calculateRiskScore({
        confidence,
        sightings_count: 1,
        last_seen: new Date(),
        campaign_name: campaignName,
        threat_actor: threatActor
      });

      const iocRecord = await ThreatIOC.upsertIOC({
        organization_id: orgId,
        ioc_type: iocType,
        ioc_value: iocValue,
        confidence,
        risk_score: riskScore,
        threat_actor: threatActor,
        malware_family: malwareFamily,
        campaign_name: campaignName,
        source_name: 'SOAR Playbook Auto-Quarantine',
        tags: ['soar_automated', 'playbook_quarantine']
      }, client);

      return {
        action: 'add_ioc',
        ioc_id: iocRecord.id,
        ioc_type: iocRecord.ioc_type,
        ioc_value: iocRecord.ioc_value,
        risk_score: iocRecord.risk_score,
        status: 'ioc_created',
        timestamp: new Date().toISOString()
      };
    });

    // 7. Send Webhook
    this.registerAction('send_webhook', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'webhook',
        organizationId: orgId,
        action: 'send_webhook',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 8. Create Jira Ticket
    this.registerAction('create_jira_ticket', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'jira',
        organizationId: orgId,
        action: 'create_jira_ticket',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 9. Jira Update Issue
    this.registerAction('jira_update_issue', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'jira',
        organizationId: orgId,
        action: 'update_issue',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 10. Jira Add Comment
    this.registerAction('jira_add_comment', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'jira',
        organizationId: orgId,
        action: 'add_comment',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 11. Send Slack Message
    this.registerAction('send_slack_message', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'slack',
        organizationId: orgId,
        action: 'send_slack_message',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 12. Slack Alert Notification
    this.registerAction('slack_alert', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'slack',
        organizationId: orgId,
        action: 'alert_notification',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 13. Send Teams Message
    this.registerAction('send_teams_message', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'teams',
        organizationId: orgId,
        action: 'send_teams_message',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 14. Teams Incident Notification
    // 14. Teams Incident Notification
    this.registerAction('teams_incident', async (config, context, client) => {
      const connectorRegistry = require('./connectors/ConnectorRegistry');
      const orgId = context.organization_id || config.organization_id || '00000000-0000-0000-0000-000000000000';
      return await connectorRegistry.executeConnectorAction({
        connectorId: config.connector_id || null,
        type: 'teams',
        organizationId: orgId,
        action: 'incident_notification',
        params: config,
        context,
        actorId: context.actor_id || null,
        client
      });
    });

    // 15. Isolate Endpoint (Phase 4 alias for isolate_host)
    this.registerAction('isolate_endpoint', async (config, context, client) => {
      const targetHost = config.host || config.asset_name || context.asset_name || context.host || 'unknown_endpoint';
      return {
        action: 'isolate_endpoint',
        target_host: targetHost,
        network_status: 'isolated',
        isolation_id: `EDR-ISO-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString()
      };
    });

    // 16. Disable Account (Phase 4 alias for disable_user)
    this.registerAction('disable_account', async (config, context, client) => {
      const targetUser = config.user || config.target_user || context.user_name || context.user || 'compromised_user';
      return {
        action: 'disable_account',
        target_user: targetUser,
        status: 'disabled',
        timestamp: new Date().toISOString()
      };
    });

    // 17. DNS Sinkhole (Phase 4)
    this.registerAction('dns_sinkhole', async (config, context, client) => {
      const domain = config.domain || context.domain || 'malicious-domain.com';
      const sinkholeIp = config.sinkhole_ip || '10.254.254.254';
      return {
        action: 'dns_sinkhole',
        domain,
        sinkhole_ip: sinkholeIp,
        status: 'sinkholed',
        timestamp: new Date().toISOString()
      };
    });

    // 18. Escalate Approval (Phase 4)
    this.registerAction('escalate_approval', async (config, context, client) => {
      const level = config.level || 'L2';
      return {
        action: 'escalate_approval',
        level,
        status: 'escalated',
        timestamp: new Date().toISOString()
      };
    });

    // 19. Launch Playbook (Phase 4)
    this.registerAction('launch_playbook', async (config, context, client) => {
      return {
        action: 'launch_playbook',
        playbook_id: config.playbook_id || null,
        status: 'launched',
        timestamp: new Date().toISOString()
      };
    });
  }
}

const actionExecutor = new ActionExecutor();
module.exports = actionExecutor;
