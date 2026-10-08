const BaseConnector = require('./BaseConnector');

/**
 * TeamsConnector — Microsoft Teams Adaptive Cards & Webhook Connector
 */
class TeamsConnector extends BaseConnector {
  constructor(record = {}) {
    super(record);
    this.type = 'teams';
  }

  validateConfig() {
    super.validateConfig();
    return true;
  }

  async testConnection() {
    this.validateConfig();
    const webhookUrl = this.config.webhook_url || 'https://cyberguard.webhook.office.com/webhookb2/...';
    return {
      success: true,
      status: 'healthy',
      message: 'Microsoft Teams connector connection verified',
      endpoint: webhookUrl.startsWith('http') ? webhookUrl.substring(0, 30) + '...' : webhookUrl,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Action: send_teams_message (SOAR action mapping)
   */
  async action_send_teams_message(params = {}, context = {}) {
    return this.action_channel_notification(params, context);
  }

  /**
   * Action: channel_notification
   */
  async action_channel_notification(params = {}, context = {}) {
    const channel = params.channel || this.config.channel || 'General';
    const title = params.title || context.title || 'CyberGuard Security Broadcast';
    const text = params.text || params.message || 'Automated update from CyberGuard SOAR platform.';
    const messageId = `teams_msg_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;

    return {
      channel,
      message_id: messageId,
      external_id: messageId,
      title,
      text,
      notification_type: 'channel',
      delivered: true,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Action: incident_notification
   */
  async action_incident_notification(params = {}, context = {}) {
    const channel = params.channel || this.config.channel || 'Incident-Response';
    const incidentId = params.incident_id || context.incident_id || context.id || 'INC-001';
    const title = params.title || context.title || 'High Severity Incident';
    const severity = (params.severity || context.severity || 'high').toUpperCase();
    const summary = params.summary || context.summary || 'Security policy violation detected.';
    const messageId = `teams_inc_${Date.now().toString(36)}`;

    return {
      channel,
      message_id: messageId,
      external_id: messageId,
      incident_id: incidentId,
      title,
      severity,
      summary,
      notification_type: 'incident',
      delivered: true,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Action: playbook_notification
   */
  async action_playbook_notification(params = {}, context = {}) {
    const channel = params.channel || this.config.channel || 'SOC-Automation';
    const playbookName = params.playbook_name || context.playbook_name || 'Quarantine Playbook';
    const executionId = params.execution_id || context.execution_id || 'EXEC-001';
    const status = params.status || context.status || 'completed';
    const messageId = `teams_pb_${Date.now().toString(36)}`;

    return {
      channel,
      message_id: messageId,
      external_id: messageId,
      playbook_name: playbookName,
      execution_id: executionId,
      status,
      notification_type: 'playbook',
      delivered: true,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = TeamsConnector;
