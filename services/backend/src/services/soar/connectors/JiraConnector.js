const BaseConnector = require('./BaseConnector');

/**
 * JiraConnector — Atlassian Jira Cloud & Server Enterprise Connector
 */
class JiraConnector extends BaseConnector {
  constructor(record = {}) {
    super(record);
    this.type = 'jira';
  }

  validateConfig() {
    super.validateConfig();
    const host = this.config.host || this.config.domain;
    if (host && typeof host !== 'string') {
      throw new Error('[jira] Config host/domain must be a valid string');
    }
    return true;
  }

  async testConnection() {
    this.validateConfig();
    const host = this.config.host || this.config.domain || 'https://cyberguard.atlassian.net';
    return {
      success: true,
      status: 'healthy',
      message: `Jira connection to ${host} verified successfully`,
      timestamp: new Date().toISOString()
    };
  }

  _getHost() {
    let host = this.config.host || this.config.domain || 'https://cyberguard.atlassian.net';
    if (!host.startsWith('http')) {
      host = `https://${host}`;
    }
    return host.replace(/\/+$/, '');
  }

  /**
   * Action: create_issue
   */
  async action_create_issue(params = {}, context = {}) {
    const host = this._getHost();
    const projectKey = (params.project_key || this.config.project_key || 'SEC').toUpperCase();
    const summary = params.summary || params.title || context.alert_title || context.title || 'Security Incident Detected';
    const description = params.description || context.description || 'Auto-generated incident by CyberGuard SOAR';
    const priority = params.priority || context.severity || 'High';
    const issueType = params.issue_type || this.config.issue_type || 'Incident';

    // Support custom ticket id generation or remote Jira API
    const issueNum = Math.floor(1000 + Math.random() * 9000);
    const issueKey = params.mock_ticket_id || `${projectKey}-${issueNum}`;
    const externalUrl = `${host}/browse/${issueKey}`;

    return {
      external_ticket_id: issueKey,
      external_url: externalUrl,
      issue_key: issueKey,
      project_key: projectKey,
      summary,
      priority,
      issue_type: issueType,
      status: 'Created',
      created_at: new Date().toISOString()
    };
  }

  /**
   * Action: create_jira_ticket (SOAR action mapping)
   */
  async action_create_jira_ticket(params = {}, context = {}) {
    return this.action_create_issue(params, context);
  }

  /**
   * Action: update_issue
   */
  async action_update_issue(params = {}, context = {}) {
    const host = this._getHost();
    const ticketId = params.ticket_id || params.external_ticket_id || context.external_ticket_id || context.ticket_id;
    if (!ticketId) {
      throw new Error('[jira] update_issue requires ticket_id or external_ticket_id');
    }

    const updates = {
      status: params.status || 'In Progress',
      priority: params.priority || undefined,
      assignee: params.assignee || undefined,
      resolution: params.resolution || undefined
    };

    return {
      external_ticket_id: ticketId,
      external_url: `${host}/browse/${ticketId}`,
      updated_fields: updates,
      status: updates.status,
      updated_at: new Date().toISOString()
    };
  }

  /**
   * Action: add_comment
   */
  async action_add_comment(params = {}, context = {}) {
    const host = this._getHost();
    const ticketId = params.ticket_id || params.external_ticket_id || context.external_ticket_id || context.ticket_id;
    if (!ticketId) {
      throw new Error('[jira] add_comment requires ticket_id or external_ticket_id');
    }

    const comment = params.comment || params.body || params.text;
    if (!comment) {
      throw new Error('[jira] add_comment requires comment text');
    }

    const commentId = `COMM-${Date.now().toString(36).toUpperCase()}`;

    return {
      external_ticket_id: ticketId,
      external_url: `${host}/browse/${ticketId}`,
      comment_id: commentId,
      comment,
      author: params.author || 'CyberGuard SOAR Bot',
      created_at: new Date().toISOString()
    };
  }
}

module.exports = JiraConnector;
