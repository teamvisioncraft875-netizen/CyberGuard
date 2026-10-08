const SoarConnector = require('../../../models/SoarConnector');
const BaseConnector = require('./BaseConnector');
const WebhookConnector = require('./WebhookConnector');
const JiraConnector = require('./JiraConnector');
const SlackConnector = require('./SlackConnector');
const TeamsConnector = require('./TeamsConnector');
const auditService = require('../../auditService');

/**
 * ConnectorRegistry — Central Enterprise Connector Management & Dispatcher
 */
class ConnectorRegistry {
  constructor() {
    this.classes = new Map();
    this.classes.set('webhook', WebhookConnector);
    this.classes.set('jira', JiraConnector);
    this.classes.set('slack', SlackConnector);
    this.classes.set('teams', TeamsConnector);
  }

  /**
   * Register a custom connector class definition
   */
  registerConnectorClass(type, connectorClass) {
    this.classes.set(type.toLowerCase().trim(), connectorClass);
  }

  /**
   * Factory to instantiate connector from database record
   */
  createInstance(record) {
    if (!record) return null;
    const type = (record.type || 'generic').toLowerCase().trim();
    const ConnectorClass = this.classes.get(type) || BaseConnector;
    return new ConnectorClass(record);
  }

  /**
   * Registers a new connector for a tenant
   */
  async registerConnector(data, client = null) {
    const record = await SoarConnector.create(data, client);
    await auditService.log({
      organization_id: record.organization_id,
      user_id: data.created_by || null,
      actor_id: data.created_by || null,
      action: 'SOAR_CONNECTOR_CREATED',
      resource_type: 'soar_connector',
      resource_id: record.id,
      details: {
        name: record.name,
        type: record.type,
        status: record.status,
        is_default: record.is_default
      }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return this.createInstance(record);
  }

  /**
   * Retrieves a connector by ID with tenant isolation
   */
  async getConnector(id, organizationId, client = null) {
    const record = await SoarConnector.findById(id, organizationId, client);
    if (!record) return null;
    return this.createInstance(record);
  }

  /**
   * Retrieves default connector for a given type in an organization
   */
  async getDefaultConnector(type, organizationId, client = null) {
    const record = await SoarConnector.getDefault(organizationId, type, client);
    if (!record) return null;
    return this.createInstance(record);
  }

  /**
   * Lists connectors for a tenant
   */
  async listConnectors(organizationId, filters = {}, client = null) {
    const records = await SoarConnector.findMany({
      ...filters,
      organization_id: organizationId
    }, client);
    return records.map(r => this.createInstance(r));
  }

  /**
   * Enables a connector
   */
  async enableConnector(id, organizationId, actorId = null, client = null) {
    const updated = await SoarConnector.updateStatus(id, organizationId, 'active', client);
    if (!updated) {
      throw new Error(`Connector "${id}" not found for organization`);
    }

    await auditService.log({
      organization_id: organizationId,
      user_id: actorId || null,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_STATUS_CHANGED',
      resource_type: 'soar_connector',
      resource_id: id,
      details: { status: 'active' }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return this.createInstance(updated);
  }

  /**
   * Disables a connector
   */
  async disableConnector(id, organizationId, actorId = null, client = null) {
    const updated = await SoarConnector.updateStatus(id, organizationId, 'disabled', client);
    if (!updated) {
      throw new Error(`Connector "${id}" not found for organization`);
    }

    await auditService.log({
      organization_id: organizationId,
      user_id: actorId || null,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_STATUS_CHANGED',
      resource_type: 'soar_connector',
      resource_id: id,
      details: { status: 'disabled' }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return this.createInstance(updated);
  }

  /**
   * Updates connector configuration or status
   */
  async updateConnector(id, organizationId, updates = {}, actorId = null, client = null) {
    const updated = await SoarConnector.update(id, organizationId, updates, client);
    if (!updated) {
      throw new Error(`Connector "${id}" not found for organization`);
    }

    await auditService.log({
      organization_id: organizationId,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_UPDATED',
      resource_type: 'soar_connector',
      resource_id: id,
      details: {
        updates: SoarConnector.maskConfig(updates)
      }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return this.createInstance(updated);
  }

  /**
   * Deletes a connector
   */
  async deleteConnector(id, organizationId, actorId = null, client = null) {
    const deleted = await SoarConnector.delete(id, organizationId, client);
    if (!deleted) {
      throw new Error(`Connector "${id}" not found for organization`);
    }

    await auditService.log({
      organization_id: organizationId,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_DELETED',
      resource_type: 'soar_connector',
      resource_id: id,
      details: { name: deleted.name, type: deleted.type }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return deleted;
  }

  /**
   * Tests connector connectivity and updates health
   */
  async testConnector(id, organizationId, actorId = null, client = null) {
    const connector = await this.getConnector(id, organizationId, client);
    if (!connector) {
      throw new Error(`Connector "${id}" not found for organization`);
    }

    let testResult;
    try {
      testResult = await connector.testConnection();
      await SoarConnector.updateHealth(id, organizationId, {
        status: 'healthy',
        message: testResult.message,
        timestamp: new Date().toISOString()
      }, client);
    } catch (err) {
      testResult = {
        success: false,
        status: 'error',
        error: err.message,
        timestamp: new Date().toISOString()
      };
      await SoarConnector.updateHealth(id, organizationId, {
        status: 'error',
        error: err.message,
        timestamp: new Date().toISOString()
      }, client);
      await SoarConnector.updateStatus(id, organizationId, 'error', client);
    }

    await auditService.log({
      organization_id: organizationId,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_TESTED',
      resource_type: 'soar_connector',
      resource_id: id,
      details: { result: testResult }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return testResult;
  }

  /**
   * Executes an action on a connector
   */
  async executeConnectorAction({
    connectorId = null,
    type = null,
    organizationId,
    action,
    params = {},
    context = {},
    actorId = null,
    client = null
  }) {
    if (!organizationId) {
      throw new Error('executeConnectorAction requires organizationId');
    }

    let connector = null;
    if (connectorId) {
      connector = await this.getConnector(connectorId, organizationId, client);
      if (!connector) {
        throw new Error(`Connector "${connectorId}" not found for organization`);
      }
    } else if (type) {
      connector = await this.getDefaultConnector(type, organizationId, client);
      if (!connector) {
        // Fallback: If no default connector is configured in DB, instantiate an ephemeral one
        const ConnectorClass = this.classes.get(type.toLowerCase()) || BaseConnector;
        connector = new ConnectorClass({
          organization_id: organizationId,
          type: type.toLowerCase(),
          name: `Ephemeral ${type} Connector`,
          status: 'active',
          config: params.connector_config || {}
        });
      }
    } else {
      throw new Error('executeConnectorAction requires either connectorId or type');
    }

    const execResult = await connector.execute(action, params, context, client);

    await auditService.log({
      organization_id: organizationId,
      actor_id: actorId,
      action: 'SOAR_CONNECTOR_ACTION_EXECUTED',
      resource_type: 'soar_connector',
      resource_id: connector.id || null,
      details: {
        connector_type: connector.type,
        action,
        success: execResult.success,
        external_id: execResult.external_ticket_id || execResult.external_id || null
      }
    }).catch(err => console.warn('[ConnectorRegistry] Audit error:', err.message));

    return execResult;
  }
}

const connectorRegistry = new ConnectorRegistry();
module.exports = connectorRegistry;
module.exports.ConnectorRegistry = ConnectorRegistry;
