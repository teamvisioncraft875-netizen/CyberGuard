const SoarConnector = require('../../../models/SoarConnector');

/**
 * BaseConnector — Abstract Base Class for Enterprise SOAR Connectors
 */
class BaseConnector {
  /**
   * @param {Object} record - Database record or configuration object
   */
  constructor(record = {}) {
    this.id = record.id || null;
    this.organization_id = record.organization_id || null;
    this.name = record.name || 'Unnamed Connector';
    this.type = record.type || 'generic';
    this.description = record.description || null;
    this.status = record.status || 'active'; // 'active', 'disabled', 'error'
    this.config = record.config || {};
    this.is_default = Boolean(record.is_default);
    this.health_status = record.health_status || { status: 'unknown' };
    this.last_health_check = record.last_health_check || null;
    this.created_by = record.created_by || null;
  }

  /**
   * Returns whether connector is currently active
   */
  isActive() {
    return this.status === 'active';
  }

  /**
   * Mask secrets for audit and logging
   */
  maskSecrets(data) {
    return SoarConnector.maskConfig(data);
  }

  /**
   * Validates connector configuration. Subclasses should override this.
   */
  validateConfig() {
    if (!this.config || typeof this.config !== 'object') {
      throw new Error(`[${this.type}] Connector config must be an object`);
    }
    return true;
  }

  /**
   * Tests connectivity to the external system. Subclasses should override this.
   */
  async testConnection() {
    this.validateConfig();
    return {
      success: true,
      status: 'healthy',
      message: `Connector "${this.name}" connection test successful`,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Executes an action on the connector with error handling and audit recording.
   */
  async execute(action, params = {}, context = {}, client = null) {
    if (!this.isActive()) {
      throw new Error(`Connector "${this.name}" (${this.id}) is ${this.status} and cannot execute actions.`);
    }

    const startTime = Date.now();
    let status = 'success';
    let result = null;
    let externalId = null;

    try {
      const handlerName = `action_${action.toLowerCase().trim()}`;
      if (typeof this[handlerName] !== 'function') {
        throw new Error(`Connector "${this.name}" does not support action "${action}".`);
      }

      result = await this[handlerName](params, context);
      externalId = result?.external_ticket_id || result?.external_id || result?.message_id || null;

      return {
        success: true,
        connector_id: this.id,
        connector_type: this.type,
        action,
        duration_ms: Date.now() - startTime,
        ...result
      };
    } catch (err) {
      status = 'failed';
      result = { error: err.message };
      throw err;
    } finally {
      if (this.id && this.organization_id) {
        try {
          await SoarConnector.logExecution({
            connector_id: this.id,
            organization_id: this.organization_id,
            action,
            status,
            request_payload: params,
            response_payload: result,
            external_id: externalId,
            duration_ms: Date.now() - startTime
          }, client);
        } catch (logErr) {
          console.warn(`[BaseConnector] Failed to record execution log: ${logErr.message}`);
        }
      }
    }
  }
}

module.exports = BaseConnector;
