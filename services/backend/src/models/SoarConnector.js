const db = require('../config/db');

/**
 * Masking helper to protect secrets in connector configuration
 */
function maskSecrets(config = {}) {
  if (!config || typeof config !== 'object') return config;
  const masked = Array.isArray(config) ? [] : {};
  const secretKeyPattern = /key|token|secret|password|auth|credential|cert|private/i;

  for (const [key, value] of Object.entries(config)) {
    if (value && typeof value === 'object') {
      masked[key] = maskSecrets(value);
    } else if (typeof value === 'string' && secretKeyPattern.test(key)) {
      if (value.length <= 4) {
        masked[key] = '****';
      } else {
        masked[key] = `****${value.slice(-4)}`;
      }
    } else {
      masked[key] = value;
    }
  }
  return masked;
}

class SoarConnector {
  /**
   * Helper to expose secret masking
   */
  static maskConfig(config) {
    return maskSecrets(config);
  }

  /**
   * Creates a new connector instance for a tenant.
   */
  static async create({
    organization_id,
    name,
    type,
    description = null,
    status = 'active',
    config = {},
    is_default = false,
    created_by = null
  }, client = null) {
    const dbClient = client || db;

    if (!organization_id || !name || !type) {
      throw new Error('SoarConnector.create requires organization_id, name, and type');
    }

    const validTypes = ['webhook', 'jira', 'slack', 'teams', 'custom'];
    if (!validTypes.includes(type.toLowerCase())) {
      throw new Error(`SoarConnector.create: invalid connector type "${type}". Allowed: ${validTypes.join(', ')}`);
    }

    const validStatuses = ['active', 'disabled', 'error'];
    if (!validStatuses.includes(status.toLowerCase())) {
      throw new Error(`SoarConnector.create: invalid status "${status}". Allowed: ${validStatuses.join(', ')}`);
    }

    if (is_default) {
      // Clear previous default for this org and type
      await dbClient.query(
        `UPDATE public.soar_connectors 
         SET is_default = false 
         WHERE organization_id = $1 AND type = $2`,
        [organization_id, type.toLowerCase()]
      );
    }

    const query = `
      INSERT INTO public.soar_connectors (
        organization_id, name, type, description, status, config, is_default, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    const values = [
      organization_id,
      name,
      type.toLowerCase(),
      description,
      status.toLowerCase(),
      JSON.stringify(config || {}),
      Boolean(is_default),
      created_by
    ];

    const { rows } = await dbClient.query(query, values);
    return rows[0];
  }

  /**
   * Finds a connector by ID with tenant isolation.
   */
  static async findById(id, organization_id, client = null) {
    const dbClient = client || db;
    let query = 'SELECT * FROM public.soar_connectors WHERE id = $1';
    const params = [id];

    if (organization_id) {
      query += ' AND organization_id = $2';
      params.push(organization_id);
    }

    const { rows } = await dbClient.query(query, params);
    return rows[0] || null;
  }

  /**
   * Lists connectors with filtering and pagination.
   */
  static async findMany(filters = {}, client = null) {
    const dbClient = client || db;
    const {
      organization_id,
      type,
      status,
      search,
      limit = 50,
      offset = 0
    } = filters;

    let query = 'SELECT * FROM public.soar_connectors WHERE 1=1';
    const params = [];
    let pIdx = 1;

    if (organization_id) {
      query += ` AND organization_id = $${pIdx++}`;
      params.push(organization_id);
    }

    if (type) {
      query += ` AND type = $${pIdx++}`;
      params.push(type.toLowerCase());
    }

    if (status) {
      query += ` AND status = $${pIdx++}`;
      params.push(status.toLowerCase());
    }

    if (search) {
      query += ` AND (name ILIKE $${pIdx} OR description ILIKE $${pIdx})`;
      params.push(`%${search}%`);
      pIdx++;
    }

    query += ' ORDER BY created_at DESC';

    if (limit) {
      query += ` LIMIT $${pIdx++}`;
      params.push(limit);
    }

    if (offset) {
      query += ` OFFSET $${pIdx++}`;
      params.push(offset);
    }

    const { rows } = await dbClient.query(query, params);
    return rows;
  }

  /**
   * Retrieves the default connector for an organization and type.
   */
  static async getDefault(organization_id, type, client = null) {
    const dbClient = client || db;
    const query = `
      SELECT * FROM public.soar_connectors 
      WHERE organization_id = $1 AND type = $2 AND status = 'active'
      ORDER BY is_default DESC, created_at DESC
      LIMIT 1;
    `;
    const { rows } = await dbClient.query(query, [organization_id, type.toLowerCase()]);
    return rows[0] || null;
  }

  /**
   * Updates connector configuration or metadata.
   */
  static async update(id, organization_id, updates = {}, client = null) {
    const dbClient = client || db;
    const allowed = ['name', 'description', 'status', 'config', 'is_default'];
    const sets = [];
    const params = [id, organization_id];
    let pIdx = 3;

    if (updates.is_default) {
      const existing = await this.findById(id, organization_id, dbClient);
      if (existing) {
        await dbClient.query(
          `UPDATE public.soar_connectors 
           SET is_default = false 
           WHERE organization_id = $1 AND type = $2`,
          [organization_id, existing.type]
        );
      }
    }

    for (const key of allowed) {
      if (updates[key] !== undefined) {
        if (key === 'config') {
          sets.push(`config = $${pIdx++}`);
          params.push(JSON.stringify(updates.config));
        } else if (key === 'status') {
          const val = updates.status.toLowerCase();
          if (!['active', 'disabled', 'error'].includes(val)) {
            throw new Error(`Invalid status "${val}"`);
          }
          sets.push(`status = $${pIdx++}`);
          params.push(val);
        } else {
          sets.push(`${key} = $${pIdx++}`);
          params.push(updates[key]);
        }
      }
    }

    if (sets.length === 0) {
      return await this.findById(id, organization_id, dbClient);
    }

    const query = `
      UPDATE public.soar_connectors
      SET ${sets.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const { rows } = await dbClient.query(query, params);
    return rows[0] || null;
  }

  /**
   * Updates connector status ('active', 'disabled', 'error').
   */
  static async updateStatus(id, organization_id, status, client = null) {
    return await this.update(id, organization_id, { status }, client);
  }

  /**
   * Records health check results.
   */
  static async updateHealth(id, organization_id, healthStatus, client = null) {
    const dbClient = client || db;
    const query = `
      UPDATE public.soar_connectors
      SET health_status = $3, last_health_check = NOW()
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const { rows } = await dbClient.query(query, [id, organization_id, JSON.stringify(healthStatus)]);
    return rows[0] || null;
  }

  /**
   * Deletes a connector.
   */
  static async delete(id, organization_id, client = null) {
    const dbClient = client || db;
    const query = `
      DELETE FROM public.soar_connectors
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const { rows } = await dbClient.query(query, [id, organization_id]);
    return rows[0] || null;
  }

  /**
   * Logs a connector execution audit record.
   */
  static async logExecution({
    connector_id,
    organization_id,
    action,
    status,
    request_payload = {},
    response_payload = {},
    external_id = null,
    duration_ms = 0
  }, client = null) {
    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_connector_logs (
        connector_id, organization_id, action, status,
        request_payload, response_payload, external_id, duration_ms
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    const values = [
      connector_id,
      organization_id,
      action,
      status,
      JSON.stringify(maskSecrets(request_payload)),
      JSON.stringify(maskSecrets(response_payload)),
      external_id,
      duration_ms
    ];
    const { rows } = await dbClient.query(query, values);
    return rows[0];
  }

  /**
   * Fetches execution audit logs for a connector.
   */
  static async getLogs(connector_id, organization_id, options = {}, client = null) {
    const dbClient = client || db;
    const { limit = 50, offset = 0 } = options;
    const query = `
      SELECT * FROM public.soar_connector_logs
      WHERE connector_id = $1 AND organization_id = $2
      ORDER BY created_at DESC
      LIMIT $3 OFFSET $4;
    `;
    const { rows } = await dbClient.query(query, [connector_id, organization_id, limit, offset]);
    return rows;
  }
}

module.exports = SoarConnector;
