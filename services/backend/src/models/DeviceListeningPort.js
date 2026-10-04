const db = require('../config/db');

/**
 * DeviceListeningPort Model — Manages discovered network listening sockets
 * for Attack Surface Discovery (Phase A).
 */
const DeviceListeningPort = {
  /**
   * Upserts an observed listening port for a device.
   * If the (device_id, port, protocol, bind_address, status) exists:
   *   Updates last_seen_at = NOW(), and updates pid, process_name, process_path, exposure_scope.
   * If new:
   *   Inserts record with status = 'open', first_seen_at = NOW(), last_seen_at = NOW().
   */
  async upsertPort({
    organization_id,
    device_id,
    port,
    protocol = 'tcp',
    bind_address = '0.0.0.0',
    exposure_scope = 'unknown',
    pid = null,
    process_name = null,
    process_path = null,
    status = 'open'
  }, client = db) {
    if (!organization_id || !device_id || !port) {
      throw new Error('organization_id, device_id, and port are required');
    }

    const normPort = parseInt(port, 10);
    const normProtocol = String(protocol).toLowerCase().trim();
    const normBind = String(bind_address).trim();
    const normScope = ['loopback', 'private', 'public', 'unknown'].includes(exposure_scope)
      ? exposure_scope
      : 'unknown';
    const normStatus = status === 'closed' ? 'closed' : 'open';

    const text = `
      INSERT INTO public.device_listening_ports (
        organization_id,
        device_id,
        port,
        protocol,
        bind_address,
        exposure_scope,
        pid,
        process_name,
        process_path,
        status,
        first_seen_at,
        last_seen_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
      ON CONFLICT (device_id, port, protocol, bind_address, status)
      DO UPDATE SET
        last_seen_at = NOW(),
        exposure_scope = EXCLUDED.exposure_scope,
        pid = COALESCE(EXCLUDED.pid, device_listening_ports.pid),
        process_name = COALESCE(EXCLUDED.process_name, device_listening_ports.process_name),
        process_path = COALESCE(EXCLUDED.process_path, device_listening_ports.process_path)
      RETURNING *;
    `;

    const params = [
      organization_id,
      device_id,
      normPort,
      normProtocol,
      normBind,
      normScope,
      pid ? parseInt(pid, 10) : null,
      process_name ? String(process_name).slice(0, 255) : null,
      process_path ? String(process_path).slice(0, 500) : null,
      normStatus
    ];

    const res = await client.query(text, params);
    return res.rows[0];
  },

  /**
   * Retrieves listening ports for a specific device, optionally scoped by organization.
   */
  async getPortsForDevice(device_id, organization_id = null, filters = {}, client = db) {
    let query = `
      SELECT *
      FROM public.device_listening_ports
      WHERE device_id = $1
    `;
    const params = [device_id];
    let idx = 2;

    if (organization_id) {
      query += ` AND organization_id = $${idx++}`;
      params.push(organization_id);
    }

    if (filters.status) {
      query += ` AND status = $${idx++}`;
      params.push(filters.status);
    }

    if (filters.exposure_scope) {
      query += ` AND exposure_scope = $${idx++}`;
      params.push(filters.exposure_scope);
    }

    if (filters.protocol) {
      query += ` AND protocol = $${idx++}`;
      params.push(filters.protocol.toLowerCase());
    }

    query += ` ORDER BY port ASC, last_seen_at DESC`;

    if (filters.limit) {
      query += ` LIMIT $${idx++}`;
      params.push(parseInt(filters.limit, 10));
    }

    if (filters.offset) {
      query += ` OFFSET $${idx++}`;
      params.push(parseInt(filters.offset, 10));
    }

    const res = await client.query(query, params);
    return res.rows;
  },

  /**
   * Retrieves listening ports across an entire organization with optional filters.
   */
  async getPortsForOrganization(organization_id, filters = {}, client = db) {
    if (!organization_id) {
      throw new Error('organization_id is required');
    }

    let query = `
      SELECT p.*, d.hostname, d.os, d.platform, d.status AS device_status
      FROM public.device_listening_ports p
      JOIN public.devices d ON p.device_id = d.id
      WHERE p.organization_id = $1
    `;
    const params = [organization_id];
    let idx = 2;

    if (filters.status) {
      query += ` AND p.status = $${idx++}`;
      params.push(filters.status);
    }

    if (filters.exposure_scope) {
      query += ` AND p.exposure_scope = $${idx++}`;
      params.push(filters.exposure_scope);
    }

    if (filters.protocol) {
      query += ` AND p.protocol = $${idx++}`;
      params.push(filters.protocol.toLowerCase());
    }

    if (filters.port) {
      query += ` AND p.port = $${idx++}`;
      params.push(parseInt(filters.port, 10));
    }

    query += ` ORDER BY p.port ASC, p.last_seen_at DESC`;

    if (filters.limit) {
      query += ` LIMIT $${idx++}`;
      params.push(parseInt(filters.limit, 10));
    }

    if (filters.offset) {
      query += ` OFFSET $${idx++}`;
      params.push(parseInt(filters.offset, 10));
    }

    const res = await client.query(query, params);
    return res.rows;
  }
};

module.exports = DeviceListeningPort;
