const db = require('../config/db');

/**
 * DeviceListeningPort Model — Manages discovered network listening sockets
 * for Attack Surface Discovery (Phase A Hardened).
 */
const DeviceListeningPort = {
  /**
   * Bulk upserts an array of observed listening ports in a SINGLE database round-trip.
   * Parameterized and multi-tenant isolated.
   */
  async bulkUpsert({ organization_id, device_id, ports = [] }, client = db) {
    if (!organization_id || !device_id) {
      throw new Error('organization_id and device_id are required');
    }
    if (!Array.isArray(ports) || ports.length === 0) {
      return [];
    }

    const valueClauses = [];
    const params = [];
    let idx = 1;

    // Deduplicate by key within the snapshot to prevent PostgreSQL "ON CONFLICT DO UPDATE command cannot affect row a second time"
    const seen = new Set();
    const uniquePorts = [];
    for (const p of ports) {
      if (!p || typeof p !== 'object') continue;
      const normPort = parseInt(p.port, 10);
      if (isNaN(normPort) || normPort <= 0 || normPort > 65535) continue;
      const normProtocol = String(p.protocol || 'tcp').toLowerCase().trim();
      const normBind = String(p.bind_address || '0.0.0.0').trim();
      const key = `${normPort}:${normProtocol}:${normBind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      uniquePorts.push({ ...p, port: normPort, protocol: normProtocol, bind_address: normBind });
    }

    for (const p of uniquePorts) {
      const normScope = ['loopback', 'private', 'public', 'unknown'].includes(p.exposure_scope)
        ? p.exposure_scope
        : 'unknown';
      const pid = p.pid ? parseInt(p.pid, 10) : null;
      const processName = p.process_name ? String(p.process_name).slice(0, 255) : null;
      const processPath = p.process_path ? String(p.process_path).slice(0, 500) : null;

      valueClauses.push(
        `($${idx}, $${idx + 1}, $${idx + 2}, $${idx + 3}, $${idx + 4}, $${idx + 5}, $${idx + 6}, $${idx + 7}, $${idx + 8}, 'open', NOW(), NOW())`
      );
      params.push(
        organization_id,
        device_id,
        p.port,
        p.protocol,
        p.bind_address,
        normScope,
        pid,
        processName,
        processPath
      );
      idx += 9;
    }

    if (valueClauses.length === 0) {
      return [];
    }

    const query = `
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
      VALUES ${valueClauses.join(',\n')}
      ON CONFLICT (device_id, port, protocol, bind_address, status)
      DO UPDATE SET
        last_seen_at = NOW(),
        exposure_scope = EXCLUDED.exposure_scope,
        pid = COALESCE(EXCLUDED.pid, device_listening_ports.pid),
        process_name = COALESCE(EXCLUDED.process_name, device_listening_ports.process_name),
        process_path = COALESCE(EXCLUDED.process_path, device_listening_ports.process_path)
      RETURNING *;
    `;

    const res = await client.query(query, params);
    return res.rows;
  },

  /**
   * Reconciles the latest snapshot against existing inventory:
   * 1. Reopens any previously closed ports that have reappeared (status='open', closed_at=NULL).
   * 2. Bulk upserts all active ports in the snapshot in a single parameterized query.
   * 3. Marks open ports not observed in this snapshot as 'closed' with closed_at = NOW(), last_seen_at = NOW().
   * Runs in a single transaction.
   */
  async reconcileSnapshot({ organization_id, device_id, currentPorts = [] }, client = null) {
    if (!organization_id || !device_id) {
      throw new Error('organization_id and device_id are required');
    }

    const runReconciliation = async (txClient) => {
      // Step A: Extract active keys from snapshot
      const activeKeySet = [];
      const seen = new Set();
      for (const p of currentPorts) {
        if (!p || !p.port) continue;
        const normPort = parseInt(p.port, 10);
        if (isNaN(normPort) || normPort <= 0 || normPort > 65535) continue;
        const normProtocol = String(p.protocol || 'tcp').toLowerCase().trim();
        const normBind = String(p.bind_address || '0.0.0.0').trim();
        const key = `${normPort}:${normProtocol}:${normBind}`;
        if (!seen.has(key)) {
          seen.add(key);
          activeKeySet.push({ port: normPort, protocol: normProtocol, bind_address: normBind });
        }
      }

      // Step B: Reopen any previously closed rows that have reappeared in this snapshot
      if (activeKeySet.length > 0) {
        const reopenPredicates = [];
        const reopenParams = [device_id, organization_id];
        let rIdx = 3;

        for (const k of activeKeySet) {
          reopenPredicates.push(`(port = $${rIdx} AND protocol = $${rIdx + 1} AND bind_address = $${rIdx + 2})`);
          reopenParams.push(k.port, k.protocol, k.bind_address);
          rIdx += 3;
        }

        // Deduplicate: if an open row already exists for this port, delete any stale closed row
        const dedupeQuery = `
          DELETE FROM public.device_listening_ports c
          WHERE c.device_id = $1
            AND c.organization_id = $2
            AND c.status = 'closed'
            AND (${reopenPredicates.join(' OR ')})
            AND EXISTS (
              SELECT 1 FROM public.device_listening_ports o
              WHERE o.device_id = c.device_id
                AND o.port = c.port
                AND o.protocol = c.protocol
                AND o.bind_address = c.bind_address
                AND o.status = 'open'
            );
        `;
        await txClient.query(dedupeQuery, reopenParams);

        // Reopen closed rows to open
        const reopenQuery = `
          UPDATE public.device_listening_ports
          SET status = 'open', closed_at = NULL, last_seen_at = NOW()
          WHERE device_id = $1
            AND organization_id = $2
            AND status = 'closed'
            AND (${reopenPredicates.join(' OR ')});
        `;
        await txClient.query(reopenQuery, reopenParams);
      }

      // Step C: Bulk upsert current snapshot into database (single parameterized write)
      const upserted = await this.bulkUpsert({ organization_id, device_id, ports: currentPorts }, txClient);

      // Step D: Reconcile missing ports - any currently 'open' port for this device not in current snapshot is marked 'closed'
      let closeRes;
      if (activeKeySet.length === 0) {
        // Snapshot is empty: close ALL open ports for this device
        // Deduplicate first
        await txClient.query(`
          DELETE FROM public.device_listening_ports c
          WHERE c.device_id = $1
            AND c.organization_id = $2
            AND c.status = 'closed'
            AND EXISTS (
              SELECT 1 FROM public.device_listening_ports o
              WHERE o.device_id = c.device_id
                AND o.port = c.port
                AND o.protocol = c.protocol
                AND o.bind_address = c.bind_address
                AND o.status = 'open'
            );
        `, [device_id, organization_id]);

        closeRes = await txClient.query(`
          UPDATE public.device_listening_ports
          SET status = 'closed', closed_at = NOW(), last_seen_at = NOW()
          WHERE device_id = $1
            AND organization_id = $2
            AND status = 'open'
          RETURNING *;
        `, [device_id, organization_id]);
      } else {
        const notInPredicates = [];
        const closeParams = [device_id, organization_id];
        let cIdx = 3;

        for (const k of activeKeySet) {
          notInPredicates.push(`(port = $${cIdx} AND protocol = $${cIdx + 1} AND bind_address = $${cIdx + 2})`);
          closeParams.push(k.port, k.protocol, k.bind_address);
          cIdx += 3;
        }

        // Deduplicate first
        await txClient.query(`
          DELETE FROM public.device_listening_ports c
          WHERE c.device_id = $1
            AND c.organization_id = $2
            AND c.status = 'closed'
            AND EXISTS (
              SELECT 1 FROM public.device_listening_ports o
              WHERE o.device_id = c.device_id
                AND o.port = c.port
                AND o.protocol = c.protocol
                AND o.bind_address = c.bind_address
                AND o.status = 'open'
                AND NOT (${notInPredicates.join(' OR ')})
            );
        `, closeParams);

        closeRes = await txClient.query(`
          UPDATE public.device_listening_ports
          SET status = 'closed', closed_at = NOW(), last_seen_at = NOW()
          WHERE device_id = $1
            AND organization_id = $2
            AND status = 'open'
            AND NOT (${notInPredicates.join(' OR ')})
          RETURNING *;
        `, closeParams);
      }

      return {
        active_count: upserted.length,
        closed_count: closeRes.rows.length,
        closed_ports: closeRes.rows
      };
    };

    if (client) {
      return runReconciliation(client);
    }
    return db.transaction(runReconciliation);
  },

  /**
   * Upserts an observed listening port for a device (single port helper).
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
    const rows = await this.bulkUpsert({
      organization_id,
      device_id,
      ports: [{ port, protocol, bind_address, exposure_scope, pid, process_name, process_path, status }]
    }, client);
    return rows[0] || null;
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
