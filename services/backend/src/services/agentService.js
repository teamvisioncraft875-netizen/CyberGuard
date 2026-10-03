const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../config/db');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Agent Service — Enterprise Agent v1 Foundation.
 * Manages enrollment tokens, device identity, heartbeat tracking, and command execution.
 */
const agentService = {
  /**
   * Generates a single-use cryptographically secure enrollment token for an organization.
   *
   * @param {string} organization_id - Target organization UUID
   * @param {number} [valid_for_hours=24] - Token validity window
   * @returns {Promise<string>} 64-char hex enrollment token
   */
  async generateEnrollmentToken(organization_id, valid_for_hours = 24) {
    if (!organization_id || !UUID_REGEX.test(organization_id)) {
      throw new Error('Valid organization_id UUID is required to generate enrollment token');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const hours = Math.max(1, parseInt(valid_for_hours, 10) || 24);

    const query = `
      INSERT INTO public.devices (
        organization_id,
        enrollment_token,
        token_expires_at,
        status,
        created_at
      )
      VALUES ($1, $2, NOW() + ($3 || ' hours')::interval, 'pending', NOW())
      RETURNING *;
    `;

    await db.query(query, [organization_id, token, hours]);
    return token;
  },

  /**
   * Validates an enrollment token.
   *
   * @param {string} token
   * @returns {Promise<string|null>} organization_id if valid, or null if expired/non-existent
   */
  async validateEnrollmentToken(token) {
    if (!token || typeof token !== 'string') return null;

    try {
      const query = `
        SELECT organization_id, token_expires_at, status
        FROM public.devices
        WHERE enrollment_token = $1
          AND status = 'pending';
      `;
      const res = await db.query(query, [token.trim()]);
      if (!res.rows || res.rows.length === 0) {
        return null;
      }

      const row = res.rows[0];
      if (new Date(row.token_expires_at) <= new Date()) {
        return null;
      }

      return row.organization_id;
    } catch (err) {
      console.warn('[agentService.validateEnrollmentToken error]', err.message);
      return null;
    }
  },

  /**
   * Enrolls a device using a valid enrollment token.
   * Generates permanent agent credentials (credential_id + secret) and transitions status to 'online'.
   * The plaintext credential_secret is returned ONCE and never stored or returned again.
   *
   * @param {Object} params
   * @param {string} params.token - One-time enrollment token
   * @param {string} [params.hostname='unknown-host']
   * @param {string} [params.os='unknown-os']
   * @param {string} [params.platform='desktop']
   * @param {string|null} [params.linked_user_id=null]
   * @param {string} [params.agent_version='1.0.0']
   * @returns {Promise<{ device_id: string, credential_id: string, credential_secret: string, organization_id: string }|null>}
   */
  async enrollDevice({
    token,
    hostname = 'unknown-host',
    os = 'unknown-os',
    platform = 'desktop',
    linked_user_id = null,
    agent_version = '1.0.0'
  }) {
    if (!token) return null;

    const orgId = await this.validateEnrollmentToken(token);
    if (!orgId) return null;

    // Generate credentials
    const credential_id = crypto.randomUUID();
    const credential_secret = crypto.randomBytes(32).toString('hex');
    const credential_secret_hash = await bcrypt.hash(credential_secret, 10);

    try {
      const updateQuery = `
        UPDATE public.devices
        SET status = 'online',
            hostname = $1,
            os = $2,
            platform = $3,
            device_name = $1,
            user_id = $4,
            agent_credentials_id = $5,
            agent_credentials_hash = $6,
            agent_version = $7,
            last_heartbeat = NOW(),
            last_seen = NOW(),
            enrollment_token = NULL,
            token_expires_at = NULL,
            device_id = id::text
        WHERE enrollment_token = $8
          AND status = 'pending'
          AND token_expires_at > NOW()
        RETURNING *;
      `;

      const res = await db.query(updateQuery, [
        hostname,
        os,
        platform,
        linked_user_id && UUID_REGEX.test(linked_user_id) ? linked_user_id : null,
        credential_id,
        credential_secret_hash,
        agent_version,
        token.trim()
      ]);

      if (!res.rows || res.rows.length === 0) {
        return null;
      }

      const enrolled = res.rows[0];
      return {
        device_id: enrolled.id,
        credential_id,
        credential_secret,
        organization_id: enrolled.organization_id
      };
    } catch (err) {
      console.warn('[agentService.enrollDevice error]', err.message);
      return null;
    }
  },

  /**
   * Internal helper: Verifies agent credentials against the database.
   * Safe, never throws. Returns the device record if valid, null otherwise.
   *
   * @param {string} device_id
   * @param {string} credential_id
   * @param {string} credential_secret
   * @returns {Promise<Object|null>}
   */
  async verifyAgentCredentials(device_id, credential_id, credential_secret) {
    if (!device_id || !credential_id || !credential_secret) return null;
    if (!UUID_REGEX.test(device_id) || !UUID_REGEX.test(credential_id)) return null;

    try {
      const query = `
        SELECT *
        FROM public.devices
        WHERE id = $1
          AND agent_credentials_id = $2;
      `;
      const res = await db.query(query, [device_id, credential_id]);
      if (!res.rows || res.rows.length === 0) {
        return null;
      }

      const device = res.rows[0];
      if (device.status === 'disabled') {
        return null;
      }

      if (!device.agent_credentials_hash) {
        return null;
      }

      const isMatch = await bcrypt.compare(credential_secret, device.agent_credentials_hash);
      return isMatch ? device : null;
    } catch (err) {
      console.warn('[agentService.verifyAgentCredentials error]', err.message);
      return null;
    }
  },

  /**
   * Records a periodic agent heartbeat and updates online status and last_heartbeat timestamp.
   *
   * @param {string} device_id
   * @param {string} credential_id
   * @param {string} credential_secret
   * @param {Object} [meta={}]
   * @returns {Promise<{ status: string, next_heartbeat_expected_in_seconds: number, next_heartbeat_in_seconds: number, commands_pending: number }|null>}
   */
  async recordHeartbeat(device_id, credential_id, credential_secret, meta = {}) {
    const device = await this.verifyAgentCredentials(device_id, credential_id, credential_secret);
    if (!device) return null;

    try {
      const updateQuery = `
        UPDATE public.devices
        SET last_heartbeat = NOW(),
            last_seen = NOW(),
            status = CASE WHEN status = 'disabled' THEN 'disabled' ELSE 'online' END,
            agent_version = COALESCE($2, agent_version)
        WHERE id = $1
        RETURNING *;
      `;
      await db.query(updateQuery, [device_id, meta.agent_version || null]);

      // Count pending commands
      const cmdCountQuery = `
        SELECT COUNT(*)::int AS count
        FROM public.agent_commands
        WHERE device_id = $1
          AND status IN ('pending', 'executing');
      `;
      const cmdRes = await db.query(cmdCountQuery, [device_id]);
      const pendingCount = cmdRes.rows[0]?.count || 0;

      return {
        status: 'online',
        next_heartbeat_expected_in_seconds: 60,
        next_heartbeat_in_seconds: 60,
        commands_pending: pendingCount
      };
    } catch (err) {
      console.warn('[agentService.recordHeartbeat error]', err.message);
      return null;
    }
  },

  /**
   * Retrieves full device status and last_heartbeat age.
   *
   * @param {string} device_id
   * @param {string|null} [organization_id=null] - Optional tenant scoping check
   * @returns {Promise<Object|null>}
   */
  async getDeviceStatus(device_id, organization_id = null) {
    if (!device_id || !UUID_REGEX.test(device_id)) return null;

    try {
      const query = `
        SELECT id, organization_id, user_id, device_name, hostname, os, platform,
               agent_version, status, last_heartbeat, created_at,
               EXTRACT(EPOCH FROM (NOW() - last_heartbeat))::int AS last_heartbeat_age_seconds
        FROM public.devices
        WHERE id = $1;
      `;
      const res = await db.query(query, [device_id]);
      if (!res.rows || res.rows.length === 0) return null;

      const device = res.rows[0];
      if (organization_id && device.organization_id !== organization_id) {
        return null;
      }

      return device;
    } catch (err) {
      console.warn('[agentService.getDeviceStatus error]', err.message);
      return null;
    }
  },

  /**
   * Fetches pending/executing commands queued for a device.
   *
   * @param {string} device_id
   * @param {string} credential_id
   * @param {string} credential_secret
   * @returns {Promise<Array<Object>|null>}
   */
  async getCommandsForDevice(device_id, credential_id, credential_secret) {
    const device = await this.verifyAgentCredentials(device_id, credential_id, credential_secret);
    if (!device) return null;

    try {
      const query = `
        SELECT id, command_type, target_data, status, created_at, executed_at, result
        FROM public.agent_commands
        WHERE device_id = $1
          AND status IN ('pending', 'executing')
        ORDER BY created_at ASC;
      `;
      const res = await db.query(query, [device_id]);
      return res.rows || [];
    } catch (err) {
      console.warn('[agentService.getCommandsForDevice error]', err.message);
      return [];
    }
  },

  /**
   * Records the execution result of an agent command.
   *
   * @param {string} device_id
   * @param {string} command_id
   * @param {'completed'|'failed'} status
   * @param {Object} result
   * @param {string} credential_id
   * @param {string} credential_secret
   * @returns {Promise<boolean>}
   */
  async recordCommandResult(device_id, command_id, status, result, credential_id, credential_secret) {
    const device = await this.verifyAgentCredentials(device_id, credential_id, credential_secret);
    if (!device) return false;

    if (!command_id || !UUID_REGEX.test(command_id)) return false;
    const cleanStatus = status === 'failed' ? 'failed' : 'completed';

    try {
      const query = `
        UPDATE public.agent_commands
        SET status = $1,
            result = $2,
            executed_at = NOW()
        WHERE id = $3
          AND device_id = $4
        RETURNING id;
      `;
      const res = await db.query(query, [
        cleanStatus,
        typeof result === 'string' ? result : JSON.stringify(result || {}),
        command_id,
        device_id
      ]);

      return Boolean(res.rows && res.rows.length > 0);
    } catch (err) {
      console.warn('[agentService.recordCommandResult error]', err.message);
      return false;
    }
  }
};

module.exports = agentService;
