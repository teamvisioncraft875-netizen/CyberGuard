const db = require('../config/db');
const redis = require('../config/redis');
const RefreshToken = require('../models/RefreshToken');
const Device = require('../models/Device');
const { log: auditLog } = require('./auditService');

// Read-only model safety: Ensure Device.updateStatus is safely available
if (typeof Device.updateStatus !== 'function') {
  Device.updateStatus = async function (device_id, status) {
    const text = `
      UPDATE public.devices
      SET status = $2
      WHERE device_id = $1 OR device_fingerprint = $1 OR id::text = $1
      RETURNING *;
    `;
    const res = await db.query(text, [device_id, status]);
    return res.rows[0] || null;
  };
}

const PROTECTED_IPS = new Set([
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  'localhost'
]);

const PROTECTED_DOMAINS = new Set([
  'localhost',
  'cyberguard.internal',
  'cyberguard.security',
  'api.cyberguard.internal',
  'dashboard.cyberguard.internal'
]);

const net = require('net');
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Checks whether an IP address is in a protected internal/loopback/broadcast range or malformed.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isProtectedIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const clean = ip.trim().toLowerCase();
  
  if (net.isIP(clean) === 0) return true; // Malformed IP is rejected as protected/invalid
  if (PROTECTED_IPS.has(clean)) return true;

  // Broadcast & 0.0.0.0/8
  if (clean === '255.255.255.255' || clean === '0.0.0.0' || clean.startsWith('0.')) return true;

  // Loopback (127.0.0.0/8)
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;

  // RFC 1918 Private Ranges
  // 10.0.0.0/8
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
  // 172.16.0.0/12
  if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
  // 192.168.0.0/16
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
  // 169.254.0.0/16 (link-local)
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;

  // Multicast & Reserved (224.0.0.0 - 255.255.255.255)
  const firstOctet = parseInt(clean.split('.')[0], 10);
  if (!isNaN(firstOctet) && firstOctet >= 224) return true;

  return false;
}

/**
 * Checks whether a domain name belongs to protected infrastructure or is malformed.
 *
 * @param {string} domain
 * @returns {boolean}
 */
function isProtectedDomain(domain) {
  if (!domain || typeof domain !== 'string') return true;
  const clean = domain.trim().toLowerCase();
  if (clean.includes('*') || /[/\\:?#@\s]/.test(clean)) return true;
  if (PROTECTED_DOMAINS.has(clean)) return true;
  if (clean.endsWith('.cyberguard.internal') || clean.endsWith('.cyberguard.security') || clean.endsWith('.localhost')) {
    return true;
  }
  return false;
}

/**
 * Revokes all active refresh tokens for the target user.
 *
 * @param {Object} action
 * @returns {Promise<{ revoked_tokens: number, user_id: string }>}
 */
async function revokeSession(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.user_id || !UUID_REGEX.test(target.user_id)) {
    return { success: false, error: 'target.user_id must be a valid UUID for revoke_session' };
  }
  const count = await RefreshToken.revokeByUserId(target.user_id);
  return { revoked_tokens: count || 0, user_id: target.user_id };
}

/**
 * Stores blocked IP in Redis without expiration.
 *
 * @param {Object} action
 * @returns {Promise<{ blocked_ip: string, action_id: string } | { success: false, error: string }>}
 */
async function blockIp(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.ip_address) {
    return { success: false, error: 'target.ip_address is required for block_ip' };
  }
  if (isProtectedIp(target.ip_address)) {
    return { success: false, error: 'target is protected' };
  }
  const key = `blocked_ips:${action.id || target.ip_address}`;
  await redis.set(key, target.ip_address);
  return { blocked_ip: target.ip_address, action_id: action.id };
}

/**
 * Stores blocked domain in Redis without expiration.
 *
 * @param {Object} action
 * @returns {Promise<{ blocked_domain: string, action_id: string } | { success: false, error: string }>}
 */
async function blockDomain(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.domain) {
    return { success: false, error: 'target.domain is required for block_domain' };
  }
  if (isProtectedDomain(target.domain)) {
    return { success: false, error: 'target is protected' };
  }
  const key = `blocked_domains:${action.id || target.domain}`;
  await redis.set(key, target.domain);
  return { blocked_domain: target.domain, action_id: action.id };
}

/**
 * Stores blocked URL in Redis without expiration.
 *
 * @param {Object} action
 * @returns {Promise<{ blocked_url: string, action_id: string } | { success: false, error: string }>}
 */
async function blockUrl(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  const url = target.url || target.indicator_value;
  if (!url) {
    return { success: false, error: 'target.url is required for block_url' };
  }
  const key = `blocked_urls:${action.id || url}`;
  await redis.set(key, url);
  return { blocked_url: url, action_id: action.id };
}

/**
 * Updates device status to 'isolated' in PostgreSQL.
 *
 * @param {Object} action
 * @returns {Promise<{ isolated_device_id: string } | { success: false, error: string }>}
 */
async function isolateDevice(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  const deviceId = target.device_id || action.target_device_id;
  if (!deviceId || !UUID_REGEX.test(deviceId)) {
    return { success: false, error: 'target.device_id must be a valid UUID for isolate_device' };
  }
  const devCheck = await db.query(
    'SELECT id FROM public.devices WHERE id = $1 AND ($2::UUID IS NULL OR organization_id = $2::UUID);',
    [deviceId, action.organization_id]
  );
  if (!devCheck.rows || devCheck.rows.length === 0) {
    return { success: false, error: 'Target device not found or does not belong to organization' };
  }
  await Device.updateStatus(deviceId, 'isolated');
  return { isolated_device_id: deviceId };
}

/**
 * Simulates notifying admin for automated action.
 *
 * @param {Object} action
 * @returns {Promise<{ notified: boolean, action_id: string }>}
 */
async function notifyAdmin(action) {
  return { notified: true, action_id: action.id };
}

/**
 * Updates device status to 'suspended' in PostgreSQL.
 *
 * @param {Object} action
 * @returns {Promise<{ suspended_device_id: string } | { success: false, error: string }>}
 */
async function suspendDevice(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.device_id || !UUID_REGEX.test(target.device_id)) {
    return { success: false, error: 'target.device_id must be a valid UUID for suspend_device' };
  }
  // Validate device belongs to organization
  const devCheck = await db.query(
    'SELECT id FROM public.devices WHERE id = $1 AND ($2::UUID IS NULL OR organization_id = $2::UUID);',
    [target.device_id, action.organization_id]
  );
  if (!devCheck.rows || devCheck.rows.length === 0) {
    return { success: false, error: 'Target device not found or does not belong to organization' };
  }
  await Device.updateStatus(target.device_id, 'suspended');
  return { suspended_device_id: target.device_id };
}

/**
 * Stores password reset requirement flag in Redis with a 7-day TTL.
 *
 * @param {Object} action
 * @returns {Promise<{ user_id: string, expires_in_days: number } | { success: false, error: string }>}
 */
async function forcePasswordReset(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.user_id || !UUID_REGEX.test(target.user_id)) {
    return { success: false, error: 'target.user_id must be a valid UUID for force_password_reset' };
  }
  // Validate user belongs to organization
  const userCheck = await db.query(
    'SELECT id FROM public.users WHERE id = $1 AND ($2::UUID IS NULL OR organization_id = $2::UUID);',
    [target.user_id, action.organization_id]
  );
  if (!userCheck.rows || userCheck.rows.length === 0) {
    return { success: false, error: 'Target user not found or does not belong to organization' };
  }
  const sevenDaysInSeconds = 7 * 24 * 60 * 60;
  await redis.set(`password_reset_required:${target.user_id}`, 'true', { EX: sevenDaysInSeconds });
  return { user_id: target.user_id, expires_in_days: 7 };
}

/**
 * Carries out live response action execution with strict guardrails and audit logging.
 *
 * @param {Object} action - The response_action record
 * @param {'system_policy'|'admin'|'user'|'background_scheduler'} [actor_type='system_policy']
 * @returns {Promise<{ success: boolean, result?: Object, error?: string, already_executed?: boolean }>}
 */
async function execute(action, actor_type = 'system_policy') {
  if (!action || !action.id) {
    return { success: false, error: 'Valid action with ID is required' };
  }

  // Guardrail a: ONLY execute if status='approved' or status='scheduled'
  if (action.status !== 'approved' && action.status !== 'scheduled') {
    const err = new Error(`Action status must be 'approved' or 'scheduled' to execute (got '${action?.status}')`);
    err.statusCode = 400;
    err.status = 400;
    throw err;
  }

  // Guardrail b: ONLY execute if action_mode='live'
  if (action.action_mode !== 'live') {
    const err = new Error(`Action mode must be 'live' to execute (got '${action?.action_mode}')`);
    err.statusCode = 400;
    err.status = 400;
    throw err;
  }

  // Guardrail c: Increment execution_attempts, cap at 3
  const currentAttempts = Number(action?.execution_attempts || 0);
  if (currentAttempts >= 3) {
    const errorMsg = 'Maximum execution attempts (3) exceeded';
    try {
      await db.query(`
        UPDATE public.response_actions
        SET status = 'failed',
            last_execution_error = $1,
            result = $2
        WHERE id = $3;
      `, [errorMsg, JSON.stringify({ error: errorMsg }), action.id]);
    } catch (dbErr) {
      console.warn('[executionService DB update error]', dbErr.message);
    }
    return { success: false, error: errorMsg };
  }

  // CONCURRENCY & DEDUPLICATION GUARD:
  // Atomically claim the action from ('approved', 'scheduled') -> 'executing'.
  // Only ONE execution thread across all schedulers/workers can succeed here.
  const claimRes = await db.query(`
    UPDATE public.response_actions
    SET status = 'executing',
        execution_attempts = COALESCE(execution_attempts, 0) + 1
    WHERE id = $1 AND status IN ('approved', 'scheduled')
    RETURNING *;
  `, [action.id]);

  if (!claimRes.rows || claimRes.rows.length === 0) {
    return {
      success: false,
      already_executed: true,
      error: `Action ${action.id} is already executing, completed, or no longer approved`
    };
  }

  const activeAction = claimRes.rows[0];
  const newAttempts = Number(activeAction.execution_attempts || 1);
  const target = typeof activeAction.target === 'string' ? JSON.parse(activeAction.target) : (activeAction.target || {});

  try {
    let executionResult;

    switch (action.action_type) {
      case 'revoke_session':
        executionResult = await revokeSession(action);
        break;
      case 'block_ip':
        executionResult = await blockIp(action);
        break;
      case 'block_domain':
        executionResult = await blockDomain(action);
        break;
      case 'block_url':
        executionResult = await blockUrl(action);
        break;
      case 'suspend_device':
        executionResult = await suspendDevice(action);
        break;
      case 'isolate_device':
        executionResult = await isolateDevice(action);
        break;
      case 'notify_admin':
        executionResult = await notifyAdmin(action);
        break;
      case 'force_password_reset':
        executionResult = await forcePasswordReset(action);
        break;
      default:
        throw new Error(`Unsupported action_type: ${action.action_type}`);
    }

    // Check if the executor returned a protected failure
    if (executionResult && executionResult.success === false) {
      const errMsg = executionResult.error || 'Execution failed';
      if (action.id) {
        try {
          await db.query(`
            UPDATE public.response_actions
            SET status = 'failed',
                execution_attempts = $1,
                last_execution_error = $2,
                result = $3
            WHERE id = $4;
          `, [newAttempts, errMsg, JSON.stringify({ error: errMsg }), action.id]);
        } catch (dbErr) {
          console.warn('[executionService DB update error]', dbErr.message);
        }
      }

      await auditLog({
        organization_id: action.organization_id || null,
        user_id: action.approved_by_id || null,
        actor_type: actor_type || 'system_policy',
        action: 'action_executed',
        resource_type: 'response_action',
        resource_id: action.id,
        details: { action_type: action.action_type, result: { error: errMsg }, target }
      });

      return { success: false, error: errMsg };
    }

    // Phase C Integration: If action is firewall-related (block_ip, block_domain), queue agent command
    if (['block_ip', 'block_domain', 'temporary_block_ip'].includes(action.action_type)) {
      try {
        const agentCommandService = require('./agentCommandService');
        const targetDeviceId = action.target_device_id || target.target_device_id || target.device_id;
        
        let targetDevice = null;
        if (targetDeviceId) {
          const devRes = await db.query('SELECT * FROM public.devices WHERE id = $1;', [targetDeviceId]);
          targetDevice = devRes.rows[0] || null;
        } else if (target.user_id) {
          const devRes = await db.query(
            `SELECT * FROM public.devices 
             WHERE user_id = $1 AND organization_id = $2 AND status != 'disabled' 
             ORDER BY last_heartbeat DESC NULLS LAST LIMIT 1;`,
            [target.user_id, action.organization_id]
          );
          targetDevice = devRes.rows[0] || null;
        }

        if (targetDevice && targetDevice.status !== 'disabled') {
          const cmdResult = await agentCommandService.createAgentCommandFromResponseAction(action, targetDevice.id);
          if (cmdResult && cmdResult.success) {
            executionResult.agent_command_id = cmdResult.command_id;
            executionResult.target_device_id = targetDevice.id;
          }
        }
      } catch (cmdErr) {
        console.warn('[executionService] Warning: Failed to enqueue agent command for firewall action:', cmdErr.message);
      }
    }

    // Success update
    if (action.id) {
      try {
        await db.query(`
          UPDATE public.response_actions
          SET status = 'executed',
              executed_at = NOW(),
              result = $1,
              execution_attempts = $2,
              last_execution_error = NULL
          WHERE id = $3;
        `, [JSON.stringify(executionResult), newAttempts, action.id]);
      } catch (dbErr) {
        console.warn('[executionService DB update error]', dbErr.message);
      }
    }

    // Log to audit_log: action='action_executed', resource_type='response_action', resource_id=action.id, details={action_type, result, target}
    await auditLog({
      organization_id: action.organization_id || null,
      user_id: action.approved_by_id || null,
      actor_type: actor_type || 'system_policy',
      action: 'action_executed',
      resource_type: 'response_action',
      resource_id: action.id,
      details: {
        action_type: action.action_type,
        result: executionResult,
        target
      }
    });

    return { success: true, result: executionResult };
  } catch (err) {
    const errorMsg = err.message || 'Execution error';
    if (action.id) {
      try {
        await db.query(`
          UPDATE public.response_actions
          SET status = 'failed',
              execution_attempts = $1,
              last_execution_error = $2,
              result = $3
          WHERE id = $4;
        `, [newAttempts, errorMsg, JSON.stringify({ error: errorMsg }), action.id]);
      } catch (dbErr) {
        console.warn('[executionService DB update error]', dbErr.message);
      }
    }

    await auditLog({
      organization_id: action.organization_id || null,
      user_id: action.approved_by_id || null,
      actor_type: actor_type || 'system_policy',
      action: 'action_executed',
      resource_type: 'response_action',
      resource_id: action.id,
      details: {
        action_type: action.action_type,
        result: { error: errorMsg },
        target
      }
    });

    return { success: false, error: errorMsg };
  }
}

module.exports = {
  execute,
  revokeSession,
  blockIp,
  blockDomain,
  blockUrl,
  suspendDevice,
  isolateDevice,
  notifyAdmin,
  forcePasswordReset,
  isProtectedIp,
  isProtectedDomain
};
