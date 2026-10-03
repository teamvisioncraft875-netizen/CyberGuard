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

/**
 * Checks whether an IP address is in a protected internal/loopback range.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isProtectedIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim().toLowerCase();
  if (PROTECTED_IPS.has(clean)) return true;
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
  return false;
}

/**
 * Checks whether a domain name belongs to protected infrastructure.
 *
 * @param {string} domain
 * @returns {boolean}
 */
function isProtectedDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const clean = domain.trim().toLowerCase();
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
  if (!target.user_id) {
    throw new Error('target.user_id is required for revoke_session');
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
    throw new Error('target.ip_address is required for block_ip');
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
    throw new Error('target.domain is required for block_domain');
  }
  if (isProtectedDomain(target.domain)) {
    return { success: false, error: 'target is protected' };
  }
  const key = `blocked_domains:${action.id || target.domain}`;
  await redis.set(key, target.domain);
  return { blocked_domain: target.domain, action_id: action.id };
}

/**
 * Updates device status to 'suspended' in PostgreSQL.
 *
 * @param {Object} action
 * @returns {Promise<{ suspended_device_id: string }>}
 */
async function suspendDevice(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.device_id) {
    throw new Error('target.device_id is required for suspend_device');
  }
  await Device.updateStatus(target.device_id, 'suspended');
  return { suspended_device_id: target.device_id };
}

/**
 * Stores password reset requirement flag in Redis with a 7-day TTL.
 *
 * @param {Object} action
 * @returns {Promise<{ user_id: string, expires_in_days: number }>}
 */
async function forcePasswordReset(action) {
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});
  if (!target.user_id) {
    throw new Error('target.user_id is required for force_password_reset');
  }
  const sevenDaysInSeconds = 7 * 24 * 60 * 60;
  await redis.set(`password_reset_required:${target.user_id}`, 'true', { EX: sevenDaysInSeconds });
  return { user_id: target.user_id, expires_in_days: 7 };
}

/**
 * Carries out live response action execution with strict guardrails and audit logging.
 *
 * @param {Object} action - The response_action record
 * @param {'system_policy'|'admin'|'user'} [actor_type='system_policy']
 * @returns {Promise<{ success: boolean, result?: Object, error?: string }>}
 */
async function execute(action, actor_type = 'system_policy') {
  // Guardrail c: Increment execution_attempts, cap at 3 (fail after 3 retries)
  const currentAttempts = Number(action?.execution_attempts || 0);
  if (currentAttempts >= 3) {
    const errorMsg = 'Maximum execution attempts (3) exceeded';
    if (action?.id) {
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
    }
    return { success: false, error: errorMsg };
  }

  // Guardrail a: ONLY execute if status='approved' or status='scheduled' (throw 400 if status='proposed', 'pending_approval', etc.)
  if (!action || (action.status !== 'approved' && action.status !== 'scheduled')) {
    const err = new Error(`Action status must be 'approved' or 'scheduled' to execute (got '${action?.status}')`);
    err.statusCode = 400;
    err.status = 400;
    throw err;
  }

  // Guardrail b: ONLY execute if action_mode='live' (throw 400 if 'shadow')
  if (action.action_mode !== 'live') {
    const err = new Error(`Action mode must be 'live' to execute (got '${action?.action_mode}')`);
    err.statusCode = 400;
    err.status = 400;
    throw err;
  }

  const newAttempts = currentAttempts + 1;
  const target = typeof action.target === 'string' ? JSON.parse(action.target) : (action.target || {});

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
      case 'suspend_device':
        executionResult = await suspendDevice(action);
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
  suspendDevice,
  forcePasswordReset,
  isProtectedIp,
  isProtectedDomain
};
