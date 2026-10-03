const net = require('net');
const { URL } = require('url');
const db = require('../config/db');
const config = require('../config');
const FirewallRule = require('../models/FirewallRule');
const { auditService, AUDIT_ACTIONS } = require('./auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Domain validation regex: labels separated by dots, lowercase alphanumeric and hyphens, no consecutive dots
const DOMAIN_LABEL_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// Standard protected private, loopback, and link-local CIDR ranges
const PROTECTED_IPV4_CIDRS = [
  '127.0.0.0/8',     // Loopback
  '10.0.0.0/8',      // RFC 1918 Class A
  '172.16.0.0/12',   // RFC 1918 Class B (172.16.0.0 - 172.31.255.255)
  '192.168.0.0/16',  // RFC 1918 Class C
  '169.254.0.0/16',  // Link-local
  '0.0.0.0/8',       // Current network / default route
  '224.0.0.0/4',     // Multicast
  '240.0.0.0/4',     // Reserved
  '255.255.255.255/32' // Broadcast
];

// Standard protected static IP addresses
const STATIC_PROTECTED_IPS = [
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '::',
  '8.8.8.8',
  '8.8.4.4',
  '1.1.1.1',
  '1.0.0.1',
  '9.9.9.9'
];

// Protected domains that must never be blocked
const STATIC_PROTECTED_DOMAINS = [
  'localhost',
  'cyberguard.local'
];

/**
 * Parses an IPv4 string into a 32-bit unsigned integer.
 * @param {string} ip
 * @returns {number|null}
 */
function parseIpv4(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255 || !Number.isInteger(n))) {
    return null;
  }
  return (((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0);
}

/**
 * Checks if an IPv4 address falls within a given CIDR block.
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
function isIpv4InCidr(ip, cidr) {
  const [rangeIp, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const ipNum = parseIpv4(ip);
  const rangeNum = parseIpv4(rangeIp);

  if (ipNum === null || rangeNum === null || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Extracts backend host and port from configuration.
 * @returns {{ host: string|null, isIp: boolean }}
 */
function getBackendHostInfo() {
  const backendUrlStr = process.env.CYBERGUARD_BACKEND_URL || process.env.BACKEND_URL || 'http://localhost:5000';
  try {
    const parsed = new URL(backendUrlStr.startsWith('http') ? backendUrlStr : `http://${backendUrlStr}`);
    const hostname = parsed.hostname ? parsed.hostname.toLowerCase() : null;
    if (!hostname) return { host: null, isIp: false };
    const ipType = net.isIP(hostname);
    return { host: hostname, isIp: ipType !== 0 };
  } catch (e) {
    return { host: null, isIp: false };
  }
}

/**
 * Firewall Service — Core business logic for rule validation, creation,
 * revocation, and protected target enforcement.
 */
const firewallService = {
  /**
   * Returns list of IPs, CIDR blocks, and domains that should NEVER be blocked.
   * Consumed by backend validations and downloaded by agents.
   *
   * @returns {{ protected_ips: string[], protected_ip_ranges: string[], protected_domains: string[] }}
   */
  getProtectedTargets() {
    const backendInfo = getBackendHostInfo();
    const protectedIps = new Set(STATIC_PROTECTED_IPS);
    const protectedDomains = new Set(STATIC_PROTECTED_DOMAINS);

    if (backendInfo.host) {
      if (backendInfo.isIp) {
        protectedIps.add(backendInfo.host);
      } else {
        protectedDomains.add(backendInfo.host);
      }
    }

    if (process.env.CYBERGUARD_BACKEND_IP) {
      const customIp = process.env.CYBERGUARD_BACKEND_IP.trim();
      if (net.isIP(customIp)) {
        protectedIps.add(customIp);
      }
    }

    return {
      protected_ips: Array.from(protectedIps),
      protected_ip_ranges: [...PROTECTED_IPV4_CIDRS],
      protected_domains: Array.from(protectedDomains)
    };
  },

  /**
   * Validates target IP or domain against security rules and protected target lists.
   *
   * @param {string} command_type - 'block_ip', 'block_domain', 'unblock_ip', 'unblock_domain', 'temporary_block_ip'
   * @param {Object|string} target_data - Payload containing ip_address or domain
   * @returns {{ valid: boolean, error?: string, target_ip?: string, target_domain?: string }}
   */
  validateFirewallInput(command_type, target_data) {
    if (!command_type || typeof command_type !== 'string') {
      return { valid: false, error: 'command_type must be a non-empty string' };
    }

    const normalizedCmd = command_type.trim().toLowerCase();
    const isIpCommand = ['block_ip', 'unblock_ip', 'temporary_block_ip'].includes(normalizedCmd);
    const isDomainCommand = ['block_domain', 'unblock_domain'].includes(normalizedCmd);

    if (!isIpCommand && !isDomainCommand) {
      return { valid: false, error: `Unsupported firewall command type: ${command_type}` };
    }

    const protectedTargets = this.getProtectedTargets();

    // 1. IP Validation
    if (isIpCommand) {
      let rawIp = null;
      if (typeof target_data === 'string') {
        rawIp = target_data.trim();
      } else if (target_data && typeof target_data === 'object') {
        rawIp = target_data.ip_address || target_data.target_ip || target_data.ip || null;
      }

      if (!rawIp || typeof rawIp !== 'string' || !rawIp.trim()) {
        return { valid: false, error: 'Target IP address is required' };
      }

      const cleanIp = rawIp.trim();
      const ipVersion = net.isIP(cleanIp);
      if (ipVersion === 0) {
        return { valid: false, error: `Invalid IP address format: ${cleanIp}` };
      }

      // Check static protected IPs
      if (protectedTargets.protected_ips.includes(cleanIp)) {
        return { valid: false, error: `Target IP ${cleanIp} is in protected list and cannot be blocked` };
      }

      // Check IPv4 CIDR blocks
      if (ipVersion === 4) {
        for (const cidr of protectedTargets.protected_ip_ranges) {
          if (isIpv4InCidr(cleanIp, cidr)) {
            return {
              valid: false,
              error: `Target IP ${cleanIp} falls within protected private/reserved range (${cidr}) and cannot be blocked`
            };
          }
        }
      }

      // Check IPv6 loopback / link-local / ULA
      if (ipVersion === 6) {
        const lowerIpv6 = cleanIp.toLowerCase();
        if (
          lowerIpv6 === '::1' ||
          lowerIpv6 === '::' ||
          lowerIpv6.startsWith('fe80:') ||
          lowerIpv6.startsWith('fc') ||
          lowerIpv6.startsWith('fd')
        ) {
          return {
            valid: false,
            error: `Target IPv6 ${cleanIp} is in protected local/link-local address space and cannot be blocked`
          };
        }
      }

      // Check if target is agent's own reported IP (if passed in target_data)
      if (target_data && typeof target_data === 'object' && target_data.agent_ip) {
        if (cleanIp === String(target_data.agent_ip).trim()) {
          return {
            valid: false,
            error: `Target IP ${cleanIp} matches the agent's own network IP and cannot be blocked`
          };
        }
      }

      return { valid: true, target_ip: cleanIp };
    }

    // 2. Domain Validation
    if (isDomainCommand) {
      let rawDomain = null;
      if (typeof target_data === 'string') {
        rawDomain = target_data.trim();
      } else if (target_data && typeof target_data === 'object') {
        rawDomain = target_data.domain || target_data.target_domain || null;
      }

      if (!rawDomain || typeof rawDomain !== 'string' || !rawDomain.trim()) {
        return { valid: false, error: 'Target domain is required' };
      }

      let cleanDomain = rawDomain.trim().toLowerCase();

      // Disallow wildcards
      if (cleanDomain.includes('*')) {
        return { valid: false, error: 'Wildcard domains are not permitted in firewall rules' };
      }

      // Disallow protocol, port, path, spaces or invalid characters
      if (/[/\\:?#@\s]/.test(cleanDomain)) {
        return {
          valid: false,
          error: 'Invalid domain format: must not contain protocol, port, path, or whitespace'
        };
      }

      // Strip trailing dot if present
      if (cleanDomain.endsWith('.')) {
        cleanDomain = cleanDomain.slice(0, -1);
      }

      if (cleanDomain.length === 0 || cleanDomain.length > 253) {
        return { valid: false, error: 'Domain length must be between 1 and 253 characters' };
      }

      // Check regex pattern ^[a-z0-9.-]+$
      if (!/^[a-z0-9.-]+$/.test(cleanDomain)) {
        return { valid: false, error: `Invalid domain characters in: ${cleanDomain}` };
      }

      const labels = cleanDomain.split('.');
      if (labels.some((l) => !l || !DOMAIN_LABEL_REGEX.test(l))) {
        return { valid: false, error: `Invalid domain label structure in: ${cleanDomain}` };
      }

      // Check protected domain list
      for (const protDomain of protectedTargets.protected_domains) {
        const lowerProt = protDomain.toLowerCase();
        if (cleanDomain === lowerProt || cleanDomain.endsWith(`.${lowerProt}`)) {
          return {
            valid: false,
            error: `Target domain ${cleanDomain} matches protected domain (${protDomain}) and cannot be blocked`
          };
        }
      }

      return { valid: true, target_domain: cleanDomain };
    }

    return { valid: false, error: 'Unrecognized validation path' };
  },

  /**
   * Validates and records a new firewall rule in 'pending' status.
   *
   * @param {string} agent_id - Device UUID
   * @param {'block_ip'|'block_domain'} rule_type
   * @param {Object} target_data - { ip_address } or { domain }
   * @param {string|null} [created_by_id=null] - User UUID if initiated by admin
   * @returns {Promise<{ success: boolean, valid: boolean, rule_id?: string, status?: string, validation_result?: Object, error?: string, rule?: Object }>}
   */
  async createFirewallRule(agent_id, rule_type, target_data, created_by_id = null) {
    if (!agent_id || !UUID_REGEX.test(agent_id)) {
      return { success: false, valid: false, error: 'Valid agent_id UUID is required' };
    }

    if (!['block_ip', 'block_domain'].includes(rule_type)) {
      return { success: false, valid: false, error: "rule_type must be either 'block_ip' or 'block_domain'" };
    }

    // Verify agent exists and extract organization_id
    const deviceRes = await db.query(
      'SELECT id, organization_id, hostname FROM public.devices WHERE id = $1;',
      [agent_id]
    );

    if (!deviceRes.rows || deviceRes.rows.length === 0) {
      return { success: false, valid: false, error: `Agent device not found: ${agent_id}` };
    }

    const device = deviceRes.rows[0];
    const organization_id = device.organization_id;

    // Normalize target_data
    const enrichedTargetData = typeof target_data === 'object' && target_data !== null
      ? { ...target_data }
      : { target: target_data };

    // Perform strict validation
    const validation = this.validateFirewallInput(rule_type, enrichedTargetData);
    if (!validation.valid) {
      return {
        success: false,
        valid: false,
        status: 'rejected',
        error: validation.error,
        validation_result: validation
      };
    }

    try {
      const target_ip = validation.target_ip || null;
      const target_domain = validation.target_domain || null;

      const rule = await FirewallRule.create({
        agent_id,
        organization_id,
        rule_type,
        target_ip,
        target_domain,
        status: 'pending',
        created_by_id,
        result: {
          validation: 'passed',
          initiated_at: new Date().toISOString()
        }
      });

      // Audit log: firewall_rule_created
      await auditService.log({
        organization_id,
        user_id: created_by_id,
        actor_type: created_by_id ? 'admin' : 'system_policy',
        action: AUDIT_ACTIONS.FIREWALL_RULE_CREATED,
        resource_type: 'firewall_rule',
        resource_id: rule.id,
        details: {
          rule_type,
          target: target_ip || target_domain,
          status: rule.status,
          agent_id
        }
      });

      return {
        success: true,
        valid: true,
        rule_id: rule.id,
        status: rule.status,
        validation_result: validation,
        rule
      };
    } catch (err) {
      console.error('[firewallService.createFirewallRule Error]', err.message);
      return {
        success: false,
        valid: true,
        error: `Failed to create firewall rule: ${err.message}`
      };
    }
  },

  /**
   * Retrieves paginated list of firewall rules scoped to an organization.
   *
   * @param {string} organization_id
   * @param {Object} [filters={}]
   * @returns {Promise<{ total: number, limit: number, offset: number, rules: Array<Object> }>}
   */
  async listFirewallRules(organization_id, filters = {}) {
    if (!organization_id || !UUID_REGEX.test(organization_id)) {
      throw new Error('Valid organization_id UUID is required to list firewall rules');
    }

    const { agent_id, status, rule_type, limit = 50, offset = 0 } = filters;
    const parsedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
    const parsedOffset = Math.max(0, parseInt(offset, 10) || 0);

    return await FirewallRule.findByOrg(organization_id, {
      agent_id: agent_id && UUID_REGEX.test(agent_id) ? agent_id : undefined,
      status: status ? String(status).trim() : undefined,
      rule_type: rule_type ? String(rule_type).trim() : undefined,
      limit: parsedLimit,
      offset: parsedOffset
    });
  },

  /**
   * Initiates revocation of a firewall rule by marking it 'pending_delete'.
   *
   * @param {string} rule_id
   * @param {string} organization_id
   * @param {string|null} [deleted_by_id=null]
   * @returns {Promise<{ success: boolean, deleted: boolean, rule_id?: string, notFound?: boolean, error?: string }>}
   */
  async deleteFirewallRule(rule_id, organization_id, deleted_by_id = null) {
    if (!rule_id || !UUID_REGEX.test(rule_id)) {
      return { success: false, deleted: false, error: 'Valid rule_id UUID is required' };
    }
    if (!organization_id || !UUID_REGEX.test(organization_id)) {
      return { success: false, deleted: false, error: 'Valid organization_id UUID is required' };
    }

    const existing = await FirewallRule.findById(rule_id, organization_id);
    if (!existing) {
      return { success: false, deleted: false, notFound: true, error: 'Firewall rule not found' };
    }

    const updated = await FirewallRule.updateStatus(
      rule_id,
      organization_id,
      'pending_delete',
      new Date().toISOString()
    );

    if (!updated) {
      return { success: false, deleted: false, error: 'Failed to update rule status' };
    }

    // Audit log: firewall_rule_deleted
    await auditService.log({
      organization_id,
      user_id: deleted_by_id,
      actor_type: deleted_by_id ? 'admin' : 'system_policy',
      action: AUDIT_ACTIONS.FIREWALL_RULE_DELETED,
      resource_type: 'firewall_rule',
      resource_id: rule_id,
      details: {
        rule_type: existing.rule_type,
        target: existing.target_ip || existing.target_domain,
        previous_status: existing.status,
        status: 'pending_delete',
        agent_id: existing.agent_id
      }
    });

    return {
      success: true,
      deleted: true,
      rule_id
    };
  }
};

module.exports = firewallService;
