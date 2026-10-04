const db = require('../config/db');
const Incident = require('../models/Incident');
const IncidentEvidence = require('../models/IncidentEvidence');
const DDoSAlert = require('../models/DDoSAlert');
const { persistDetectionIncident } = require('./incidentService');
const { log: auditLog } = require('./auditService');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUUID = (val) => typeof val === 'string' && UUID_REGEX.test(val);

const VALID_METRIC_TYPES = new Set(['request_spike', 'post_flood', 'login_abuse', 'ip_flooding']);

/**
 * DDoS Detection Service (rule-based, no ML).
 * Detects request spikes, POST floods, login abuse, and IP flooding based on historical windows.
 */
const ddosDetectionService = {
  /**
   * Detects request spikes per IP within the last N minutes.
   * Default threshold: >500 requests per IP in 5 minutes (configurable via DDOS_REQUEST_SPIKE_THRESHOLD).
   *
   * @param {string|null} org_id - Target organization UUID
   * @param {number} [window_minutes=5] - Time window in minutes
   * @returns {Promise<Array<{ source_ip: string, count: number, threshold_exceeded: boolean }>>}
   */
  async detectRequestSpike(org_id, window_minutes = 5) {
    try {
      const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
      const threshold = parseInt(process.env.DDOS_REQUEST_SPIKE_THRESHOLD, 10) || 500;
      const validOrgId = isUUID(org_id) ? org_id : null;

      // 1. Query audit_logs
      const auditQuery = `
        SELECT ip_address AS source_ip, COUNT(*)::INT AS count
        FROM public.audit_logs
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND ip_address IS NOT NULL
        GROUP BY ip_address;
      `;
      const auditRes = await db.query(auditQuery, [validOrgId, windowMinutes]);

      // 2. Query ddos_metrics for recorded request spikes
      const metricsQuery = `
        SELECT source_ip, SUM(count)::INT AS count
        FROM public.ddos_metrics
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND metric_type = 'request_spike'
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND source_ip IS NOT NULL
        GROUP BY source_ip;
      `;
      const metricsRes = await db.query(metricsQuery, [validOrgId, windowMinutes]);

      const ipMap = new Map();
      for (const row of auditRes.rows) {
        if (!row.source_ip) continue;
        ipMap.set(row.source_ip, (ipMap.get(row.source_ip) || 0) + Number(row.count));
      }
      for (const row of metricsRes.rows) {
        if (!row.source_ip) continue;
        ipMap.set(row.source_ip, (ipMap.get(row.source_ip) || 0) + Number(row.count));
      }

      const results = [];
      const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
      const windowEnd = new Date();

      for (const [source_ip, count] of ipMap.entries()) {
        const threshold_exceeded = count > threshold;
        const item = {
          source_ip,
          count,
          threshold_exceeded
        };
        results.push(item);

        // Store metric entry for trending / audit if threshold exceeded and auto-create incident
        if (threshold_exceeded && validOrgId) {
          try {
            const inc = await this.createDDoSIncident(validOrgId, 'request_spike', source_ip, {
              count,
              window_minutes: windowMinutes,
              threshold
            });
            item.incident_id = inc?.id || inc;
          } catch (e) {
            console.warn('[detectRequestSpike auto-create incident note]', e.message);
          }
        }
      }

      return results;
    } catch (err) {
      console.error('[ddosDetectionService.detectRequestSpike Error]', err.message);
      return [];
    }
  },

  /**
   * Detects POST floods to a specific endpoint per IP.
   * Default threshold: >100 POST requests to same endpoint per IP in 5 minutes (configurable via DDOS_POST_FLOOD_THRESHOLD).
   *
   * @param {string|null} org_id - Target organization UUID
   * @param {string} [endpoint=null] - Specific endpoint path (e.g. '/api/v1/auth/login')
   * @param {number} [window_minutes=5] - Time window in minutes
   * @returns {Promise<Array<{ source_ip: string, count: number, endpoint: string }>>}
   */
  async detectPostFlood(org_id, endpoint = null, window_minutes = 5) {
    try {
      const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
      const threshold = parseInt(process.env.DDOS_POST_FLOOD_THRESHOLD, 10) || 100;
      const validOrgId = isUUID(org_id) ? org_id : null;
      const targetEndpoint = endpoint ? String(endpoint).trim() : null;

      // 1. Query audit_logs for POST requests
      const auditQuery = `
        SELECT ip_address AS source_ip,
               COALESCE(details->>'endpoint', details->>'path', resource_type, 'unknown') AS ep,
               COUNT(*)::INT AS count
        FROM public.audit_logs
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND created_at >= NOW() - ($3 || ' minutes')::INTERVAL
          AND ip_address IS NOT NULL
          AND (
            details->>'method' ILIKE 'POST'
            OR action ILIKE '%POST%'
            OR action ILIKE '%create%'
          )
          AND (
            $2::TEXT IS NULL
            OR details->>'endpoint' = $2::TEXT
            OR details->>'path' = $2::TEXT
            OR resource_type = $2::TEXT
            OR resource_id = $2::TEXT
          )
        GROUP BY ip_address, ep;
      `;
      const auditRes = await db.query(auditQuery, [validOrgId, targetEndpoint, windowMinutes]);

      // 2. Query ddos_metrics for recorded post_flood entries
      const metricsQuery = `
        SELECT source_ip,
               COALESCE(endpoint, 'unknown') AS ep,
               SUM(count)::INT AS count
        FROM public.ddos_metrics
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND metric_type = 'post_flood'
          AND ($2::TEXT IS NULL OR endpoint = $2::TEXT)
          AND created_at >= NOW() - ($3 || ' minutes')::INTERVAL
          AND source_ip IS NOT NULL
        GROUP BY source_ip, ep;
      `;
      const metricsRes = await db.query(metricsQuery, [validOrgId, targetEndpoint, windowMinutes]);

      const keyMap = new Map();
      for (const row of auditRes.rows) {
        if (!row.source_ip) continue;
        const key = `${row.source_ip}||${row.ep}`;
        keyMap.set(key, (keyMap.get(key) || 0) + Number(row.count));
      }
      for (const row of metricsRes.rows) {
        if (!row.source_ip) continue;
        const key = `${row.source_ip}||${row.ep}`;
        keyMap.set(key, (keyMap.get(key) || 0) + Number(row.count));
      }

      const results = [];
      const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
      const windowEnd = new Date();

      for (const [key, count] of keyMap.entries()) {
        const [source_ip, ep] = key.split('||');
        if (count > threshold) {
          const matchedEndpoint = targetEndpoint || ep;
          const item = {
            source_ip,
            count,
            endpoint: matchedEndpoint,
            threshold_exceeded: true
          };
          results.push(item);

          if (validOrgId) {
            try {
              const inc = await this.createDDoSIncident(validOrgId, 'post_flood', source_ip, {
                count,
                endpoint: matchedEndpoint,
                window_minutes: windowMinutes,
                threshold
              });
              item.incident_id = inc?.id || inc;
            } catch (e) {
              console.warn('[detectPostFlood auto-create incident note]', e.message);
            }
          }
        }
      }

      return results;
    } catch (err) {
      console.error('[ddosDetectionService.detectPostFlood Error]', err.message);
      return [];
    }
  },

  /**
   * Detects login abuse (failed login attempts per IP).
   * Default threshold: >10 failed attempts per IP in 15 minutes (configurable via DDOS_LOGIN_ABUSE_THRESHOLD).
   *
   * @param {string|null} org_id - Target organization UUID
   * @param {number} [window_minutes=15] - Time window in minutes
   * @returns {Promise<Array<{ source_ip: string, count: number, failed_attempts: number }>>}
   */
  async detectLoginAbuse(org_id, window_minutes = 15) {
    try {
      const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 15);
      const threshold = parseInt(process.env.DDOS_LOGIN_ABUSE_THRESHOLD, 10) || 10;
      const validOrgId = isUUID(org_id) ? org_id : null;

      // 1. Query login_events
      const loginEventsQuery = `
        SELECT l.ip_address AS source_ip,
               COALESCE(SUM(GREATEST(l.failed_attempt_count, 1)), 0)::INT AS failed_attempts,
               COUNT(*)::INT AS count
        FROM public.login_events l
        LEFT JOIN public.users u ON l.user_id = u.id
        WHERE ($1::UUID IS NULL OR u.organization_id = $1::UUID)
          AND (l.success = false OR l.failed_attempt_count > 0)
          AND l.created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND l.ip_address IS NOT NULL
        GROUP BY l.ip_address;
      `;
      const loginRes = await db.query(loginEventsQuery, [validOrgId, windowMinutes]);

      // 2. Query audit_logs for login failure actions
      const auditQuery = `
        SELECT ip_address AS source_ip,
               COUNT(*)::INT AS failed_attempts,
               COUNT(*)::INT AS count
        FROM public.audit_logs
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND ip_address IS NOT NULL
          AND (
            action ILIKE '%login%fail%'
            OR action ILIKE '%auth%fail%'
            OR action ILIKE '%failed%login%'
            OR (details->>'status' IN ('failed', 'failure', '401', '403') AND action ILIKE '%login%')
          )
        GROUP BY ip_address;
      `;
      const auditRes = await db.query(auditQuery, [validOrgId, windowMinutes]);

      // 3. Query ddos_metrics for recorded login_abuse entries
      const metricsQuery = `
        SELECT source_ip,
               SUM(count)::INT AS failed_attempts,
               SUM(count)::INT AS count
        FROM public.ddos_metrics
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND metric_type = 'login_abuse'
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND source_ip IS NOT NULL
        GROUP BY source_ip;
      `;
      const metricsRes = await db.query(metricsQuery, [validOrgId, windowMinutes]);

      const ipMap = new Map();
      const addData = (ip, count, failed) => {
        if (!ip) return;
        const existing = ipMap.get(ip) || { count: 0, failed_attempts: 0 };
        existing.count += count;
        existing.failed_attempts += failed;
        ipMap.set(ip, existing);
      };

      for (const row of loginRes.rows) {
        addData(row.source_ip, Number(row.count), Number(row.failed_attempts));
      }
      for (const row of auditRes.rows) {
        addData(row.source_ip, Number(row.count), Number(row.failed_attempts));
      }
      for (const row of metricsRes.rows) {
        addData(row.source_ip, Number(row.count), Number(row.failed_attempts));
      }

      const results = [];
      const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
      const windowEnd = new Date();

      for (const [source_ip, data] of ipMap.entries()) {
        if (data.failed_attempts > threshold) {
          const item = {
            source_ip,
            count: data.count,
            failed_attempts: data.failed_attempts,
            threshold_exceeded: true
          };
          results.push(item);

          if (validOrgId) {
            try {
              const inc = await this.createDDoSIncident(validOrgId, 'login_abuse', source_ip, {
                count: data.failed_attempts,
                failed_attempts: data.failed_attempts,
                endpoint: '/api/v1/auth/login',
                window_minutes: windowMinutes,
                threshold
              });
              item.incident_id = inc?.id || inc;
            } catch (e) {
              console.warn('[detectLoginAbuse auto-create incident note]', e.message);
            }
          }
        }
      }

      return results;
    } catch (err) {
      console.error('[ddosDetectionService.detectLoginAbuse Error]', err.message);
      return [];
    }
  },

  /**
   * Detects IP flooding (>20 requests from same IP in <5min across multiple endpoints / geolocations).
   * Simplified: checks request variance and volume.
   * Default threshold: >20 requests per IP in 5 minutes (configurable via DDOS_IP_FLOOD_THRESHOLD).
   *
   * @param {string|null} org_id - Target organization UUID
   * @param {number} [window_minutes=5] - Time window in minutes
   * @returns {Promise<Array<{ source_ip: string, unique_endpoints: number, request_count: number }>>}
   */
  async detectIPFlooding(org_id, window_minutes = 5) {
    try {
      const windowMinutes = Math.max(1, parseInt(window_minutes, 10) || 5);
      const threshold = parseInt(process.env.DDOS_IP_FLOOD_THRESHOLD, 10) || 20;
      const validOrgId = isUUID(org_id) ? org_id : null;

      // 1. Query audit_logs
      const auditQuery = `
        SELECT ip_address AS source_ip,
               COUNT(DISTINCT COALESCE(details->>'endpoint', details->>'path', resource_type, 'default'))::INT AS unique_endpoints,
               COUNT(*)::INT AS request_count
        FROM public.audit_logs
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND ip_address IS NOT NULL
        GROUP BY ip_address;
      `;
      const auditRes = await db.query(auditQuery, [validOrgId, windowMinutes]);

      // 2. Query ddos_metrics
      const metricsQuery = `
        SELECT source_ip,
               COUNT(DISTINCT COALESCE(endpoint, 'default'))::INT AS unique_endpoints,
               SUM(count)::INT AS request_count
        FROM public.ddos_metrics
        WHERE ($1::UUID IS NULL OR organization_id = $1::UUID)
          AND metric_type = 'ip_flooding'
          AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
          AND source_ip IS NOT NULL
        GROUP BY source_ip;
      `;
      const metricsRes = await db.query(metricsQuery, [validOrgId, windowMinutes]);

      const ipMap = new Map();
      for (const row of auditRes.rows) {
        if (!row.source_ip) continue;
        const existing = ipMap.get(row.source_ip) || { unique_endpoints: 0, request_count: 0 };
        existing.unique_endpoints = Math.max(existing.unique_endpoints, Number(row.unique_endpoints));
        existing.request_count += Number(row.request_count);
        ipMap.set(row.source_ip, existing);
      }
      for (const row of metricsRes.rows) {
        if (!row.source_ip) continue;
        const existing = ipMap.get(row.source_ip) || { unique_endpoints: 0, request_count: 0 };
        existing.unique_endpoints = Math.max(existing.unique_endpoints, Number(row.unique_endpoints));
        existing.request_count += Number(row.request_count);
        ipMap.set(row.source_ip, existing);
      }

      const results = [];
      const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
      const windowEnd = new Date();

      for (const [source_ip, data] of ipMap.entries()) {
        if (data.request_count > threshold) {
          const item = {
            source_ip,
            unique_endpoints: Math.max(1, data.unique_endpoints),
            request_count: data.request_count,
            count: data.request_count,
            threshold_exceeded: true
          };
          results.push(item);

          if (validOrgId) {
            try {
              const inc = await this.createDDoSIncident(validOrgId, 'ip_flooding', source_ip, {
                count: data.request_count,
                request_count: data.request_count,
                unique_endpoints: data.unique_endpoints,
                window_minutes: windowMinutes,
                threshold
              });
              item.incident_id = inc?.id || inc;
            } catch (e) {
              console.warn('[detectIPFlooding auto-create incident note]', e.message);
            }
          }
        }
      }

      return results;
    } catch (err) {
      console.error('[ddosDetectionService.detectIPFlooding Error]', err.message);
      return [];
    }
  },

  /**
   * Generates a critical DDoS incident and records incident evidence.
   * Signature supports both:
   *   createDDoSIncident(metric_type, source_ip, details)
   *   createDDoSIncident(org_id, metric_type, source_ip, details)
   *
   * @param {...*} args
   * @returns {Promise<string>} incident_id
   */
  async createDDoSIncident(...args) {
    let org_id = null;
    let metric_type = 'request_spike';
    let source_ip = 'unknown';
    let details = {};

    if (args.length >= 4) {
      [org_id, metric_type, source_ip, details = {}] = args;
    } else if (args.length === 3) {
      if (isUUID(args[0]) && !VALID_METRIC_TYPES.has(args[0])) {
        [org_id, metric_type, source_ip] = args;
      } else {
        [metric_type, source_ip, details = {}] = args;
        org_id = details?.organization_id || details?.org_id || null;
      }
    } else if (args.length === 2) {
      [metric_type, source_ip] = args;
    }

    if (!VALID_METRIC_TYPES.has(metric_type)) {
      metric_type = 'request_spike';
    }

    const resolvedOrgId = isUUID(org_id) ? org_id : null;
    const count = Number(details?.count || details?.request_count || details?.failed_attempts || 1);
    const targetSourceIp = source_ip || details?.source_ip || details?.ip_address || 'unknown';

    // 0. Deduplication Check: Query incidents table for an existing OPEN DDoS incident
    // Match: organization_id, threat_type='ddos', source_ip within last 15 minutes
    try {
      const existingQuery = `
        SELECT i.*
        FROM public.incidents i
        WHERE ($1::UUID IS NULL OR i.organization_id = $1::UUID)
          AND i.threat_type = 'ddos'
          AND i.status = 'open'
          AND i.created_at >= NOW() - INTERVAL '15 minutes'
          AND (
            i.explanation ILIKE ('%' || $2::TEXT || '%')
            OR EXISTS (
              SELECT 1 FROM public.incident_evidence e
              WHERE e.incident_id = i.id
                AND (
                  e.metadata->>'source_ip' = $2::TEXT
                  OR e.metadata->>'ip_address' = $2::TEXT
                )
            )
          )
        ORDER BY i.created_at DESC
        LIMIT 1;
      `;

      const existingRes = await db.query(existingQuery, [resolvedOrgId, targetSourceIp]);
      if (existingRes && existingRes.rows && existingRes.rows.length > 0) {
        const existingIncident = existingRes.rows[0];
        console.log('[DDoS] Reusing existing incident', existingIncident.id);
        if (existingIncident && typeof existingIncident === 'object') {
          existingIncident.toString = () => existingIncident.id;
        }
        return existingIncident;
      }
    } catch (dedupErr) {
      console.warn('[ddosDetectionService.createDDoSIncident Deduplication Check Note]', dedupErr.message);
    }

    // 1. Call incidentService to fully initialize incident and trigger policy engine
    const incident = await persistDetectionIncident({
      user: {
        id: details?.user_id || null,
        organization_id: resolvedOrgId,
        role: details?.user_role || 'admin'
      },
      threatType: 'ddos',
      sourceType: 'ddos_detection',
      mlResult: {
        risk_level: 'critical',
        risk_score: 95,
        explanation: details?.explanation || `Automated DDoS detection: ${metric_type} pattern identified from IP ${source_ip}.`,
        signals: [
          {
            signal_name: metric_type,
            signal_value: count,
            weight: 0.9
          }
        ],
        details: {
          metric_type,
          source_ip,
          ip_address: source_ip,
          count,
          endpoint: details?.endpoint || null,
          target_device_id: details?.target_device_id || details?.device_id || null,
          ...details
        },
        confidence: 95
      },
      recommendedActions: details?.recommended_actions || ['block_ip', 'notify_admin']
    });

    // 2. Store metric details in incident_evidence
    try {
      await IncidentEvidence.create({
        incident_id: incident.id,
        evidence_type: 'ddos_metrics',
        raw_payload: {
          metric_type,
          source_ip,
          threshold_exceeded: true,
          count,
          endpoint: details?.endpoint || null,
          ...details
        }
      });
    } catch (evErr) {
      console.warn('[ddosDetectionService.createDDoSIncident Evidence Recording Note]', evErr.message);
    }

    // 3. Store metric for audit + trending in ddos_metrics
    try {
      await DDoSAlert.create({
        organization_id: resolvedOrgId,
        metric_type,
        source_ip,
        endpoint: details?.endpoint || null,
        count,
        window_start: details?.window_start || new Date(Date.now() - 5 * 60 * 1000),
        window_end: details?.window_end || new Date(),
        threshold_exceeded: true,
        metadata: {
          incident_id: incident.id,
          ...details
        }
      });
    } catch (e) {
      console.warn('[ddosDetectionService.createDDoSIncident Metric Recording Note]', e.message);
    }

    // 4. Log ddos_incident_created to audit_logs
    try {
      await auditLog({
        organization_id: resolvedOrgId,
        user_id: details?.user_id || null,
        actor_type: 'system_guard',
        action: 'ddos_incident_created',
        resource_type: 'incident',
        resource_id: incident.id,
        details: {
          metric_type,
          source_ip,
          count,
          endpoint: details?.endpoint || null,
          incident_id: incident.id,
          threat_type: 'ddos',
          risk_score: 95
        },
        ip_address: source_ip
      });
    } catch (auditErr) {
      console.warn('[ddosDetectionService.createDDoSIncident Audit Log Note]', auditErr.message);
    }

    // Provide toString for backward compatibility where caller expects string incident ID
    if (incident && typeof incident === 'object') {
      incident.toString = () => incident.id;
    }

    return incident;
  },

  /**
   * Helper to manually record a request metric for testing and stream ingestion.
   */
  async recordMetric({
    organization_id = null,
    metric_type = 'request_spike',
    source_ip,
    endpoint = null,
    count = 1,
    window_start = null,
    window_end = null,
    threshold_exceeded = false,
    metadata = {}
  }) {
    return DDoSAlert.create({
      organization_id: isUUID(organization_id) ? organization_id : null,
      metric_type,
      source_ip,
      endpoint,
      count,
      window_start,
      window_end,
      threshold_exceeded,
      metadata
    });
  }
};

ddosDetectionService.default = ddosDetectionService;
module.exports = ddosDetectionService;
