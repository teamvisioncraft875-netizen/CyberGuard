const crypto = require('crypto');
const db = require('../config/db');
const { persistDetectionIncident, resolveIncident } = require('./incidentService');
const { log: auditLog } = require('./auditService');
const MitreMapping = require('../models/MitreMapping');
const PolicyEngine = require('./PolicyEngine');

/**
 * CYBERGUARD Attack Surface Discovery (ASD) Phase B Service
 * 
 * Capabilities:
 * 1. Exposure Classification Engine (Rule-based, explainable, deterministic)
 * 2. Risk Scoring Engine (Formula with Exposure Multiplier, Asset Multiplier, Duration Modifier)
 * 3. Exposure Storage & Deduplication (public.attack_surface_exposures)
 * 4. Incident Orchestration & Advisory-Lock Deduplication (15m window, zero duplicates)
 * 5. Automated Exposure & Incident Mitigation / Resolution
 * 6. Fleet Overview Analytics & Scan Command Dispatch
 */

// Canonical Detection Rules
const DETECTION_RULES = Object.freeze({
  // Critical
  'EXP-CRIT-RDP': {
    rule_id: 'EXP-CRIT-RDP',
    severity: 'critical',
    risk_score: 95,
    title: 'Public Remote Desktop (RDP) Exposed',
    description: 'Microsoft Remote Desktop Protocol service is publicly accessible from the internet.',
    remediation: 'Disable direct RDP access. Require secure VPN connection and multi-factor authentication (MFA).'
  },
  'EXP-CRIT-REDIS': {
    rule_id: 'EXP-CRIT-REDIS',
    severity: 'critical',
    risk_score: 95,
    title: 'Public Redis Instance',
    description: 'Redis in-memory database is exposed without network perimeter protection.',
    remediation: 'Bind Redis to 127.0.0.1 or internal private network. Configure strong requirepass authentication.'
  },
  'EXP-CRIT-POSTGRES': {
    rule_id: 'EXP-CRIT-POSTGRES',
    severity: 'critical',
    risk_score: 90,
    title: 'Public PostgreSQL Database',
    description: 'PostgreSQL database server port is accessible on public interfaces.',
    remediation: 'Restrict listen_addresses to private interfaces or localhost in postgresql.conf and enforce pg_hba.conf CIDR ACLs.'
  },
  'EXP-CRIT-MYSQL': {
    rule_id: 'EXP-CRIT-MYSQL',
    severity: 'critical',
    risk_score: 90,
    title: 'Public MySQL Database',
    description: 'MySQL database server port is publicly accessible.',
    remediation: 'Set bind-address = 127.0.0.1 in my.cnf and block port 3306 on external host firewalls.'
  },
  'EXP-CRIT-MONGO': {
    rule_id: 'EXP-CRIT-MONGO',
    severity: 'critical',
    risk_score: 90,
    title: 'Public MongoDB Instance',
    description: 'MongoDB document database port is reachable on public interfaces.',
    remediation: 'Bind to internal localhost/private IP and enable security.authorization in mongod.conf.'
  },
  'EXP-CRIT-MSSQL': {
    rule_id: 'EXP-CRIT-MSSQL',
    severity: 'critical',
    risk_score: 90,
    title: 'Public Microsoft SQL Server',
    description: 'Microsoft SQL Server TDS port is accessible on external network interfaces.',
    remediation: 'Disable remote external TCP/IP connections in SQL Server Configuration Manager and enforce firewall isolation.'
  },

  // High
  'EXP-HIGH-SSH': {
    rule_id: 'EXP-HIGH-SSH',
    severity: 'high',
    risk_score: 80,
    title: 'Public SSH Service Exposed',
    description: 'SSH remote management daemon is publicly reachable.',
    remediation: 'Disable password authentication (PasswordAuthentication no), enforce public key auth, and restrict via VPN or IP allowlist.'
  },
  'EXP-HIGH-ELASTIC': {
    rule_id: 'EXP-HIGH-ELASTIC',
    severity: 'high',
    risk_score: 75,
    title: 'Public Elasticsearch Cluster',
    description: 'Elasticsearch REST API port is publicly accessible.',
    remediation: 'Enable X-Pack security, require authentication, and bind network.host to private or loopback IP.'
  },
  'EXP-HIGH-KIBANA': {
    rule_id: 'EXP-HIGH-KIBANA',
    severity: 'high',
    risk_score: 75,
    title: 'Public Kibana Dashboard',
    description: 'Kibana web dashboard is exposed to the public internet.',
    remediation: 'Place Kibana behind a reverse proxy with corporate SSO authentication or restrict to private VPN.'
  },
  'EXP-HIGH-ADMIN': {
    rule_id: 'EXP-HIGH-ADMIN',
    severity: 'high',
    risk_score: 75,
    title: 'Public Admin Panel Exposed',
    description: 'Web administration interface or management console is exposed on a public socket.',
    remediation: 'Restrict administrative consoles to internal management subnets or dedicated bastion hosts.'
  },

  // Medium
  'EXP-MED-HTTP': {
    rule_id: 'EXP-MED-HTTP',
    severity: 'medium',
    risk_score: 55,
    title: 'Public HTTP Service',
    description: 'Standard web application or HTTP server port is exposed on public interfaces.',
    remediation: 'Ensure web application is patched, running with minimal privileges, and protected by Web Application Firewall (WAF) and TLS.'
  },
  'EXP-MED-DEBUG': {
    rule_id: 'EXP-MED-DEBUG',
    severity: 'medium',
    risk_score: 50,
    title: 'Remote Debugging Port Exposed',
    description: 'Language runtime remote debugger port (JVM, Node.js, Python debugpy) is exposed.',
    remediation: 'Immediately terminate remote debugging on production interfaces. Bind debuggers strictly to 127.0.0.1.'
  },

  // Informational
  'EXP-INFO-LOOPBACK': {
    rule_id: 'EXP-INFO-LOOPBACK',
    severity: 'info',
    risk_score: 0,
    title: 'Loopback Service',
    description: 'Service listening strictly on internal host loopback interface.',
    remediation: 'No remediation required.'
  }
});

// Admin panel port catalog and signature tokens
const ADMIN_PORTS = new Set([8080, 8443, 9000, 9090, 10000]);
const ADMIN_PROCESS_REGEX = /admin|webmin|cockpit|phpmyadmin|cpanel|whm/i;

// Debugger port catalog
const DEBUG_PORTS = new Set([5005, 5678, 9229]);

// Standard web service ports and process names
const HTTP_PORTS = new Set([80, 443, 8000, 8081]);
const HTTP_PROCESS_REGEX = /nginx|httpd|apache|caddy|lighttpd|envoy|traefik/i;

/**
 * Maps an organization, device, and exposure tuple to a signed 64-bit BigInt string
 * for PostgreSQL transaction-scoped advisory locks.
 */
function getAdvisoryLockKey(orgId, devId, port, proto, ruleId) {
  const hash = crypto.createHash('sha256')
    .update(`${orgId}:${devId}:${port}:${proto}:${ruleId}`)
    .digest('hex')
    .slice(0, 15);
  let intVal = BigInt('0x' + hash);
  const maxSigned = 9223372036854775807n;
  if (intVal > maxSigned) {
    intVal = intVal - 18446744073709551616n;
  }
  return intVal.toString();
}

const attackSurfaceService = {
  DETECTION_RULES,

  /**
   * PART 1 & 2: Exposure Classification Engine
   * Evaluates exact rule matching based on port, protocol, bind address, and exposure scope.
   */
  classifyExposure(portRecord) {
    if (!portRecord || typeof portRecord !== 'object') {
      return null;
    }

    const port = parseInt(portRecord.port, 10);
    const scope = String(portRecord.exposure_scope || 'unknown').toLowerCase().trim();
    const bindAddr = String(portRecord.bind_address || '').trim().toLowerCase();
    const procName = String(portRecord.process_name || '').trim().toLowerCase();
    const proto = String(portRecord.protocol || 'tcp').toLowerCase().trim();

    // Check for loopback-only binding (127.0.0.0/8, ::1, localhost) (MED-03)
    if (scope === 'loopback' || bindAddr === '127.0.0.1' || bindAddr.startsWith('127.') || bindAddr === '::1' || bindAddr === 'localhost') {
      return { ...DETECTION_RULES['EXP-INFO-LOOPBACK'] };
    }

    // Critical Rules (TCP only) (MED-05)
    if (proto === 'tcp') {
      if (port === 3389) return { ...DETECTION_RULES['EXP-CRIT-RDP'] };
      if (port === 6379) return { ...DETECTION_RULES['EXP-CRIT-REDIS'] };
      if (port === 5432) return { ...DETECTION_RULES['EXP-CRIT-POSTGRES'] };
      if (port === 3306) return { ...DETECTION_RULES['EXP-CRIT-MYSQL'] };
      if (port === 27017) return { ...DETECTION_RULES['EXP-CRIT-MONGO'] };
      if (port === 1433) return { ...DETECTION_RULES['EXP-CRIT-MSSQL'] };

      // High Rules
      if (port === 22) return { ...DETECTION_RULES['EXP-HIGH-SSH'] };
      if (port === 9200) return { ...DETECTION_RULES['EXP-HIGH-ELASTIC'] };
      if (port === 5601) return { ...DETECTION_RULES['EXP-HIGH-KIBANA'] };
    }

    // Debugger Ports (Medium)
    if (DEBUG_PORTS.has(port)) {
      return { ...DETECTION_RULES['EXP-MED-DEBUG'] };
    }

    // Admin Panels (High)
    if (ADMIN_PORTS.has(port) || ADMIN_PROCESS_REGEX.test(procName)) {
      return { ...DETECTION_RULES['EXP-HIGH-ADMIN'] };
    }

    // HTTP Services (Medium)
    if (HTTP_PORTS.has(port) || HTTP_PROCESS_REGEX.test(procName)) {
      return { ...DETECTION_RULES['EXP-MED-HTTP'] };
    }

    // Generic exposed service on public interface
    if (scope === 'public') {
      return {
        rule_id: 'EXP-MED-GENERIC',
        severity: 'medium',
        risk_score: 50,
        title: `Public Service Exposed on Port ${port}`,
        description: `Unidentified network service listening on port ${port} is exposed on public interface.`,
        remediation: 'Inspect process listening on port and restrict external binding if not required.'
      };
    }

    return null;
  },

  /**
   * PART 3: Risk Scoring Engine
   * Final Score = (Base Score × Exposure Multiplier × Asset Multiplier) + Duration Modifier
   */
  calculateRiskScore({
    baseScore,
    exposureScope = 'public',
    assetType = 'workstation',
    firstSeenAt = null,
    now = new Date()
  }) {
    const rawBase = Number(baseScore ?? 0);
    if (isNaN(rawBase) || rawBase <= 0) {
      return 0;
    }

    // 1. Exposure Multiplier
    const scope = String(exposureScope).toLowerCase().trim();
    let exposureMult = 0.6; // default private / internal
    if (scope === 'public') {
      exposureMult = 1.0;
    } else if (scope === 'loopback') {
      return 0; // Loopback always yields score 0
    }

    // 2. Asset Multiplier (HIGH-05 fix operator precedence & prioritize dev)
    const normAsset = String(assetType).toLowerCase().trim();
    let assetMult = 1.00;
    if (normAsset.includes('dev') || normAsset.includes('test')) {
      assetMult = 0.80;
    } else if ((normAsset.includes('prod') && normAsset.includes('db')) || normAsset.includes('production_database')) {
      assetMult = 1.25;
    } else if (normAsset.includes('server') || normAsset.includes('app')) {
      assetMult = 1.10;
    } else if (normAsset.includes('workstation') || normAsset.includes('desktop') || normAsset.includes('laptop') || normAsset.includes('client')) {
      assetMult = 1.00;
    }

    // 3. Duration Modifier
    let durationMod = 0;
    if (firstSeenAt) {
      const firstSeenTime = new Date(firstSeenAt).getTime();
      const nowTime = new Date(now).getTime();
      const diffHours = (nowTime - firstSeenTime) / (1000 * 60 * 60);

      if (diffHours >= 168) {
        // Open > 7 days
        durationMod = 15;
      } else if (diffHours >= 24) {
        // Open > 24 hours
        durationMod = 5;
      }
    }

    const calculated = (rawBase * exposureMult * assetMult) + durationMod;
    const finalScore = Math.min(100, Math.max(0, Math.round(calculated)));
    return finalScore;
  },

  /**
   * PART 5 & 6: Incident Orchestration & Advisory-Lock Deduplication
   * Ensures exactly one open incident per (organization_id, device_id, port, protocol, rule_id)
   * within a 15-minute window. Prevents duplicate incidents, MITRE mappings, and policy proposals.
   */
  async orchestrateIncident({
    organization_id,
    device_id,
    port,
    classification,
    calculatedScore,
    assetInfo = {}
  }) {
    const normPort = parseInt(port.port, 10);
    const normProto = String(port.protocol || 'tcp').toLowerCase().trim();
    const lockKey = getAdvisoryLockKey(
      organization_id,
      device_id,
      normPort,
      normProto,
      classification.rule_id
    );

    let incidentResult = null;
    let isReused = false;

    // Execute atomic creation under transaction-scoped advisory lock
    await db.transaction(async (txClient) => {
      // 1. Try to acquire transaction-scoped PostgreSQL advisory lock (non-blocking - CRIT-02)
      const lockRes = await txClient.query('SELECT pg_try_advisory_xact_lock($1) AS acquired;', [lockKey]);
      const acquired = Boolean(lockRes.rows[0]?.acquired);

      // 2. Open incident deduplication query (CRIT-01: 1 exposure = 1 incident as long as status='open')
      const dedupeQuery = `
        SELECT i.*
        FROM public.incidents i
        WHERE i.organization_id = $1
          AND i.threat_type = 'attack_surface_exposure'
          AND i.status = 'open'
          AND (
            EXISTS (
              SELECT 1 FROM public.attack_surface_exposures e
              WHERE e.incident_id = i.id
                AND e.device_id = $2
                AND e.rule_id = $3
            )
            OR EXISTS (
              SELECT 1 FROM public.detection_signals s
              WHERE s.incident_id = i.id
                AND s.signal_name = 'public_exposed_service'
                AND s.signal_value = $4
            )
          )
        ORDER BY i.created_at DESC
        LIMIT 1;
      `;

      if (!acquired) {
        // Concurrency contender: another worker acquired the advisory lock.
        // Wait briefly for the lock-holding transaction to commit, then reuse the incident
        await new Promise((r) => setTimeout(r, 100));
        const contendedRes = await txClient.query(dedupeQuery, [
          organization_id,
          device_id,
          classification.rule_id,
          String(normPort)
        ]);
        if (contendedRes.rows.length > 0) {
          incidentResult = contendedRes.rows[0];
          isReused = true;
        }
        return;
      }

      const existingRes = await txClient.query(dedupeQuery, [
        organization_id,
        device_id,
        classification.rule_id,
        String(normPort)
      ]);

      if (existingRes.rows.length > 0) {
        // Reuse existing open incident without creating duplicates (CRIT-01)
        incidentResult = existingRes.rows[0];
        isReused = true;
        return;
      }

      // 3. Create fresh incident row inside transaction
      const riskLevel = calculatedScore >= 90 ? 'critical' : 'high';
      const incRes = await txClient.query(
        `INSERT INTO public.incidents (
           organization_id,
           threat_type,
           source_type,
           risk_level,
           risk_score,
           explanation,
           status
         )
         VALUES ($1, 'attack_surface_exposure', 'attack_surface', $2, $3, $4, 'open')
         RETURNING *;`,
        [
          organization_id,
          riskLevel,
          calculatedScore,
          `${classification.title}: Discovered exposed port ${normPort}/${normProto} on host ${assetInfo.hostname || device_id}. Risk score: ${calculatedScore}.`
        ]
      );
      incidentResult = incRes.rows[0];

      // Insert MITRE mapping using existing MITRE infrastructure
      const mitreTechnique = MitreMapping.getTechniqueForAttackSurface(classification.rule_id);
      await txClient.query(
        `INSERT INTO public.mitre_mappings (incident_id, technique_id, technique_name)
         VALUES ($1, $2, $3);`,
        [incidentResult.id, mitreTechnique.technique_id, mitreTechnique.technique_name]
      );

      // Insert detection signals
      await txClient.query(
        `INSERT INTO public.detection_signals (incident_id, signal_name, signal_value, weight)
         VALUES ($1, 'public_exposed_service', $2, 0.95);`,
        [incidentResult.id, String(normPort)]
      );

      // Insert recommended actions
      for (const act of ['notify_admin', 'block_port']) {
        await txClient.query(
          `INSERT INTO public.recommended_actions (incident_id, action_type, action_status)
           VALUES ($1, $2, 'pending');`,
          [incidentResult.id, act]
        );
      }

      // Link exposure row if port.id exists
      if (port.id) {
        await txClient.query(
          `UPDATE public.attack_surface_exposures
           SET incident_id = $1
           WHERE device_id = $2 AND port_id = $3 AND rule_id = $4 AND status = 'active';`,
          [incidentResult.id, device_id, port.id, classification.rule_id]
        );
      }
    });

    // 4. Policy Engine Evaluation (Phase 1B: SHADOW MODE)
    // Run after transaction commit so incident row is guaranteed visible across all connections
    if (!isReused && incidentResult) {
      try {
        await PolicyEngine.evaluateAndProposeActions({
          ...incidentResult,
          signals: {
            public_exposed_service: normPort
          },
          details: {
            port: normPort,
            protocol: normProto,
            bind_address: port.bind_address || '0.0.0.0',
            process_name: port.process_name || null,
            rule_id: classification.rule_id,
            device_id
          },
          target: {
            port: normPort,
            protocol: normProto,
            device_id
          },
          analysis_confidence: 100
        });
      } catch (policyErr) {
        console.error('[PolicyEngine Background Evaluation Error]', policyErr.message);
      }
    }

    return {
      incident: incidentResult,
      isReused
    };
  },

  /**
   * PART 4, 5, 9: Ingestion Pipeline Hook
   * Processes active and closed ports from a snapshot:
   * 1. Auto-resolves exposures & incidents for closed ports.
   * 2. Classifies and stores active exposures.
   * 3. Orchestrates incidents and policies for exposures with risk_score >= 70.
   */
  async processAttackSurfaceTelemetry({
    organization_id,
    device_id,
    currentPorts = [],
    closedPorts = []
  }) {
    if (!organization_id || !device_id) return null;

    // Fetch device asset metadata for multiplier calculation
    const devRes = await db.query(
      `SELECT id, organization_id, hostname, platform, os, user_id FROM public.devices WHERE id = $1;`,
      [device_id]
    );
    const device = devRes.rows[0] || {};
    const assetType = device.platform || 'workstation';

    // -------------------------------------------------------------------------
    // PART 9: AUTO-RESOLUTION of Closed Ports
    // -------------------------------------------------------------------------
    if (Array.isArray(closedPorts) && closedPorts.length > 0) {
      for (const closedPort of closedPorts) {
        if (!closedPort || !closedPort.id) continue;

        // Mark active exposure as mitigated
        const mitRes = await db.query(
          `UPDATE public.attack_surface_exposures
           SET status = 'mitigated', mitigated_at = NOW(), last_seen_at = NOW()
           WHERE port_id = $1 AND status = 'active'
           RETURNING *;`,
          [closedPort.id]
        );

        for (const exp of mitRes.rows) {
          // Resolve linked incident
          if (exp.incident_id) {
            await resolveIncident(exp.incident_id);
          }

          // Record audit log entry
          await auditLog({
            organization_id,
            actor_type: 'system_policy',
            action: 'attack_surface_exposure_resolved',
            resource_type: 'device',
            resource_id: device_id,
            details: {
              exposure_id: exp.id,
              rule_id: exp.rule_id,
              port: closedPort.port,
              incident_id: exp.incident_id
            }
          });
        }
      }
    }

    // -------------------------------------------------------------------------
    // PART 4 & 5: Active Ports Classification, Storage & Incident Generation
    // -------------------------------------------------------------------------
    if (!Array.isArray(currentPorts) || currentPorts.length === 0) {
      return { exposures_processed: 0 };
    }

    // Retrieve the DB rows for the active ports to obtain their UUID port_id and first_seen_at
    const dbPortsRes = await db.query(
      `SELECT id, port, protocol, bind_address, exposure_scope, first_seen_at, last_seen_at
       FROM public.device_listening_ports
       WHERE device_id = $1 AND status = 'open';`,
      [device_id]
    );
    const portMap = new Map();
    for (const row of dbPortsRes.rows) {
      const key = `${row.port}:${row.protocol}:${row.bind_address}`;
      portMap.set(key, row);
    }

    let processedCount = 0;

    for (const p of currentPorts) {
      if (!p || !p.port) continue;
      const key = `${p.port}:${p.protocol || 'tcp'}:${p.bind_address || '0.0.0.0'}`;
      const dbPort = portMap.get(key);
      if (!dbPort) continue;

      const classification = this.classifyExposure(p);
      if (!classification || classification.severity === 'info' || classification.risk_score === 0) {
        continue; // Loopback or informational: inventory only, no exposure record
      }

      const finalScore = this.calculateRiskScore({
        baseScore: classification.risk_score,
        exposureScope: p.exposure_scope || dbPort.exposure_scope,
        assetType,
        firstSeenAt: dbPort.first_seen_at
      });

      // Check if an existing exposure record already exists (active or previously mitigated)
      // Anti-flapping (CRIT-04): reactivate existing record to preserve first_seen_at & exposure history
      const existingExpRes = await db.query(
        `SELECT * FROM public.attack_surface_exposures
         WHERE device_id = $1 AND rule_id = $2 AND port_id = $3
         ORDER BY CASE WHEN status = 'active' THEN 1 WHEN status = 'grace_period' THEN 2 ELSE 3 END, last_seen_at DESC
         LIMIT 1;`,
        [device_id, classification.rule_id, dbPort.id]
      );

      let exposureRecord = null;
      if (existingExpRes.rows.length > 0) {
        // Reappearance / Reactivation / Update last_seen_at (CRIT-04 Anti-Flapping: preserve original first_seen_at and id)
        const updateRes = await db.query(
          `UPDATE public.attack_surface_exposures
           SET status = 'active',
               mitigated_at = NULL,
               grace_period_started_at = NULL,
               last_seen_at = NOW(),
               risk_score = $1,
               title = $2,
               remediation = $3
           WHERE id = $4
           RETURNING *;`,
          [finalScore, classification.title, classification.remediation, existingExpRes.rows[0].id]
        );
        exposureRecord = updateRes.rows[0];
      } else {
        // Create new active exposure record
        const insertRes = await db.query(
          `INSERT INTO public.attack_surface_exposures (
             organization_id,
             device_id,
             port_id,
             rule_id,
             severity,
             risk_score,
             title,
             description,
             remediation,
             status,
             first_seen_at,
             last_seen_at,
             metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', NOW(), NOW(), $10)
           RETURNING *;`,
          [
            organization_id,
            device_id,
            dbPort.id,
            classification.rule_id,
            classification.severity,
            finalScore,
            classification.title,
            classification.description,
            classification.remediation,
            JSON.stringify({
              port: p.port,
              protocol: p.protocol || 'tcp',
              bind_address: p.bind_address || '0.0.0.0',
              process_name: p.process_name || null
            })
          ]
        );
        exposureRecord = insertRes.rows[0];
      }

      // If risk score >= 70, trigger incident orchestration (Part 5)
      if (finalScore >= 70 && exposureRecord) {
        try {
          const { incident } = await this.orchestrateIncident({
            organization_id,
            device_id,
            port: p,
            classification,
            calculatedScore: finalScore,
            assetInfo: device
          });

          if (incident && incident.id && exposureRecord.incident_id !== incident.id) {
            await db.query(
              `UPDATE public.attack_surface_exposures SET incident_id = $1 WHERE id = $2;`,
              [incident.id, exposureRecord.id]
            );
          }
        } catch (incErr) {
          console.warn('[attackSurfaceService.processAttackSurfaceTelemetry Incident Note]', incErr.message);
        }
      }

      processedCount++;
    }

    return { exposures_processed: processedCount };
  },

  /**
   * PART 10: Admin APIs
   */

  /**
   * Lists organization exposures with optional filters.
   */
  async getExposures({ organization_id, severity, status = 'active', device_id, limit = 50, offset = 0 }) {
    if (!organization_id) throw new Error('organization_id is required');

    let query = `
      SELECT e.*, d.hostname, d.os, d.platform, p.port, p.protocol, p.bind_address, p.exposure_scope
      FROM public.attack_surface_exposures e
      JOIN public.devices d ON e.device_id = d.id
      JOIN public.device_listening_ports p ON e.port_id = p.id
      WHERE e.organization_id = $1
    `;
    const params = [organization_id];
    let idx = 2;

    if (severity) {
      query += ` AND e.severity = $${idx++}`;
      params.push(String(severity).toLowerCase());
    }

    if (status && status !== 'all') {
      query += ` AND e.status = $${idx++}`;
      params.push(String(status).toLowerCase());
    }

    if (device_id) {
      query += ` AND e.device_id = $${idx++}`;
      params.push(device_id);
    }

    // Get total count
    const countRes = await db.query(
      `SELECT COUNT(*) as total FROM (${query}) AS sub;`,
      params
    );
    const total = parseInt(countRes.rows[0]?.total || 0, 10);

    // Enforce safe pagination boundaries (MED-02)
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

    query += ` ORDER BY e.risk_score DESC, e.last_seen_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
    params.push(safeLimit, safeOffset);

    const rowsRes = await db.query(query, params);

    return {
      total,
      items: rowsRes.rows
    };
  },

  /**
   * Computes organization fleet overview metrics.
   */
  async getOverview({ organization_id }) {
    if (!organization_id) throw new Error('organization_id is required');

    // 1. Critical & High active exposures count
    const exposureCountsRes = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
         COUNT(*) FILTER (WHERE severity = 'high') as high_count,
         COALESCE(AVG(risk_score), 0) as avg_risk_score,
         COALESCE(MAX(risk_score), 0) as max_risk_score
       FROM public.attack_surface_exposures
       WHERE organization_id = $1 AND status = 'active';`,
      [organization_id]
    );
    const expRow = exposureCountsRes.rows[0] || {};
    const criticalExposures = parseInt(expRow.critical_count || 0, 10);
    const highExposures = parseInt(expRow.high_count || 0, 10);

    // Fleet risk score: average risk score of active exposures (or 0 if none)
    const fleetRiskScore = Math.round(parseFloat(expRow.avg_risk_score || 0));

    // 2. Count of distinct public services across the org
    const publicServicesRes = await db.query(
      `SELECT COUNT(DISTINCT (device_id, port, protocol)) as public_count
       FROM public.device_listening_ports
       WHERE organization_id = $1 AND exposure_scope = 'public' AND status = 'open';`,
      [organization_id]
    );
    const publicServices = parseInt(publicServicesRes.rows[0]?.public_count || 0, 10);

    return {
      critical_exposures: criticalExposures,
      high_exposures: highExposures,
      fleet_risk_score: fleetRiskScore,
      public_services: publicServices
    };
  },

  /**
   * PART 11: SOC Dashboard (Phase C)
   * Returns comprehensive dashboard metrics for the attack surface SOC view.
   * Includes exposure summary cards, risk distribution, category breakdown, top risky assets.
   */
  async getDashboard({ organization_id }) {
    if (!organization_id) throw new Error('organization_id is required');

    // 1. Exposure summary counts (all statuses)
    const summaryRes = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE status = 'active')                             AS total_active,
         COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical')   AS critical_active,
         COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high')       AS high_active,
         COUNT(*) FILTER (WHERE status = 'active' AND severity = 'medium')     AS medium_active,
         COUNT(*) FILTER (WHERE status = 'active' AND severity = 'low')        AS low_active,
         COUNT(*) FILTER (WHERE status = 'mitigated')                          AS total_mitigated,
         COUNT(DISTINCT device_id) FILTER (WHERE status = 'active')            AS devices_with_exposures
       FROM public.attack_surface_exposures
       WHERE organization_id = $1;`,
      [organization_id]
    );
    const summary = summaryRes.rows[0] || {};

    // 2. Open incidents count linked to attack surface exposures
    const openIncRes = await db.query(
      `SELECT COUNT(*) AS open_incidents
       FROM public.incidents
       WHERE organization_id = $1
         AND threat_type = 'attack_surface_exposure'
         AND status = 'open';`,
      [organization_id]
    );
    const openIncidents = parseInt(openIncRes.rows[0]?.open_incidents || 0, 10);

    // 3. Risk distribution by score bands (active only)
    const riskDistRes = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE risk_score >= 90)             AS critical_band,
         COUNT(*) FILTER (WHERE risk_score >= 70 AND risk_score < 90) AS high_band,
         COUNT(*) FILTER (WHERE risk_score >= 40 AND risk_score < 70) AS medium_band,
         COUNT(*) FILTER (WHERE risk_score  < 40)             AS low_band
       FROM public.attack_surface_exposures
       WHERE organization_id = $1 AND status = 'active';`,
      [organization_id]
    );
    const riskDist = riskDistRes.rows[0] || {};

    // 4. Exposure category breakdown (active only)
    const catRes = await db.query(
      `SELECT rule_id, COUNT(*) AS cnt
       FROM public.attack_surface_exposures
       WHERE organization_id = $1 AND status = 'active'
       GROUP BY rule_id
       ORDER BY cnt DESC;`,
      [organization_id]
    );

    const RULE_CATEGORIES = {
      'EXP-CRIT-RDP': 'RDP Exposure',
      'EXP-CRIT-REDIS': 'Redis Exposure',
      'EXP-CRIT-POSTGRES': 'PostgreSQL Exposure',
      'EXP-HIGH-SSH': 'SSH Exposure',
      'EXP-HIGH-ADMIN': 'Admin Interface Exposure',
      'EXP-MED-PUBLIC': 'Public Service Exposure',
      'EXP-LOW-GENERIC': 'Generic Exposure',
    };

    const categoryBreakdown = catRes.rows.map(r => ({
      rule_id: r.rule_id,
      category: RULE_CATEGORIES[r.rule_id] || r.rule_id,
      count: parseInt(r.cnt, 10)
    }));

    // 5. Top 10 risky assets (devices with exposures, sorted by max risk)
    const topAssetsRes = await db.query(
      `SELECT
         e.device_id,
         d.hostname,
         d.platform,
         COUNT(*) AS exposure_count,
         MAX(e.risk_score) AS max_risk_score,
         COUNT(i.id) FILTER (WHERE i.status = 'open') AS open_incidents
       FROM public.attack_surface_exposures e
       JOIN public.devices d ON d.id = e.device_id
       LEFT JOIN public.incidents i ON i.id = e.incident_id
       WHERE e.organization_id = $1 AND e.status = 'active'
       GROUP BY e.device_id, d.hostname, d.platform
       ORDER BY max_risk_score DESC, exposure_count DESC
       LIMIT 10;`,
      [organization_id]
    );
    const topRiskyAssets = topAssetsRes.rows.map(r => ({
      device_id: r.device_id,
      hostname: r.hostname || r.device_id,
      platform: r.platform,
      exposure_count: parseInt(r.exposure_count, 10),
      max_risk_score: parseInt(r.max_risk_score, 10),
      open_incidents: parseInt(r.open_incidents, 10)
    }));

    return {
      summary: {
        total_active: parseInt(summary.total_active || 0, 10),
        critical_active: parseInt(summary.critical_active || 0, 10),
        high_active: parseInt(summary.high_active || 0, 10),
        medium_active: parseInt(summary.medium_active || 0, 10),
        low_active: parseInt(summary.low_active || 0, 10),
        total_mitigated: parseInt(summary.total_mitigated || 0, 10),
        devices_with_exposures: parseInt(summary.devices_with_exposures || 0, 10),
        open_incidents: openIncidents
      },
      risk_distribution: {
        critical: parseInt(riskDist.critical_band || 0, 10),
        high: parseInt(riskDist.high_band || 0, 10),
        medium: parseInt(riskDist.medium_band || 0, 10),
        low: parseInt(riskDist.low_band || 0, 10)
      },
      category_breakdown: categoryBreakdown,
      top_risky_assets: topRiskyAssets
    };
  },

  /**
   * PART 12: Exposure Detail (Phase C)
   * Returns a single exposure with full port metadata, MITRE mappings, and linked incident.
   * Enforces tenant isolation via organization_id.
   */
  async getExposureById({ organization_id, exposure_id }) {
    if (!organization_id) throw new Error('organization_id is required');
    if (!exposure_id) throw new Error('exposure_id is required');

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(exposure_id)) return null;

    // Main exposure + device + port join (one query, no N+1)
    const expRes = await db.query(
      `SELECT
         e.*,
         d.hostname,
         d.os,
         d.platform,
         p.port,
         p.protocol,
         p.bind_address,
         p.exposure_scope,
         p.process_name,
         p.first_seen_at AS port_first_seen_at
       FROM public.attack_surface_exposures e
       JOIN public.devices d ON d.id = e.device_id
       JOIN public.device_listening_ports p ON p.id = e.port_id
       WHERE e.id = $1 AND e.organization_id = $2;`,
      [exposure_id, organization_id]
    );

    if (expRes.rows.length === 0) return null;
    const exp = expRes.rows[0];

    // MITRE mappings for linked incident
    let mitreMappings = [];
    if (exp.incident_id) {
      const mitreRes = await db.query(
        `SELECT technique_id, technique_name
         FROM public.mitre_mappings
         WHERE incident_id = $1;`,
        [exp.incident_id]
      );
      mitreMappings = mitreRes.rows;
    }

    // Linked incident summary
    let incidentSummary = null;
    if (exp.incident_id) {
      const incRes = await db.query(
        `SELECT id, status, risk_level, risk_score, explanation, created_at, resolved_at
         FROM public.incidents
         WHERE id = $1 AND organization_id = $2;`,
        [exp.incident_id, organization_id]
      );
      if (incRes.rows.length > 0) {
        incidentSummary = incRes.rows[0];
      }
    }

    const rule = DETECTION_RULES[exp.rule_id] || {};

    return {
      id: exp.id,
      organization_id: exp.organization_id,
      device_id: exp.device_id,
      hostname: exp.hostname,
      os: exp.os,
      platform: exp.platform,
      port: exp.port,
      protocol: exp.protocol,
      bind_address: exp.bind_address,
      exposure_scope: exp.exposure_scope,
      process_name: exp.process_name,
      rule_id: exp.rule_id,
      severity: exp.severity,
      risk_score: exp.risk_score,
      status: exp.status,
      title: exp.title || rule.title,
      description: rule.description || null,
      remediation: exp.remediation || rule.remediation,
      first_seen_at: exp.first_seen_at,
      last_seen_at: exp.last_seen_at,
      mitigated_at: exp.mitigated_at,
      created_at: exp.created_at,
      incident_id: exp.incident_id,
      incident: incidentSummary,
      mitre_mappings: mitreMappings,
      metadata: exp.metadata || null
    };
  },

  /**
   * PART 13: Exposure Analytics (Phase C)
   * Returns time-series trend data for dashboard charts over the last 30 days.
   */
  async getAnalytics({ organization_id, days = 30 }) {
    if (!organization_id) throw new Error('organization_id is required');

    const safeDays = Math.min(Math.max(parseInt(days, 10) || 30, 1), 90);

    // Daily active exposure counts for the last N days
    const exposureTrendRes = await db.query(
      `SELECT
         gs.day::date AS date,
         COUNT(e.id) AS active_count
       FROM generate_series(
         NOW() - ($2 || ' days')::interval,
         NOW(),
         '1 day'::interval
       ) AS gs(day)
       LEFT JOIN public.attack_surface_exposures e
         ON e.organization_id = $1
         AND e.first_seen_at <= gs.day + INTERVAL '1 day'
         AND (e.mitigated_at IS NULL OR e.mitigated_at > gs.day)
       GROUP BY gs.day
       ORDER BY gs.day ASC;`,
      [organization_id, safeDays]
    );

    // Daily incident counts (attack surface)
    const incidentTrendRes = await db.query(
      `SELECT
         gs.day::date AS date,
         COUNT(i.id) AS incident_count
       FROM generate_series(
         NOW() - ($2 || ' days')::interval,
         NOW(),
         '1 day'::interval
       ) AS gs(day)
       LEFT JOIN public.incidents i
         ON i.organization_id = $1
         AND i.threat_type = 'attack_surface_exposure'
         AND DATE(i.created_at) = gs.day::date
       GROUP BY gs.day
       ORDER BY gs.day ASC;`,
      [organization_id, safeDays]
    );

    // Daily mitigated exposure counts
    const mitigationTrendRes = await db.query(
      `SELECT
         gs.day::date AS date,
         COUNT(e.id) AS mitigated_count
       FROM generate_series(
         NOW() - ($2 || ' days')::interval,
         NOW(),
         '1 day'::interval
       ) AS gs(day)
       LEFT JOIN public.attack_surface_exposures e
         ON e.organization_id = $1
         AND DATE(e.mitigated_at) = gs.day::date
       GROUP BY gs.day
       ORDER BY gs.day ASC;`,
      [organization_id, safeDays]
    );

    // Category breakdown (active exposures, for pie chart)
    const categoryRes = await db.query(
      `SELECT rule_id, COUNT(*) AS count
       FROM public.attack_surface_exposures
       WHERE organization_id = $1 AND status = 'active'
       GROUP BY rule_id
       ORDER BY count DESC;`,
      [organization_id]
    );

    // Summary aggregates
    const aggRes = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE status = 'active')    AS total_active,
         COUNT(*) FILTER (WHERE status = 'mitigated') AS total_mitigated,
         COALESCE(AVG(risk_score) FILTER (WHERE status = 'active'), 0) AS avg_risk_score,
         COALESCE(AVG(
           EXTRACT(EPOCH FROM (mitigated_at - first_seen_at)) / 3600.0
         ) FILTER (WHERE status = 'mitigated' AND mitigated_at IS NOT NULL), 0) AS avg_time_to_remediate_hours
       FROM public.attack_surface_exposures
       WHERE organization_id = $1;`,
      [organization_id]
    );
    const agg = aggRes.rows[0] || {};

    return {
      period_days: safeDays,
      summary: {
        total_active: parseInt(agg.total_active || 0, 10),
        total_mitigated: parseInt(agg.total_mitigated || 0, 10),
        avg_risk_score: Math.round(parseFloat(agg.avg_risk_score || 0)),
        avg_time_to_remediate_hours: Math.round(parseFloat(agg.avg_time_to_remediate_hours || 0))
      },
      exposure_trend: exposureTrendRes.rows.map(r => ({
        date: r.date,
        active_count: parseInt(r.active_count || 0, 10)
      })),
      incident_trend: incidentTrendRes.rows.map(r => ({
        date: r.date,
        incident_count: parseInt(r.incident_count || 0, 10)
      })),
      mitigation_trend: mitigationTrendRes.rows.map(r => ({
        date: r.date,
        mitigated_count: parseInt(r.mitigated_count || 0, 10)
      })),
      category_breakdown: categoryRes.rows.map(r => ({
        rule_id: r.rule_id,
        label: DETECTION_RULES[r.rule_id]?.title || r.rule_id,
        count: parseInt(r.count, 10)
      }))
    };
  },

  /**
   * PART 14: Fleet Scan History (Phase C)
   * Returns paginated agent_commands of type scan_attack_surface for the organization.
   */
  async getScanHistory({ organization_id, device_id = null, limit = 25, offset = 0 }) {
    if (!organization_id) throw new Error('organization_id is required');

    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 25, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

    const params = [organization_id];
    let filter = '';
    let idx = 2;

    if (device_id) {
      filter += ` AND c.device_id = $${idx++}`;
      params.push(device_id);
    }

    const countRes = await db.query(
      `SELECT COUNT(*) AS total
       FROM public.agent_commands c
       WHERE c.organization_id = $1
         AND c.command_type = 'scan_attack_surface'${filter};`,
      params
    );
    const total = parseInt(countRes.rows[0]?.total || 0, 10);

    params.push(safeLimit, safeOffset);
    const rowsRes = await db.query(
      `SELECT
         c.id,
         c.device_id,
         d.hostname,
         c.status,
         c.command_type,
         c.requested_by_id,
         u.email AS requested_by_email,
         c.created_at,
         c.executed_at
       FROM public.agent_commands c
       JOIN public.devices d ON d.id = c.device_id
       LEFT JOIN public.users u ON u.id = c.requested_by_id
       WHERE c.organization_id = $1
         AND c.command_type = 'scan_attack_surface'${filter}
       ORDER BY c.created_at DESC
       LIMIT $${idx++} OFFSET $${idx++};`,
      params
    );

    return {
      total,
      limit: safeLimit,
      offset: safeOffset,
      scans: rowsRes.rows.map(r => ({
        id: r.id,
        device_id: r.device_id,
        hostname: r.hostname || r.device_id,
        status: r.status,
        requested_by_id: r.requested_by_id,
        requested_by_email: r.requested_by_email || null,
        initiated_at: r.created_at,
        completed_at: r.executed_at || null
      }))
    };
  },

  /**
   * Queues a scan_attack_surface command for device(s).
   * Supports single device or atomic set-based fleet dispatch (HIGH-02).
   */
  async queueScan({ organization_id, device_id = null, requested_by_id = null }) {
    if (!organization_id) throw new Error('organization_id is required');

    let validUserId = null;
    if (requested_by_id) {
      try {
        const uRes = await db.query(`SELECT id FROM public.users WHERE id = $1;`, [requested_by_id]);
        if (uRes.rows.length > 0) {
          validUserId = requested_by_id;
        }
      } catch (_) {
        validUserId = null;
      }
    }

    let queuedCommands = [];
    if (device_id) {
      const devRes = await db.query(
        `SELECT id FROM public.devices WHERE id = $1 AND organization_id = $2;`,
        [device_id, organization_id]
      );
      if (devRes.rows.length === 0) {
        throw new Error('Device not found or not in organization');
      }
      const cmdRes = await db.query(
        `INSERT INTO public.agent_commands (
           organization_id,
           device_id,
           command_type,
           target_data,
           status,
           requested_by_id
         )
         VALUES ($1, $2, 'scan_attack_surface', '{}'::jsonb, 'pending', $3)
         RETURNING *;`,
        [organization_id, device_id, validUserId]
      );
      queuedCommands = cmdRes.rows;
    } else {
      // Atomic set-based query for fleet scan (HIGH-02)
      const fleetRes = await db.query(
        `INSERT INTO public.agent_commands (
           organization_id,
           device_id,
           command_type,
           target_data,
           status,
           requested_by_id
         )
         SELECT $1, id, 'scan_attack_surface', '{}'::jsonb, 'pending', $2
         FROM public.devices
         WHERE organization_id = $1
         RETURNING *;`,
        [organization_id, validUserId]
      );
      queuedCommands = fleetRes.rows;
    }

    return {
      status: 'queued',
      command_type: 'scan_attack_surface',
      commands: queuedCommands
    };
  }
};

module.exports = attackSurfaceService;
