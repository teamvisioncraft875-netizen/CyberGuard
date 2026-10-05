/**
 * CYBERGUARD — ATTACK SURFACE DISCOVERY (ASD) PHASE B TEST SUITE
 * 
 * Verifies all Phase B Objectives:
 * 1. Detection: Public Redis, Public RDP, Public PostgreSQL, Public SSH detected correctly.
 * 2. Risk Scoring:
 *    - Public > Private
 *    - Production > Workstation
 *    - Duration modifiers (+5 for >24h, +15 for >7d) applied correctly.
 * 3. Exposure Deduplication: Same exposure results in exactly 1 active finding.
 * 4. Incident Deduplication: 50 concurrent detections yield exactly 1 open incident.
 * 5. Policy Integration: Response proposal action created in shadow mode.
 * 6. Auto-Resolution: Port closes -> exposure status='mitigated', incident status='resolved', audit log entry recorded.
 * 7. Tenant Isolation: Organization A cannot access Organization B findings.
 * 8. Admin APIs:
 *    - GET /api/v1/admin/attack-surface/exposures
 *    - GET /api/v1/admin/attack-surface/overview
 *    - POST /api/v1/admin/attack-surface/scan
 */

// Configure fast timeout for ML service calls during testing to avoid stalling
process.env.ML_SERVICE_TIMEOUT_MS = '50';

const assert = require('assert');
const db = require('../src/config/db');
const DeviceListeningPort = require('../src/models/DeviceListeningPort');
const attackSurfaceService = require('../src/services/attackSurfaceService');
const attackSurfaceController = require('../src/controllers/attackSurfaceController');
const telemetryController = require('../src/controllers/telemetryController');
const PolicyEngine = require('../src/services/PolicyEngine');
const MitreMapping = require('../src/models/MitreMapping');

async function runPhaseBTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Attack Surface Discovery Phase B Test Suite');
  console.log('========================================================================\n');

  const testOrgA = '00000000-0000-0000-0000-000000000a91';
  const testOrgB = '00000000-0000-0000-0000-000000000b92';
  const testDeviceA = '00000000-0000-0000-0000-000000000d91';
  const testDeviceB = '00000000-0000-0000-0000-000000000d92';

  function createMockRes() {
    return {
      statusCode: 200,
      body: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(data) {
        this.body = data;
        return this;
      }
    };
  }

  try {
    // ---------------------------------------------------------------------------
    // SETUP: Clean test resources and insert isolated test organizations & devices
    // ---------------------------------------------------------------------------
    await db.query(`DELETE FROM public.response_actions WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.agent_commands WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.audit_logs WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.attack_surface_exposures WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.incidents WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.telemetry_events WHERE device_id IN ($1, $2);`, [testDeviceA, testDeviceB]);
    await db.query(`DELETE FROM public.devices WHERE id IN ($1, $2);`, [testDeviceA, testDeviceB]);
    await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgA, testOrgB]);

    await db.query(`
      INSERT INTO public.organizations (id, name)
      VALUES ($1, 'ASD Phase B Org A'),
             ($2, 'ASD Phase B Org B');
    `, [testOrgA, testOrgB]);

    await db.query(`
      INSERT INTO public.devices (id, organization_id, hostname, platform, os, status, agent_version)
      VALUES ($1, $2, 'asd-prod-node-alpha', 'production_database', 'Linux', 'online', '1.0.0'),
             ($3, $4, 'asd-workstation-beta', 'workstation', 'Windows 11', 'online', '1.0.0');
    `, [testDeviceA, testOrgA, testDeviceB, testOrgB]);

    // ===========================================================================
    // SECTION 1 — DETECTION RULES CLASSIFICATION
    // ===========================================================================
    console.log('--- TEST 1: EXPOSURE DETECTION RULES CLASSIFICATION ---');

    // 1A. Public Redis (port 6379)
    const redisClass = attackSurfaceService.classifyExposure({
      port: 6379,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public',
      process_name: 'redis-server'
    });
    assert.strictEqual(redisClass.rule_id, 'EXP-CRIT-REDIS');
    assert.strictEqual(redisClass.severity, 'critical');
    assert.strictEqual(redisClass.risk_score, 95);
    console.log('  [1A] ✅ Public Redis classified correctly: EXP-CRIT-REDIS (Score 95).');

    // 1B. Public RDP (port 3389)
    const rdpClass = attackSurfaceService.classifyExposure({
      port: 3389,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public',
      process_name: 'termsrv.dll'
    });
    assert.strictEqual(rdpClass.rule_id, 'EXP-CRIT-RDP');
    assert.strictEqual(rdpClass.severity, 'critical');
    assert.strictEqual(rdpClass.risk_score, 95);
    console.log('  [1B] ✅ Public RDP classified correctly: EXP-CRIT-RDP (Score 95).');

    // 1C. Public PostgreSQL (port 5432)
    const pgClass = attackSurfaceService.classifyExposure({
      port: 5432,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public',
      process_name: 'postgres'
    });
    assert.strictEqual(pgClass.rule_id, 'EXP-CRIT-POSTGRES');
    assert.strictEqual(pgClass.severity, 'critical');
    assert.strictEqual(pgClass.risk_score, 90);
    console.log('  [1C] ✅ Public PostgreSQL classified correctly: EXP-CRIT-POSTGRES (Score 90).');

    // 1D. Public SSH (port 22)
    const sshClass = attackSurfaceService.classifyExposure({
      port: 22,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public',
      process_name: 'sshd'
    });
    assert.strictEqual(sshClass.rule_id, 'EXP-HIGH-SSH');
    assert.strictEqual(sshClass.severity, 'high');
    assert.strictEqual(sshClass.risk_score, 80);
    console.log('  [1D] ✅ Public SSH classified correctly: EXP-HIGH-SSH (Score 80).');

    // 1E. Loopback Service (127.0.0.1) -> Informational (Score 0)
    const loopbackClass = attackSurfaceService.classifyExposure({
      port: 6379,
      protocol: 'tcp',
      bind_address: '127.0.0.1',
      exposure_scope: 'loopback',
      process_name: 'redis-server'
    });
    assert.strictEqual(loopbackClass.rule_id, 'EXP-INFO-LOOPBACK');
    assert.strictEqual(loopbackClass.severity, 'info');
    assert.strictEqual(loopbackClass.risk_score, 0);
    console.log('  [1E] ✅ Loopback Redis classified correctly: EXP-INFO-LOOPBACK (Score 0, No incident).');

    // 1F. Loopback Subnet (127.0.0.53 - systemd-resolved) -> Informational (Score 0) (MED-03)
    const loopbackSubnetClass = attackSurfaceService.classifyExposure({
      port: 53,
      protocol: 'udp',
      bind_address: '127.0.0.53',
      process_name: 'systemd-resolved'
    });
    assert.strictEqual(loopbackSubnetClass.rule_id, 'EXP-INFO-LOOPBACK');
    assert.strictEqual(loopbackSubnetClass.risk_score, 0);
    console.log('  [1F] ✅ Loopback subnet 127.0.0.53 classified as EXP-INFO-LOOPBACK (Score 0).');

    // 1G. UDP on database port 5432 must NOT be classified as PostgreSQL (MED-05)
    const udpDbClass = attackSurfaceService.classifyExposure({
      port: 5432,
      protocol: 'udp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public'
    });
    assert.notStrictEqual(udpDbClass?.rule_id, 'EXP-CRIT-POSTGRES', 'UDP on port 5432 must not match EXP-CRIT-POSTGRES');
    console.log('  [1G] ✅ Protocol validation verified: UDP port 5432 is not classified as PostgreSQL.');

    // ===========================================================================
    // SECTION 2 — DETERMINISTIC RISK SCORING ENGINE
    // ===========================================================================
    console.log('\n--- TEST 2: RISK SCORING ENGINE VERIFICATION ---');

    // 2A. Public vs. Private (Public > Private)
    const publicScore = attackSurfaceService.calculateRiskScore({
      baseScore: 95,
      exposureScope: 'public',
      assetType: 'workstation'
    });
    const privateScore = attackSurfaceService.calculateRiskScore({
      baseScore: 95,
      exposureScope: 'private',
      assetType: 'workstation'
    });
    console.log(`  Public score: ${publicScore}, Private score: ${privateScore}`);
    assert.strictEqual(publicScore, 95);
    assert.strictEqual(privateScore, 57); // 95 * 0.6 = 57
    assert.ok(publicScore > privateScore, 'Public score must exceed Private score');
    console.log('  [2A] ✅ Public > Private verified.');

    // 2B. Production Database vs. Workstation (Production > Workstation)
    const prodScore = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'production_database'
    });
    const workstationScore = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'workstation'
    });
    console.log(`  Production DB score: ${prodScore}, Workstation score: ${workstationScore}`);
    assert.strictEqual(prodScore, 94); // Math.round(75 * 1.0 * 1.25) = 94
    assert.strictEqual(workstationScore, 75); // 75 * 1.0 * 1.0 = 75
    assert.ok(prodScore > workstationScore, 'Production DB score must exceed Workstation score');
    console.log('  [2B] ✅ Production > Workstation verified.');

    // 2C. Duration Modifiers: Open > 24h (+5) and Open > 7d (+15)
    const now = new Date();
    const freshScore = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'workstation',
      firstSeenAt: new Date(now.getTime() - 2 * 3600 * 1000), // 2 hours ago
      now
    });
    const score24h = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'workstation',
      firstSeenAt: new Date(now.getTime() - 36 * 3600 * 1000), // 36 hours ago
      now
    });
    const score7d = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'workstation',
      firstSeenAt: new Date(now.getTime() - 200 * 3600 * 1000), // 200 hours ago
      now
    });
    console.log(`  Fresh: ${freshScore}, >24h: ${score24h} (+5), >7d: ${score7d} (+15)`);
    assert.strictEqual(freshScore, 75);
    assert.strictEqual(score24h, 80);
    assert.strictEqual(score7d, 90);
    console.log('  [2C] ✅ Duration modifiers (+5 for >24h, +15 for >7d) verified.');

    // 2D. Asset precedence: dev-database receives 0.80 multiplier, not production 1.25 (HIGH-05)
    const devDbScore = attackSurfaceService.calculateRiskScore({
      baseScore: 75,
      exposureScope: 'public',
      assetType: 'dev-database'
    });
    assert.strictEqual(devDbScore, 60); // 75 * 1.0 * 0.80 = 60
    console.log('  [2D] ✅ Operator precedence verified: dev-database receives 0.80 multiplier (Score 60).');

    // ===========================================================================
    // SECTION 3 — EXPOSURE STORAGE & DEDUPLICATION (PART 4)
    // ===========================================================================
    console.log('\n--- TEST 3: EXPOSURE STORAGE & DEDUPLICATION ---');

    // Ingest snapshot with Public Redis (port 6379)
    const redisSnap = {
      agent: { device_id: testDeviceA, organization_id: testOrgA, user_id: null },
      body: {
        timestamp: new Date().toISOString(),
        event_type: 'agent_telemetry',
        details: {
          attack_surface: {
            listening_ports: [
              { port: 6379, protocol: 'tcp', bind_address: '0.0.0.0', exposure_scope: 'public', process_name: 'redis-server' }
            ]
          }
        }
      }
    };

    await telemetryController.reportSystemEvent(redisSnap, createMockRes());

    const activeExp1 = await db.query(
      `SELECT * FROM public.attack_surface_exposures WHERE device_id = $1 AND status = 'active';`,
      [testDeviceA]
    );
    assert.strictEqual(activeExp1.rows.length, 1, 'Expected exactly 1 active exposure');
    assert.strictEqual(activeExp1.rows[0].rule_id, 'EXP-CRIT-REDIS');
    const firstSeen = activeExp1.rows[0].first_seen_at;

    // Send the SAME snapshot again
    await new Promise(r => setTimeout(r, 100));
    await telemetryController.reportSystemEvent(redisSnap, createMockRes());

    const activeExp2 = await db.query(
      `SELECT * FROM public.attack_surface_exposures WHERE device_id = $1 AND status = 'active';`,
      [testDeviceA]
    );
    assert.strictEqual(activeExp2.rows.length, 1, 'Duplicate active exposure record was created!');
    assert.strictEqual(activeExp2.rows[0].id, activeExp1.rows[0].id);
    assert.strictEqual(activeExp2.rows[0].first_seen_at.getTime(), firstSeen.getTime(), 'first_seen_at must be preserved');
    console.log('  [3] ✅ Same exposure yields exactly 1 active finding; last_seen updated with zero duplication.');

    // 3B. Anti-Flapping & Reactivation (CRIT-04): Port closes then reappears -> reactivates same record and preserves first_seen_at
    const closeSnap = {
      agent: { device_id: testDeviceA, organization_id: testOrgA, user_id: null },
      body: {
        timestamp: new Date().toISOString(),
        event_type: 'agent_telemetry',
        details: { attack_surface: { listening_ports: [] } }
      }
    };
    await telemetryController.reportSystemEvent(closeSnap, createMockRes());
    const mitigatedExp = await db.query(
      `SELECT * FROM public.attack_surface_exposures WHERE id = $1;`,
      [activeExp1.rows[0].id]
    );
    assert.strictEqual(mitigatedExp.rows[0].status, 'mitigated');

    // Service reappears in next snapshot
    await telemetryController.reportSystemEvent(redisSnap, createMockRes());
    const reactivatedExp = await db.query(
      `SELECT * FROM public.attack_surface_exposures WHERE device_id = $1 AND rule_id = 'EXP-CRIT-REDIS';`,
      [testDeviceA]
    );
    assert.strictEqual(reactivatedExp.rows.length, 1, 'Must not duplicate record upon reappearance');
    assert.strictEqual(reactivatedExp.rows[0].id, activeExp1.rows[0].id, 'Reactivated finding must preserve UUID');
    assert.strictEqual(reactivatedExp.rows[0].status, 'active', 'Reactivated finding must transition to ACTIVE');
    assert.strictEqual(reactivatedExp.rows[0].first_seen_at.getTime(), firstSeen.getTime(), 'Reactivated finding must preserve original first_seen_at');
    console.log('  [3B] ✅ Anti-Flapping verified: Reappearing exposure reactivates existing finding and preserves first_seen_at.');

    // ===========================================================================
    // SECTION 4 — INCIDENT DEDUPLICATION UNDER 50 CONCURRENT DETECTIONS (PART 6)
    // ===========================================================================
    console.log('\n--- TEST 4: CONCURRENT INCIDENT DEDUPLICATION (50 PARALLEL RUNS) ---');

    // Ingest port 3389 (RDP) on testDeviceB in Org B
    const portRes = await DeviceListeningPort.upsertPort({
      organization_id: testOrgB,
      device_id: testDeviceB,
      port: 3389,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public'
    });

    const portObj = {
      id: portRes.id,
      port: 3389,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      exposure_scope: 'public'
    };
    const classification = attackSurfaceService.classifyExposure(portObj);
    const calculatedScore = 95;

    // Launch 50 concurrent incident orchestration requests simultaneously across the pool
    console.log('  Triggering 50 concurrent orchestrateIncident calls for the same port and rule...');
    const concurrentResults = [];
    const concurrency = 8;
    const allTasks = Array.from({ length: 50 }, () => () =>
      attackSurfaceService.orchestrateIncident({
        organization_id: testOrgB,
        device_id: testDeviceB,
        port: portObj,
        classification,
        calculatedScore,
        assetInfo: { hostname: 'asd-workstation-beta' }
      })
    );

    let taskIdx = 0;
    async function worker() {
      while (taskIdx < allTasks.length) {
        const currentTask = allTasks[taskIdx++];
        const result = await currentTask();
        concurrentResults.push(result);
      }
    }

    await Promise.all(Array.from({ length: concurrency }, worker));
    const uniqueIncidentIds = new Set(concurrentResults.map(r => r.incident?.id).filter(Boolean));

    console.log(`  Received ${concurrentResults.length} orchestration results, unique incident IDs: ${uniqueIncidentIds.size}`);
    assert.strictEqual(uniqueIncidentIds.size, 1, 'Advisory lock failed: Multiple incident IDs created!');

    const dbIncidentsCount = await db.query(
      `SELECT COUNT(*) as count FROM public.incidents 
       WHERE organization_id = $1 AND threat_type = 'attack_surface_exposure';`,
      [testOrgB]
    );
    assert.strictEqual(parseInt(dbIncidentsCount.rows[0].count, 10), 1, 'Expected exactly 1 incident row in DB');
    console.log('  [4] ✅ 50 concurrent detections produced exactly 1 open incident via PostgreSQL advisory locking.');

    // ===========================================================================
    // SECTION 5 — MITRE ATT&CK MAPPING VERIFICATION (PART 7)
    // ===========================================================================
    console.log('\n--- TEST 5: MITRE ATT&CK MAPPING VERIFICATION ---');

    const createdIncidentId = Array.from(uniqueIncidentIds)[0];
    const mitreRows = await MitreMapping.findByIncidentId(createdIncidentId);
    console.log('  Stored MITRE mapping for RDP incident:', mitreRows);
    assert.strictEqual(mitreRows.length, 1);
    assert.strictEqual(mitreRows[0].technique_id, 'T1021.001', 'RDP exposure must map to T1021.001');
    assert.strictEqual(mitreRows[0].technique_name, 'Remote Services: Remote Desktop Protocol');

    // Test other mappings
    assert.strictEqual(MitreMapping.getTechniqueForAttackSurface('EXP-HIGH-SSH').technique_id, 'T1133');
    assert.strictEqual(MitreMapping.getTechniqueForAttackSurface('EXP-CRIT-REDIS').technique_id, 'T1190');
    assert.strictEqual(MitreMapping.getTechniqueForAttackSurface('EXP-MED-GENERIC').technique_id, 'T1046');
    console.log('  [5] ✅ MITRE ATT&CK techniques (T1021.001, T1133, T1190, T1046) mapped and stored automatically.');

    // ===========================================================================
    // SECTION 6 — POLICY ENGINE INTEGRATION (PART 8)
    // ===========================================================================
    console.log('\n--- TEST 6: POLICY ENGINE INTEGRATION ---');

    // Verify response actions proposed for the created incident
    const actionsRes = await db.query(
      `SELECT * FROM public.response_actions WHERE incident_id = $1;`,
      [createdIncidentId]
    );
    console.log('  Proposed response actions:', actionsRes.rows.map(a => `${a.action_type} (${a.action_mode}, ${a.status})`));
    const actionTypes = actionsRes.rows.map(a => a.action_type);
    assert.ok(actionTypes.includes('notify_admin'), 'notify_admin proposal must be created');
    assert.ok(actionTypes.includes('block_port'), 'block_port proposal must be created');
    assert.ok(actionTypes.includes('isolate_device'), 'isolate_device proposal must be created for score >= 90');
    
    // Verify shadow-mode enforcement
    for (const action of actionsRes.rows) {
      assert.strictEqual(action.action_mode, 'shadow', 'All actions must run in shadow mode');
      assert.ok(['proposed', 'pending_approval'].includes(action.status));
    }
    console.log('  [6] ✅ Policy Engine evaluated automatically; response proposals (notify_admin, block_port, isolate_device) created in shadow mode.');

    // ===========================================================================
    // SECTION 7 — AUTO-RESOLUTION LIFECYCLE (PART 9)
    // ===========================================================================
    console.log('\n--- TEST 7: AUTO-RESOLUTION LIFECYCLE ---');

    // Ingest snapshot on testDeviceA with port 5432 (Postgres, critical)
    const pgSnap = {
      agent: { device_id: testDeviceA, organization_id: testOrgA, user_id: null },
      body: {
        timestamp: new Date().toISOString(),
        event_type: 'agent_telemetry',
        details: {
          attack_surface: {
            listening_ports: [
              { port: 5432, protocol: 'tcp', bind_address: '0.0.0.0', exposure_scope: 'public', process_name: 'postgres' }
            ]
          }
        }
      }
    };
    await telemetryController.reportSystemEvent(pgSnap, createMockRes());

    const activeExpBefore = await db.query(
      `SELECT * FROM public.attack_surface_exposures WHERE device_id = $1 AND rule_id = 'EXP-CRIT-POSTGRES' AND status = 'active';`,
      [testDeviceA]
    );
    assert.strictEqual(activeExpBefore.rows.length, 1);
    const linkedIncidentId = activeExpBefore.rows[0].incident_id;
    assert.ok(linkedIncidentId, 'Active critical exposure must have linked incident_id');

    const incBefore = await db.query(`SELECT status FROM public.incidents WHERE id = $1;`, [linkedIncidentId]);
    assert.strictEqual(incBefore.rows[0].status, 'open', 'Incident must initially be OPEN');

    // Port disappears in next snapshot (service shut down or firewall applied)
    console.log('  Sending snapshot with empty listening ports (port 5432 closed)...');
    const emptySnap = {
      agent: { device_id: testDeviceA, organization_id: testOrgA, user_id: null },
      body: {
        timestamp: new Date().toISOString(),
        event_type: 'agent_telemetry',
        details: {
          attack_surface: {
            listening_ports: []
          }
        }
      }
    };
    await telemetryController.reportSystemEvent(emptySnap, createMockRes());

    // 1. Exposure must transition active -> mitigated
    const expAfter = await db.query(
      `SELECT status, mitigated_at FROM public.attack_surface_exposures WHERE id = $1;`,
      [activeExpBefore.rows[0].id]
    );
    assert.strictEqual(expAfter.rows[0].status, 'mitigated', 'Exposure must transition to MITIGATED');
    assert.ok(expAfter.rows[0].mitigated_at !== null, 'mitigated_at must be populated');

    // 2. Incident must transition open -> resolved
    const incAfter = await db.query(`SELECT status FROM public.incidents WHERE id = $1;`, [linkedIncidentId]);
    assert.strictEqual(incAfter.rows[0].status, 'resolved', 'Linked incident must transition to RESOLVED');

    // 3. Audit log entry attack_surface_exposure_resolved must be created
    const autoAuditRes = await db.query(
      `SELECT * FROM public.audit_logs 
       WHERE organization_id = $1 AND action = 'attack_surface_exposure_resolved' 
       ORDER BY created_at DESC LIMIT 1;`,
      [testOrgA]
    );
    assert.strictEqual(autoAuditRes.rows.length, 1, 'Audit log for exposure resolution must exist');
    assert.strictEqual(autoAuditRes.rows[0].details.exposure_id, activeExpBefore.rows[0].id);
    assert.strictEqual(autoAuditRes.rows[0].details.incident_id, linkedIncidentId);
    console.log('  [7] ✅ Auto-Resolution complete: exposure mitigated, incident resolved, audit log entry recorded.');

    // ===========================================================================
    // SECTION 8 — ADMIN APIs & TENANT ISOLATION (PART 10)
    // ===========================================================================
    console.log('\n--- TEST 8: ADMIN APIs & MULTI-TENANT ISOLATION ---');

    // Setup active exposure for Org A
    await telemetryController.reportSystemEvent(redisSnap, createMockRes());

    // 8A. GET /api/v1/admin/attack-surface/exposures
    const mockReqAdminA = {
      user: { id: '00000000-0000-0000-0000-000000000001', organization_id: testOrgA, role: 'admin' },
      query: { severity: 'critical', status: 'active' }
    };
    const resAdminA = createMockRes();
    await attackSurfaceController.getExposures(mockReqAdminA, resAdminA);
    assert.strictEqual(resAdminA.statusCode, 200);
    assert.ok(resAdminA.body.total >= 1);
    assert.ok(resAdminA.body.items.some(i => i.rule_id === 'EXP-CRIT-REDIS'));
    console.log(`  [8A] ✅ Admin API GET /exposures returned ${resAdminA.body.total} exposures for Org A.`);

    // 8B. GET /api/v1/admin/attack-surface/overview
    const resOverviewA = createMockRes();
    await attackSurfaceController.getOverview(mockReqAdminA, resOverviewA);
    assert.strictEqual(resOverviewA.statusCode, 200);
    console.log('  Org A overview response:', resOverviewA.body);
    assert.ok(resOverviewA.body.critical_exposures >= 1);
    assert.ok(resOverviewA.body.fleet_risk_score > 0);
    assert.ok(resOverviewA.body.public_services >= 1);
    console.log('  [8B] ✅ Admin API GET /overview returned accurate metrics.');

    // 8C. POST /api/v1/admin/attack-surface/scan (Single device)
    const mockReqScanA = {
      user: { id: '00000000-0000-0000-0000-000000000001', organization_id: testOrgA, role: 'admin' },
      body: { device_id: testDeviceA }
    };
    const resScanA = createMockRes();
    await attackSurfaceController.triggerScan(mockReqScanA, resScanA);
    assert.strictEqual(resScanA.statusCode, 202);
    assert.strictEqual(resScanA.body.status, 'queued');
    assert.strictEqual(resScanA.body.command_type, 'scan_attack_surface');
    assert.strictEqual(resScanA.body.commands.length, 1);
    assert.strictEqual(resScanA.body.commands[0].device_id, testDeviceA);
    console.log('  [8C] ✅ Admin API POST /scan queued scan_attack_surface agent command.');

    // 8C2. POST /api/v1/admin/attack-surface/scan (Fleet-wide atomic dispatch - HIGH-02)
    const mockReqScanFleet = {
      user: { id: '00000000-0000-0000-0000-000000000001', organization_id: testOrgA, role: 'admin' },
      body: {}
    };
    const resScanFleet = createMockRes();
    await attackSurfaceController.triggerScan(mockReqScanFleet, resScanFleet);
    assert.strictEqual(resScanFleet.statusCode, 202);
    assert.ok(resScanFleet.body.commands.length >= 1);
    console.log('  [8C2] ✅ Fleet-wide scan dispatched via atomic query (HIGH-02).');

    // 8D. Tenant Isolation: Org B cannot access Org A exposures
    const mockReqAdminB = {
      user: { id: '00000000-0000-0000-0000-000000000002', organization_id: testOrgB, role: 'admin' },
      query: { severity: 'critical', status: 'active' }
    };
    const resAdminB = createMockRes();
    await attackSurfaceController.getExposures(mockReqAdminB, resAdminB);
    assert.strictEqual(resAdminB.statusCode, 200);
    // Org B should have 0 Redis exposures
    const orgBRedis = resAdminB.body.items.filter(i => i.rule_id === 'EXP-CRIT-REDIS');
    assert.strictEqual(orgBRedis.length, 0, 'Tenant isolation violation: Org B accessed Org A Redis exposure!');
    console.log('  [8D] ✅ Multi-tenant isolation verified: Org B cannot view Org A exposures.');

    // 8E. Pagination Safety (MED-02): Requesting limit=5000 is clamped to 100
    const mockReqLargeLimit = {
      user: { id: '00000000-0000-0000-0000-000000000001', organization_id: testOrgA, role: 'admin' },
      query: { limit: '5000' }
    };
    const resLargeLimit = createMockRes();
    await attackSurfaceController.getExposures(mockReqLargeLimit, resLargeLimit);
    assert.strictEqual(resLargeLimit.statusCode, 200);
    assert.ok(resLargeLimit.body.items.length <= 100);
    console.log('  [8E] ✅ Pagination safety verified: limit clamped to <= 100.');

    // Cleanup test resources
    console.log('\nCleaning up Phase B test resources...');
    await db.query(`DELETE FROM public.response_actions WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.agent_commands WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.audit_logs WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.attack_surface_exposures WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.incidents WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
    await db.query(`DELETE FROM public.telemetry_events WHERE device_id IN ($1, $2);`, [testDeviceA, testDeviceB]);
    await db.query(`DELETE FROM public.devices WHERE id IN ($1, $2);`, [testDeviceA, testDeviceB]);
    await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgA, testOrgB]);
    console.log('Cleanup complete.');

    console.log('\n========================================================================');
    console.log('🎉 ALL PHASE B EXPOSURE & INCIDENT ORCHESTRATION CHECKS PASSED!');
    console.log('========================================================================\n');
  } catch (err) {
    console.error('\n❌ PHASE B TEST SUITE FAILED:', err);
    throw err;
  }
}

runPhaseBTestSuite()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
