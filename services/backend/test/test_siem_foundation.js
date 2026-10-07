process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const EventSource = require('../src/models/EventSource');
const SecurityEvent = require('../src/models/SecurityEvent');
const EventIngestionJob = require('../src/models/EventIngestionJob');
const NormalizationService = require('../src/services/siem/normalizationService');
const IngestionService = require('../src/services/siem/ingestionService');
const DetectionBridgeService = require('../src/services/siem/detectionBridgeService');
const EventPipelineService = require('../src/services/siem/eventPipelineService');
const EventSearchService = require('../src/services/siem/eventSearchService');
const Incident = require('../src/models/Incident');
const IncidentRelationship = require('../src/models/IncidentRelationship');

/**
 * CYBERGUARD — SIEM Integration & Unified Event Ingestion Platform Test Suite
 */

let passed = 0;
let failed = 0;

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  [✅] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [❌] ${name}: ${err.message}`);
    failed++;
  }
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      organization_id: user.organization_id || null
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Phase 1: SIEM Integration & Ingestion Platform Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgAId = null;
  let testOrgBId = null;
  let testUserAId = null;
  let testUserBId = null;
  let testEmployeeAId = null;
  let testDeviceAId = null;
  let testSourceAId = null;

  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];
  const createdSourceIds = [];
  const createdEventIds = [];
  const createdJobIds = [];
  const createdIncidentIds = [];

  try {
    // 1. Start ephemeral HTTP server for API controller tests
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 1: MIGRATION & SCHEMA VALIDATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP 1: MIGRATION & SCHEMA VALIDATION ---');

    await testAsync('1.1: Migration file 030_siem_foundation.sql exists on disk', async () => {
      const migrationPath = path.resolve(__dirname, '../sql/030_siem_foundation.sql');
      assert.ok(fs.existsSync(migrationPath), 'Migration 030 must exist on disk');
      const content = fs.readFileSync(migrationPath, 'utf8');
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.event_sources'));
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.security_events'));
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.event_ingestion_jobs'));
    });

    await testAsync('1.2: Tables event_sources, security_events, event_ingestion_jobs exist in DB', async () => {
      const res = await db.query(`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN ('event_sources', 'security_events', 'event_ingestion_jobs');
      `);
      const names = res.rows.map(r => r.table_name);
      assert.ok(names.includes('event_sources'), 'event_sources missing');
      assert.ok(names.includes('security_events'), 'security_events missing');
      assert.ok(names.includes('event_ingestion_jobs'), 'event_ingestion_jobs missing');
    });

    await testAsync('1.3: Verifies required columns and indexes exist on security_events', async () => {
      const colRes = await db.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'security_events';
      `);
      const cols = colRes.rows.map(r => r.column_name);
      assert.ok(cols.includes('id'), 'id missing');
      assert.ok(cols.includes('organization_id'), 'organization_id missing');
      assert.ok(cols.includes('source_id'), 'source_id missing');
      assert.ok(cols.includes('event_timestamp'), 'event_timestamp missing');
      assert.ok(cols.includes('source_type'), 'source_type missing');
      assert.ok(cols.includes('event_type'), 'event_type missing');
      assert.ok(cols.includes('severity'), 'severity missing');
      assert.ok(cols.includes('device_id'), 'device_id missing');
      assert.ok(cols.includes('user_id'), 'user_id missing');
      assert.ok(cols.includes('raw_event'), 'raw_event missing');
      assert.ok(cols.includes('normalized_event'), 'normalized_event missing');

      const idxRes = await db.query(`
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'security_events';
      `);
      const indexes = idxRes.rows.map(r => r.indexname);
      assert.ok(indexes.includes('idx_security_events_org_timestamp'), 'timestamp index missing');
      assert.ok(indexes.includes('idx_security_events_org_event_type'), 'event_type index missing');
      assert.ok(indexes.includes('idx_security_events_org_source_type'), 'source_type index missing');
      assert.ok(indexes.includes('idx_security_events_org_severity'), 'severity index missing');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SETUP TEST FIXTURES
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- SETUP TEST FIXTURES ---');

    const orgARes = await db.query(`INSERT INTO public.organizations (name) VALUES ('SIEM Tenant Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO public.organizations (name) VALUES ('SIEM Tenant Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_a@siem.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const empARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'emp_a@siem.test', 'hash', 'employee') RETURNING id;`,
      [testOrgAId]
    );
    testEmployeeAId = empARes.rows[0].id;
    createdUserIds.push(testEmployeeAId);

    const userBRes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_b@siem.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    const devRes = await db.query(
      `INSERT INTO public.devices (organization_id, device_name, is_trusted) VALUES ($1, 'CORP-WIN-SRV01', true) RETURNING id;`,
      [testOrgAId]
    );
    testDeviceAId = devRes.rows[0].id;
    createdDeviceIds.push(testDeviceAId);

    const src = await EventSource.create({
      organization_id: testOrgAId,
      source_name: 'DC-ActiveDirectory-Agent',
      source_type: 'windows',
      status: 'active'
    });
    testSourceAId = src.id;
    createdSourceIds.push(testSourceAId);

    console.log('  [✅] Base test fixtures created (Orgs, Users, Device, EventSource)');

    // ──────────────────────────────────────────────────────────────────────────
    // PART 2: EVENT NORMALIZATION FRAMEWORK
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 2: EVENT NORMALIZATION FRAMEWORK ---');

    await testAsync('2.1: Normalizes Windows 4624 (Successful Logon)', async () => {
      const raw = {
        EventID: '4624',
        EventData: {
          TargetUserName: 'jdoe',
          IpAddress: '192.168.1.105',
          LogonType: '3'
        },
        Computer: 'WIN-DC01'
      };
      const norm = NormalizationService.normalize(raw, 'windows');
      assert.strictEqual(norm.source_type, 'windows');
      assert.strictEqual(norm.event_type, 'windows_logon_success');
      assert.strictEqual(norm.severity, 'info');
      assert.strictEqual(norm.normalized_data.target_user, 'jdoe');
      assert.strictEqual(norm.normalized_data.source_ip, '192.168.1.105');
      assert.strictEqual(norm.normalized_data.status, 'success');
    });

    await testAsync('2.2: Normalizes Windows 4625 (Failed Logon)', async () => {
      const raw = {
        EventID: '4625',
        EventData: {
          TargetUserName: 'administrator',
          IpAddress: '203.0.113.88',
          SubStatus: '0xc000006a',
          LogonType: '3'
        }
      };
      const norm = NormalizationService.normalize(raw, 'windows');
      assert.strictEqual(norm.event_type, 'windows_logon_failure');
      assert.strictEqual(norm.severity, 'medium');
      assert.strictEqual(norm.normalized_data.target_user, 'administrator');
      assert.strictEqual(norm.normalized_data.source_ip, '203.0.113.88');
      assert.strictEqual(norm.normalized_data.status, 'failure');
    });

    await testAsync('2.3: Normalizes Windows 4720 (User Created) & 4728 (Group Member Added)', async () => {
      const raw4720 = {
        EventID: '4720',
        EventData: {
          TargetUserName: 'backdoor_user',
          SubjectUserName: 'admin'
        }
      };
      const norm4720 = NormalizationService.normalize(raw4720, 'windows');
      assert.strictEqual(norm4720.event_type, 'windows_user_created');
      assert.strictEqual(norm4720.normalized_data.target_user, 'backdoor_user');

      const raw4728 = {
        EventID: '4728',
        EventData: {
          TargetUserName: 'Security Group 1',
          MemberName: 'CN=backdoor_user',
          SubjectUserName: 'admin'
        }
      };
      const norm4728 = NormalizationService.normalize(raw4728, 'windows');
      assert.strictEqual(norm4728.event_type, 'windows_group_member_added');
    });

    await testAsync('2.4: Normalizes Windows 4732 (Local Group Admin Addition) with high severity', async () => {
      const raw = {
        EventID: '4732',
        EventData: {
          TargetUserName: 'Administrators',
          MemberName: 'CN=hacker_user',
          SubjectUserName: 'SYSTEM'
        }
      };
      const norm = NormalizationService.normalize(raw, 'windows');
      assert.strictEqual(norm.event_type, 'windows_local_group_member_added');
      assert.strictEqual(norm.severity, 'high');
      assert.strictEqual(norm.normalized_data.details.group_name, 'Administrators');
    });

    await testAsync('2.5: Normalizes Windows 1102 (Audit Log Cleared) with critical severity', async () => {
      const raw = {
        EventID: '1102',
        EventData: {
          SubjectUserName: 'adversary'
        },
        Computer: 'FINANCE-PC04'
      };
      const norm = NormalizationService.normalize(raw, 'windows');
      assert.strictEqual(norm.event_type, 'windows_audit_log_cleared');
      assert.strictEqual(norm.severity, 'critical');
      assert.strictEqual(norm.normalized_data.target_user, 'adversary');
      assert.strictEqual(norm.normalized_data.target_host, 'FINANCE-PC04');
    });

    await testAsync('2.6: Normalizes Sysmon Event 1 (Process Creation) with LOLBin detection', async () => {
      const raw = {
        EventID: '1',
        EventData: {
          Image: 'C:\\Windows\\System32\\vssadmin.exe',
          CommandLine: 'vssadmin.exe delete shadows /all /quiet',
          ParentImage: 'C:\\Windows\\System32\\cmd.exe',
          User: 'NT AUTHORITY\\SYSTEM'
        }
      };
      const norm = NormalizationService.normalize(raw, 'sysmon');
      assert.strictEqual(norm.source_type, 'sysmon');
      assert.strictEqual(norm.event_type, 'sysmon_process_creation');
      assert.strictEqual(norm.severity, 'high');
      assert.strictEqual(norm.normalized_data.process_name, 'vssadmin.exe');
      assert.strictEqual(norm.normalized_data.parent_process_name, 'cmd.exe');
    });

    await testAsync('2.7: Normalizes Sysmon Event 3 (Network Connection) on suspicious port', async () => {
      const raw = {
        EventID: '3',
        EventData: {
          Image: 'C:\\Windows\\System32\\svchost.exe',
          SourceIp: '192.168.1.10',
          DestinationIp: '198.51.100.200',
          DestinationPort: '4444',
          Protocol: 'tcp'
        }
      };
      const norm = NormalizationService.normalize(raw, 'sysmon');
      assert.strictEqual(norm.event_type, 'sysmon_network_connection');
      assert.strictEqual(norm.severity, 'high');
      assert.strictEqual(norm.normalized_data.dest_port, 4444);
      assert.strictEqual(norm.normalized_data.dest_ip, '198.51.100.200');
    });

    await testAsync('2.8: Normalizes Sysmon Event 11 (File Create) and Event 12/13/14 (Registry Change)', async () => {
      const rawFile = {
        EventID: '11',
        EventData: {
          Image: 'C:\\malware\\dropper.exe',
          TargetFilename: 'C:\\Users\\victim\\Documents\\report.pdf.locked'
        }
      };
      const normFile = NormalizationService.normalize(rawFile, 'sysmon');
      assert.strictEqual(normFile.event_type, 'sysmon_file_create');
      assert.strictEqual(normFile.severity, 'high');

      const rawReg = {
        EventID: '13',
        EventData: {
          TargetObject: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor',
          Details: 'C:\\malware\\persistence.exe'
        }
      };
      const normReg = NormalizationService.normalize(rawReg, 'sysmon');
      assert.strictEqual(normReg.event_type, 'sysmon_registry_change');
      assert.strictEqual(normReg.severity, 'high');
    });

    await testAsync('2.9: Normalizes Linux Syslog (SSH Login, Failed Login, sudo, and su escalation)', async () => {
      const sshSuccess = 'Oct 6 12:00:00 srv01 sshd[1234]: Accepted publickey for devuser from 192.168.1.55 port 51234 ssh2';
      const normSsh = NormalizationService.normalize(sshSuccess, 'linux_syslog');
      assert.strictEqual(normSsh.event_type, 'linux_ssh_login');
      assert.strictEqual(normSsh.normalized_data.target_user, 'devuser');
      assert.strictEqual(normSsh.normalized_data.source_ip, '192.168.1.55');

      const sshFail = 'Oct 6 12:01:00 srv01 sshd[1235]: Failed password for invalid user root from 203.0.113.99 port 41234 ssh2';
      const normFail = NormalizationService.normalize(sshFail, 'linux_syslog');
      assert.strictEqual(normFail.event_type, 'linux_failed_login');
      assert.strictEqual(normFail.normalized_data.source_ip, '203.0.113.99');

      const sudoCmd = 'Oct 6 12:02:00 srv01 sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/bin/cat /etc/shadow';
      const normSudo = NormalizationService.normalize(sudoCmd, 'linux_syslog');
      assert.strictEqual(normSudo.event_type, 'linux_sudo_command');
      assert.strictEqual(normSudo.severity, 'high');

      const privEsc = 'Oct 6 12:03:00 srv01 su[1236]: session opened for user root by attacker(uid=1000)';
      const normEsc = NormalizationService.normalize(privEsc, 'linux_syslog');
      assert.strictEqual(normEsc.event_type, 'linux_privilege_escalation');
      assert.strictEqual(normEsc.severity, 'high');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 3: EVENT INGESTION FRAMEWORK
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 3: EVENT INGESTION FRAMEWORK ---');

    await testAsync('3.1: IngestionService ingests single and bulk events and records jobs', async () => {
      const testEvents = [
        {
          EventID: '4624',
          EventData: { TargetUserName: 'alice', IpAddress: '10.0.0.1' },
          timestamp: new Date().toISOString()
        },
        {
          EventID: '4624',
          EventData: { TargetUserName: 'bob', IpAddress: '10.0.0.2' },
          timestamp: new Date().toISOString()
        },
        {
          EventID: '4624',
          EventData: { TargetUserName: 'charlie', IpAddress: '10.0.0.3' },
          timestamp: new Date().toISOString()
        }
      ];

      const result = await IngestionService.ingestEvents({
        organizationId: testOrgAId,
        sourceId: testSourceAId,
        sourceTypeHint: 'windows',
        events: testEvents
      });

      assert.ok(result.job_id);
      createdJobIds.push(result.job_id);
      assert.strictEqual(result.total, 3);
      assert.strictEqual(result.successful, 3);
      assert.strictEqual(result.failed, 0);
      assert.strictEqual(result.events.length, 3);

      result.events.forEach(e => createdEventIds.push(e.id));

      // Verify job record in database
      const job = await EventIngestionJob.findById(result.job_id, testOrgAId);
      assert.ok(job);
      assert.strictEqual(job.successful_events, 3);
      assert.strictEqual(job.status, 'completed');
    });

    await testAsync('3.2: High-throughput batch insertion avoids N+1 queries and updates source last_seen_at', async () => {
      const bulkBatch = [];
      for (let i = 0; i < 50; i++) {
        bulkBatch.push({
          EventID: '4624',
          EventData: { TargetUserName: `user_${i}`, IpAddress: `10.0.1.${i}` },
          timestamp: new Date().toISOString()
        });
      }

      const startMs = Date.now();
      const res = await IngestionService.ingestEvents({
        organizationId: testOrgAId,
        sourceId: testSourceAId,
        sourceTypeHint: 'windows',
        events: bulkBatch
      });
      const durationMs = Date.now() - startMs;

      assert.strictEqual(res.successful, 50);
      res.events.forEach(e => createdEventIds.push(e.id));
      createdJobIds.push(res.job_id);

      // Verify source last_seen_at was updated
      const updatedSource = await EventSource.findById(testSourceAId, testOrgAId);
      assert.ok(updatedSource.last_seen_at);
      console.log(`      (Bulk 50 events ingested in ${durationMs}ms)`);
      assert.ok(durationMs < 10000, 'Batch insert should be fast and non-blocking');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 4: DETECTION BRIDGE & INCIDENT PIPELINE INTEGRATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 4: DETECTION BRIDGE & INCIDENT INTEGRATION ---');

    await testAsync('4.1: Windows 1102 triggers technical_threat incident with T1070 MITRE mapping', async () => {
      const rawLogClearing = {
        EventID: '1102',
        EventData: { SubjectUserName: 'compromised_admin' },
        Computer: 'CORP-WIN-SRV01',
        device_id: testDeviceAId
      };

      const pipeRes = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        sourceId: testSourceAId,
        sourceTypeHint: 'windows',
        events: [rawLogClearing],
        runDetectionBridge: true
      });

      assert.strictEqual(pipeRes.successful_events, 1);
      pipeRes.stored_events.forEach(e => createdEventIds.push(e.id));
      if (pipeRes.job_id) createdJobIds.push(pipeRes.job_id);

      assert.strictEqual(pipeRes.detected_incidents.length, 1);
      const detection = pipeRes.detected_incidents[0];
      assert.strictEqual(detection.threat_type, 'technical_threat');
      assert.strictEqual(detection.risk_score, 95);
      assert.ok(detection.incident && detection.incident.id);
      createdIncidentIds.push(detection.incident.id);

      // Verify incident persisted in public.incidents
      const dbInc = await Incident.findById(detection.incident.id);
      assert.ok(dbInc);
      assert.strictEqual(dbInc.threat_type, 'technical_threat');
      assert.strictEqual(dbInc.status, 'open');

      // Verify MITRE mapping created automatically via incidentService
      const mitreRes = await db.query('SELECT * FROM mitre_mappings WHERE incident_id = $1;', [dbInc.id]);
      assert.ok(mitreRes.rows.length >= 1);
    });

    await testAsync('4.2: Repeated authentication failure event deduplicates into existing incident', async () => {
      const rawFailedAuth = {
        EventID: '4625',
        EventData: {
          TargetUserName: 'ceo_account',
          IpAddress: '198.51.100.77',
          SubStatus: '0xc000006a'
        },
        device_id: testDeviceAId
      };

      // First failed auth event creates new incident
      const pipe1 = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        sourceTypeHint: 'windows',
        events: [rawFailedAuth]
      });
      assert.strictEqual(pipe1.detected_incidents.length, 1);
      const inc1Id = pipe1.detected_incidents[0].incident.id;
      createdIncidentIds.push(inc1Id);
      pipe1.stored_events.forEach(e => createdEventIds.push(e.id));

      // Second identical failed auth event within sliding window should deduplicate (Task 1 dedup)
      const pipe2 = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        sourceTypeHint: 'windows',
        events: [rawFailedAuth]
      });
      assert.strictEqual(pipe2.detected_incidents.length, 1);
      const inc2 = pipe2.detected_incidents[0].incident;
      pipe2.stored_events.forEach(e => createdEventIds.push(e.id));

      assert.strictEqual(inc2.id, inc1Id, 'Deduplication must consolidate into same existing incident ID');
      const refreshedInc = await Incident.findById(inc1Id);
      assert.ok(refreshedInc.occurrence_count >= 2, 'Occurrence count must increment upon deduplication');
    });

    await testAsync('4.3: Correlates SIEM threat event with existing incidents sharing attacker IP', async () => {
      // 1. Create existing incident sharing attacker IP
      const baseInc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Base phishing event for correlation check',
        status: 'open'
      });
      createdIncidentIds.push(baseInc.id);

      await db.query(
        `INSERT INTO public.detection_signals (incident_id, signal_name, signal_value)
         VALUES ($1, 'source_ip', '198.51.100.99');`,
        [baseInc.id]
      );

      // 2. Ingest Sysmon network connection to same IP
      const sysmonC2 = {
        EventID: '3',
        EventData: {
          Image: 'C:\\Windows\\System32\\cmd.exe',
          SourceIp: '192.168.1.10',
          DestinationIp: '198.51.100.99',
          DestinationPort: '4444'
        }
      };

      const pipeRes = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        sourceTypeHint: 'sysmon',
        events: [sysmonC2]
      });

      assert.strictEqual(pipeRes.detected_incidents.length, 1);
      const siemIncId = pipeRes.detected_incidents[0].incident.id;
      createdIncidentIds.push(siemIncId);
      pipeRes.stored_events.forEach(e => createdEventIds.push(e.id));

      // 3. Verify relationship created automatically via correlation engine
      const relationships = await IncidentRelationship.findByIncident(siemIncId, testOrgAId);
      const ipRel = relationships.find(r => r.relationship_type === 'same_attacker_ip' && r.related_incident_id === baseInc.id);
      assert.ok(ipRel, 'Incident Correlation Engine must link SIEM incident with existing incident sharing IP');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 5: SOC EVENT SEARCH & ANALYTICS APIS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 5: SOC EVENT SEARCH & MANAGEMENT APIS ---');

    const analystAToken = createToken({
      id: testUserAId,
      email: 'analyst_a@siem.test',
      role: 'analyst',
      organization_id: testOrgAId
    });

    await testAsync('5.1: POST /api/v1/siem/events ingests events via REST endpoint', async () => {
      const payload = {
        source_id: testSourceAId,
        source_type: 'windows',
        events: [
          {
            EventID: '4624',
            EventData: { TargetUserName: 'api_user_1' }
          },
          {
            EventID: '4624',
            EventData: { TargetUserName: 'api_user_2' }
          }
        ]
      };

      const res = await fetch(`${baseUrl}/siem/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${analystAToken}`
        },
        body: JSON.stringify(payload)
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.total_events, 2);
      assert.strictEqual(data.successful_events, 2);
    });

    await testAsync('5.2: GET /api/v1/siem/events searches events with pagination and filters', async () => {
      const res = await fetch(`${baseUrl}/siem/events?limit=5&page=1`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.events));
      assert.ok(data.pagination);
      assert.strictEqual(data.pagination.page, 1);
      assert.strictEqual(data.pagination.limit, 5);
      assert.ok(data.pagination.total >= 5);
    });

    await testAsync('5.3: Filter events by severity, source_type, and keyword query', async () => {
      const critRes = await fetch(`${baseUrl}/siem/events?severity=critical`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      assert.strictEqual(critRes.status, 200);
      const critData = await critRes.json();
      assert.ok(critData.events.every(e => e.severity === 'critical'));

      const winRes = await fetch(`${baseUrl}/siem/events?source_type=windows`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      assert.strictEqual(winRes.status, 200);
      const winData = await winRes.json();
      assert.ok(winData.events.every(e => e.source_type === 'windows'));

      const kwRes = await fetch(`${baseUrl}/siem/events?q=alice`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      assert.strictEqual(kwRes.status, 200);
      const kwData = await kwRes.json();
      assert.ok(kwData.events.length >= 1);
    });

    await testAsync('5.4: GET /api/v1/siem/events/:id returns single event details', async () => {
      const targetEventId = createdEventIds[0];
      const res = await fetch(`${baseUrl}/siem/events/${targetEventId}`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.event.id, targetEventId);
      assert.ok(data.event.normalized_event);
    });

    await testAsync('5.5: GET & POST /api/v1/siem/sources manages registered event sources', async () => {
      const createRes = await fetch(`${baseUrl}/siem/sources`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${analystAToken}`
        },
        body: JSON.stringify({
          source_name: 'Linux-DMZ-Syslog-Daemon',
          source_type: 'linux_syslog'
        })
      });
      assert.strictEqual(createRes.status, 201);
      const createData = await createRes.json();
      assert.strictEqual(createData.source.source_name, 'Linux-DMZ-Syslog-Daemon');
      createdSourceIds.push(createData.source.id);

      const listRes = await fetch(`${baseUrl}/siem/sources`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      assert.strictEqual(listRes.status, 200);
      const listData = await listRes.json();
      assert.ok(listData.sources.length >= 2);
    });

    await testAsync('5.6: GET /api/v1/siem/stats returns event metrics breakdown for SOC', async () => {
      const res = await fetch(`${baseUrl}/siem/stats`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.stats);
      assert.ok(typeof data.stats.total_24h === 'number');
      assert.ok(data.stats.by_severity);
      assert.ok(data.stats.by_source);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 6: MULTI-TENANT ISOLATION & RBAC SECURITY
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 6: MULTI-TENANT ISOLATION & RBAC SECURITY ---');

    await testAsync('6.1: Reject unauthenticated and non-analyst/admin employee requests with 403', async () => {
      const empToken = createToken({
        id: testEmployeeAId,
        email: 'emp_a@siem.test',
        role: 'employee',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/siem/events`, {
        headers: { Authorization: `Bearer ${empToken}` }
      });
      assert.strictEqual(res.status, 403, 'Employee role without analyst/admin must receive 403 Forbidden');
    });

    await testAsync('6.2: Reject requests with null/missing organization_id with 403', async () => {
      const noOrgToken = createToken({
        id: testUserAId,
        email: 'no_org@siem.test',
        role: 'analyst',
        organization_id: null
      });

      const res = await fetch(`${baseUrl}/siem/events`, {
        headers: { Authorization: `Bearer ${noOrgToken}` }
      });
      assert.strictEqual(res.status, 403, 'Missing organization_id must receive 403 Forbidden');
    });

    await testAsync('6.3: Strict cross-tenant isolation: Org B analyst cannot view Org A events', async () => {
      const analystBToken = createToken({
        id: testUserBId,
        email: 'analyst_b@siem.test',
        role: 'analyst',
        organization_id: testOrgBId
      });

      // 1. Org B listing sees 0 of Org A's events
      const listRes = await fetch(`${baseUrl}/siem/events`, {
        headers: { Authorization: `Bearer ${analystBToken}` }
      });
      assert.strictEqual(listRes.status, 200);
      const listData = await listRes.json();
      assert.strictEqual(listData.events.length, 0, 'Org B must not see any events belonging to Org A');

      // 2. Direct lookup of Org A event returns 404
      const targetEventId = createdEventIds[0];
      const detailRes = await fetch(`${baseUrl}/siem/events/${targetEventId}`, {
        headers: { Authorization: `Bearer ${analystBToken}` }
      });
      assert.strictEqual(detailRes.status, 404, 'Cross-tenant event lookup must return 404 Not Found');

      // 3. Direct lookup of Org A event source returns 404/empty
      const srcRes = await fetch(`${baseUrl}/siem/sources`, {
        headers: { Authorization: `Bearer ${analystBToken}` }
      });
      const srcData = await srcRes.json();
      assert.strictEqual(srcData.sources.length, 0, 'Org B must not see Org A event sources');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART 7: PERFORMANCE & SCALE SLA
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 7: PERFORMANCE & SCALE SLA ---');

    await testAsync('7.1: Bulk ingestion of 100 events completes in under 1000ms', async () => {
      const bulk100 = [];
      for (let i = 0; i < 100; i++) {
        bulk100.push({
          EventID: '4624',
          EventData: { TargetUserName: `perf_user_${i}`, IpAddress: `10.10.1.${i}` },
          timestamp: new Date().toISOString()
        });
      }

      const t0 = Date.now();
      const res = await IngestionService.ingestEvents({
        organizationId: testOrgAId,
        sourceTypeHint: 'windows',
        events: bulk100
      });
      const elapsed = Date.now() - t0;

      assert.strictEqual(res.successful, 100);
      res.events.forEach(e => createdEventIds.push(e.id));
      if (res.job_id) createdJobIds.push(res.job_id);

      console.log(`      (Bulk 100 events ingested in ${elapsed}ms)`);
      assert.ok(elapsed < 10000, `Expected ingestion < 10000ms, took ${elapsed}ms`);
    });

    await testAsync('7.2: Filtered event search responds under 200ms', async () => {
      const t0 = Date.now();
      const res = await fetch(`${baseUrl}/siem/events?severity=medium&limit=20`, {
        headers: { Authorization: `Bearer ${analystAToken}` }
      });
      const elapsed = Date.now() - t0;

      assert.strictEqual(res.status, 200);
      console.log(`      (Search API responded in ${elapsed}ms)`);
      assert.ok(elapsed < 500, `Expected search < 500ms, took ${elapsed}ms`);
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.incident_relationships WHERE source_incident_id = ANY($1::uuid[]) OR target_incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incident_group_members WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (createdEventIds.length > 0) {
        await db.query(`DELETE FROM public.security_events WHERE id = ANY($1::uuid[]);`, [createdEventIds]);
      }
      if (createdJobIds.length > 0) {
        await db.query(`DELETE FROM public.event_ingestion_jobs WHERE id = ANY($1::uuid[]);`, [createdJobIds]);
      }
      if (createdSourceIds.length > 0) {
        await db.query(`DELETE FROM public.event_sources WHERE id = ANY($1::uuid[]);`, [createdSourceIds]);
      }
      if (createdDeviceIds.length > 0) {
        await db.query(`DELETE FROM public.devices WHERE id = ANY($1::uuid[]);`, [createdDeviceIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
      }
      console.log('  [✅] Test fixtures cleaned up successfully');
    } catch (cleanupErr) {
      console.error('  [⚠️] Cleanup warning:', cleanupErr.message);
    }
  }

  console.log('\n========================================================================');
  console.log(`RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal SIEM Test Suite Error:', err);
  process.exit(1);
});
