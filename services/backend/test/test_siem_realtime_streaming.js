process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const streamingService = require('../src/services/siem/streamingService');
const liveMetricsService = require('../src/services/siem/liveMetricsService');
const eventBurstDetectionService = require('../src/services/siem/eventBurstDetectionService');
const lateralMovementService = require('../src/services/siem/lateralMovementService');
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
  console.log('CYBERGUARD — SIEM Phase 2: Real-Time Streaming & Live Detection Suite');
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

    // Setup base fixtures
    const orgARes = await db.query(`INSERT INTO public.organizations (name) VALUES ('RealTime Tenant Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO public.organizations (name) VALUES ('RealTime Tenant Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_a@stream.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const empARes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'emp_a@stream.test', 'hash', 'employee') RETURNING id;`,
      [testOrgAId]
    );
    testEmployeeAId = empARes.rows[0].id;
    createdUserIds.push(testEmployeeAId);

    const userBRes = await db.query(
      `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_b@stream.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    const devRes = await db.query(
      `INSERT INTO public.devices (organization_id, device_name, is_trusted) VALUES ($1, 'STREAM-SRV01', true) RETURNING id;`,
      [testOrgAId]
    );
    testDeviceAId = devRes.rows[0].id;
    createdDeviceIds.push(testDeviceAId);

    const tokenAnalystA = createToken({ id: testUserAId, email: 'analyst_a@stream.test', role: 'analyst', organization_id: testOrgAId });
    const tokenAnalystB = createToken({ id: testUserBId, email: 'analyst_b@stream.test', role: 'analyst', organization_id: testOrgBId });
    const tokenEmployeeA = createToken({ id: testEmployeeAId, email: 'emp_a@stream.test', role: 'employee', organization_id: testOrgAId });
    const tokenNoOrg = createToken({ id: '00000000-0000-0000-0000-000000000099', email: 'no_org@stream.test', role: 'admin', organization_id: null });

    console.log('--- TEST GROUP 1: REAL-TIME STREAMING & PUB/SUB ENGINE ---');

    await testAsync('1.1: Subscriber receives published event for same organization', async () => {
      streamingService.reset();
      let received = null;
      const subId = streamingService.subscribe({
        organizationId: testOrgAId,
        callback: (msg) => {
          received = msg;
        }
      });

      assert.ok(subId.startsWith('sub_'), 'Should return a valid subscription id');
      assert.strictEqual(streamingService.getActiveStreamCount(testOrgAId), 1);

      const sampleEvent = {
        organization_id: testOrgAId,
        event_type: 'windows_logon_success',
        source_type: 'windows',
        severity: 'low',
        message: 'Logon successful'
      };

      const pubRes = streamingService.publishEvent(sampleEvent);
      assert.strictEqual(pubRes.delivered, 1);
      assert.ok(received, 'Subscriber should have received message');
      assert.strictEqual(received.type, 'new_event');
      assert.strictEqual(received.event.event_type, 'windows_logon_success');

      streamingService.unsubscribe(subId);
      assert.strictEqual(streamingService.getActiveStreamCount(testOrgAId), 0);
    });

    await testAsync('1.2: Cross-tenant isolation: Org B subscriber never receives Org A events', async () => {
      streamingService.reset();
      let orgBReceived = null;

      const subBId = streamingService.subscribe({
        organizationId: testOrgBId,
        callback: (msg) => {
          orgBReceived = msg;
        }
      });

      const eventA = {
        organization_id: testOrgAId,
        event_type: 'sysmon_network_connection',
        source_type: 'sysmon',
        severity: 'high'
      };

      const pubRes = streamingService.publishEvent(eventA);
      assert.strictEqual(pubRes.delivered, 0, 'Should not deliver to Org B subscriber');
      assert.strictEqual(orgBReceived, null, 'Org B subscriber must remain untouched');

      streamingService.unsubscribe(subBId);
    });

    await testAsync('1.3: Filtered stream types: subscriber only receives subscribed source types', async () => {
      streamingService.reset();
      const receivedMessages = [];

      const subId = streamingService.subscribe({
        organizationId: testOrgAId,
        streamTypes: ['windows'],
        callback: (msg) => {
          receivedMessages.push(msg);
        }
      });

      streamingService.publishEvent({
        organization_id: testOrgAId,
        source_type: 'linux',
        event_type: 'linux_ssh_login'
      });
      assert.strictEqual(receivedMessages.length, 0, 'Linux event should be filtered out');

      streamingService.publishEvent({
        organization_id: testOrgAId,
        source_type: 'windows',
        event_type: 'windows_logon_success'
      });
      assert.strictEqual(receivedMessages.length, 1, 'Windows event should be delivered');

      streamingService.unsubscribe(subId);
    });

    await testAsync('1.4: Rate Limiting: Max 10 concurrent streams per org rejected with 429', async () => {
      streamingService.reset();
      const subIds = [];
      for (let i = 0; i < 10; i++) {
        subIds.push(streamingService.subscribe({
          organizationId: testOrgAId,
          callback: () => {}
        }));
      }

      assert.strictEqual(streamingService.getActiveStreamCount(testOrgAId), 10);

      let threw429 = false;
      try {
        streamingService.subscribe({
          organizationId: testOrgAId,
          callback: () => {}
        });
      } catch (err) {
        if (err.statusCode === 429) threw429 = true;
      }

      assert.ok(threw429, '11th stream must be rejected with HTTP 429 statusCode');
      for (const id of subIds) streamingService.unsubscribe(id);
    });

    await testAsync('1.5: Incident, attack chain, and campaign updates fan out cleanly', async () => {
      streamingService.reset();
      const eventsReceived = [];

      const subId = streamingService.subscribe({
        organizationId: testOrgAId,
        callback: (payload) => {
          eventsReceived.push(payload);
        }
      });

      streamingService.publishIncident({ id: 'inc-100', threat_type: 'phishing' }, testOrgAId);
      streamingService.publishAttackChainUpdate({ chain_length: 3, root_incident_id: 'inc-100' }, testOrgAId);
      streamingService.publishCampaignUpdate({ group_id: 'grp-200', action: 'merge' }, testOrgAId);

      assert.strictEqual(eventsReceived.length, 3);
      assert.strictEqual(eventsReceived[0].type, 'new_incident');
      assert.strictEqual(eventsReceived[1].type, 'attack_chain_update');
      assert.strictEqual(eventsReceived[2].type, 'campaign_update');

      streamingService.unsubscribe(subId);
    });

    console.log('\n--- TEST GROUP 2: EVENT BURST DETECTION ENGINE ---');

    await testAsync('2.1: Rule B1: > 100 events from same source within 5 mins generates Event Burst incident', async () => {
      eventBurstDetectionService.reset();
      const sourceKey = 'AGENT-DC01';
      let lastResult = null;

      for (let i = 1; i <= 101; i++) {
        const ev = {
          organization_id: testOrgAId,
          source_id: sourceKey,
          source_type: 'agent',
          event_type: 'agent_heartbeat',
          severity: 'low',
          normalized_data: {}
        };
        lastResult = await eventBurstDetectionService.processEvent(ev, testOrgAId);
      }

      assert.ok(lastResult, 'Should return processing result');
      assert.ok(lastResult.triggered_incidents.length > 0, 'Should trigger B1 Event Burst incident');
      const b1 = lastResult.triggered_incidents.find(i => i.rule_id === 'SIEM-BURST-VOLUME');
      assert.ok(b1, 'Should find SIEM-BURST-VOLUME incident');
      assert.strictEqual(b1.incident.threat_type, 'technical_threat');
      assert.strictEqual(b1.incident.risk_level, 'high');
      assert.ok(b1.incident.explanation.includes('Event Burst'), 'Explanation must note Event Burst');
    });

    await testAsync('2.2: Rule B2: > 50 auth failures within 5 mins generates Brute Force Attempt (MITRE T1110)', async () => {
      eventBurstDetectionService.reset();
      let lastResult = null;

      for (let i = 1; i <= 51; i++) {
        const ev = {
          organization_id: testOrgAId,
          event_type: 'windows_logon_failure',
          source_type: 'windows',
          severity: 'medium',
          normalized_data: {
            action: 'login_failure',
            target_user: 'admin.victim',
            source_ip: '198.51.100.25'
          }
        };
        lastResult = await eventBurstDetectionService.processEvent(ev, testOrgAId);
      }

      assert.ok(lastResult.triggered_incidents.length > 0, 'Should trigger B2 incident');
      const b2 = lastResult.triggered_incidents.find(i => i.rule_id === 'SIEM-BURST-BRUTE');
      assert.ok(b2, 'Should find SIEM-BURST-BRUTE incident');
      assert.strictEqual(b2.incident.threat_type, 'account_takeover');
      assert.strictEqual(b2.incident.risk_level, 'critical');
      assert.ok(b2.incident.explanation.includes('Brute Force Attempt'), 'Explanation must note Brute Force Attempt');

      // Verify MITRE mapping T1110 in database
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [b2.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1110');
    });

    await testAsync('2.3: Rule B3: > 20 privilege escalations within 10 mins generates Campaign (MITRE T1068)', async () => {
      eventBurstDetectionService.reset();
      let lastResult = null;

      for (let i = 1; i <= 21; i++) {
        const ev = {
          organization_id: testOrgAId,
          event_type: 'windows_local_group_member_added',
          source_type: 'windows',
          severity: 'high',
          normalized_data: {
            action: 'privilege_escalation',
            target_host: 'CORP-WIN-DC',
            target_user: 'compromised.service'
          }
        };
        lastResult = await eventBurstDetectionService.processEvent(ev, testOrgAId);
      }

      assert.ok(lastResult.triggered_incidents.length > 0, 'Should trigger B3 incident');
      const b3 = lastResult.triggered_incidents.find(i => i.rule_id === 'SIEM-BURST-PRV');
      assert.ok(b3, 'Should find SIEM-BURST-PRV incident');
      assert.strictEqual(b3.incident.threat_type, 'account_takeover');
      assert.strictEqual(b3.incident.risk_level, 'critical');
      assert.ok(b3.incident.explanation.includes('Privilege Escalation Campaign'), 'Explanation must note Privilege Escalation Campaign');

      // Verify MITRE mapping T1068
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [b3.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1068');
    });

    console.log('\n--- TEST GROUP 3: LATERAL MOVEMENT DETECTION ENGINE ---');

    await testAsync('3.1: Rule LM1: User accesses 3+ devices within 15 mins triggers Lateral Movement (MITRE T1021)', async () => {
      lateralMovementService.reset();
      const targetUser = 'bob.pivot';
      const devices = ['WORKSTATION-01', 'FILE-SRV02', 'BACKUP-NAS03'];

      let lastResult = null;
      for (const dev of devices) {
        const ev = {
          organization_id: testOrgAId,
          event_type: 'windows_logon_success',
          source_type: 'windows',
          normalized_data: {
            action: 'logon',
            target_user: targetUser,
            target_host: dev
          }
        };
        lastResult = await lateralMovementService.processEvent(ev, testOrgAId);
      }

      assert.ok(lastResult.triggered_incidents.length > 0, 'Should trigger LM1 on 3rd distinct device');
      const lm1 = lastResult.triggered_incidents.find(i => i.rule_id === 'SIEM-LM-DEVICE');
      assert.ok(lm1, 'Should find SIEM-LM-DEVICE incident');
      assert.strictEqual(lm1.incident.threat_type, 'technical_threat');
      assert.strictEqual(lm1.incident.risk_level, 'critical');
      assert.ok(lm1.incident.explanation.includes('Potential Lateral Movement'), 'Explanation must note Potential Lateral Movement');

      // Verify MITRE mapping T1021
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [lm1.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1021');
    });

    await testAsync('3.2: Rule LM2: Source IP authenticates to multiple hosts within 10 mins triggers Credential Reuse (MITRE T1078)', async () => {
      lateralMovementService.reset();
      const attackerIp = '172.16.50.25';
      const hosts = ['DEV-SRV1', 'PROD-DB2'];

      let lastResult = null;
      for (const h of hosts) {
        const ev = {
          organization_id: testOrgAId,
          event_type: 'linux_ssh_login',
          source_type: 'linux',
          normalized_data: {
            action: 'login',
            source_ip: attackerIp,
            target_host: h
          }
        };
        lastResult = await lateralMovementService.processEvent(ev, testOrgAId);
      }

      assert.ok(lastResult.triggered_incidents.length > 0, 'Should trigger LM2 on 2nd distinct host');
      const lm2 = lastResult.triggered_incidents.find(i => i.rule_id === 'SIEM-LM-IP');
      assert.ok(lm2, 'Should find SIEM-LM-IP incident');
      assert.strictEqual(lm2.incident.threat_type, 'account_takeover');
      assert.strictEqual(lm2.incident.risk_level, 'high');
      assert.ok(lm2.incident.explanation.includes('Credential Reuse Activity'), 'Explanation must note Credential Reuse Activity');

      // Verify MITRE mapping T1078
      const mitre = await db.query(`SELECT * FROM public.mitre_mappings WHERE incident_id = $1`, [lm2.incident.id]);
      assert.strictEqual(mitre.rows.length, 1);
      assert.strictEqual(mitre.rows[0].technique_id, 'T1078');
    });

    console.log('\n--- TEST GROUP 4: DASHBOARD LIVE METRICS ---');

    await testAsync('4.1: liveMetricsService tracks operational telemetry accurately', async () => {
      liveMetricsService.reset();
      streamingService.reset();

      liveMetricsService.recordEvent({ organization_id: testOrgAId, severity: 'low' });
      liveMetricsService.recordEvent({ organization_id: testOrgAId, severity: 'critical' });
      liveMetricsService.recordIncident({ organization_id: testOrgAId, risk_level: 'critical', risk_score: 95 });

      const metrics = liveMetricsService.getLiveMetrics(testOrgAId, 2);
      assert.strictEqual(metrics.events_per_minute, 2);
      assert.strictEqual(metrics.critical_events, 1);
      assert.strictEqual(metrics.incidents_per_minute, 1);
      assert.strictEqual(metrics.critical_incidents, 1);
      assert.strictEqual(metrics.active_streams, 2);
    });

    await testAsync('4.2: GET /api/v1/siem/live-metrics returns valid rolling operational data', async () => {
      const res = await fetch(`${baseUrl}/siem/live-metrics`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok('events_per_minute' in data);
      assert.ok('incidents_per_minute' in data);
      assert.ok('critical_events' in data);
      assert.ok('critical_incidents' in data);
      assert.ok('active_streams' in data);
    });

    await testAsync('4.3: GET /api/v1/siem/live-metrics responds under 100ms SLA', async () => {
      const start = Date.now();
      const res = await fetch(`${baseUrl}/siem/live-metrics`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      const duration = Date.now() - start;
      assert.strictEqual(res.status, 200);
      console.log(`      (Metrics endpoint responded in ${duration}ms)`);
      assert.ok(duration < 100, `Metrics endpoint took ${duration}ms (SLA: < 100ms)`);
    });

    console.log('\n--- TEST GROUP 5: LIVE SOC DASHBOARD SSE FEED ---');

    await testAsync('5.1: GET /api/v1/siem/stream establishes SSE stream and receives handshake', async () => {
      const sseResult = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/v1/siem/stream',
          method: 'GET',
          headers: { Authorization: `Bearer ${tokenAnalystA}` }
        }, (res) => {
          assert.strictEqual(res.statusCode, 200);
          assert.strictEqual(res.headers['content-type'], 'text/event-stream');

          let buffer = '';
          res.on('data', (chunk) => {
            buffer += chunk.toString();
            if (buffer.includes('connected')) {
              req.destroy();
              resolve({ headers: res.headers, body: buffer });
            }
          });
        });

        req.on('error', (err) => {
          // If socket destroyed after receiving handshake, ignore
          if (err.code !== 'ECONNRESET') reject(err);
        });
        req.end();
      });

      assert.ok(sseResult.body.includes('"type":"connected"'), 'Must receive connected event');
      assert.ok(sseResult.body.includes(testOrgAId), 'Must reference organization_id');
    });

    await testAsync('5.2: SSE client receives live events published to pipeline', async () => {
      const receivedLiveEvents = [];
      let clientReq;

      await new Promise((resolve) => {
        clientReq = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/v1/siem/stream',
          method: 'GET',
          headers: { Authorization: `Bearer ${tokenAnalystA}` }
        }, (res) => {
          res.on('data', (chunk) => {
            const lines = chunk.toString().split('\n');
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const parsed = JSON.parse(line.replace('data: ', ''));
                  receivedLiveEvents.push(parsed);
                  if (parsed.type === 'new_event') {
                    clientReq.destroy();
                    resolve();
                  }
                } catch (e) {}
              }
            }
          });

          // Once connected, publish an event
          setTimeout(() => {
            streamingService.publishEvent({
              organization_id: testOrgAId,
              event_type: 'windows_audit_log_cleared',
              source_type: 'windows',
              severity: 'critical'
            });
          }, 50);
        });

        clientReq.on('error', () => {});
        clientReq.end();
      });

      const found = receivedLiveEvents.find(e => e.type === 'new_event');
      assert.ok(found, 'Client must have received new_event over SSE');
      assert.strictEqual(found.event.event_type, 'windows_audit_log_cleared');
    });

    console.log('\n--- TEST GROUP 6: SECURITY & MULTI-TENANT RBAC ---');

    await testAsync('6.1: Reject unauthenticated requests with 401 on /stream and /live-metrics', async () => {
      const resStream = await fetch(`${baseUrl}/siem/stream`);
      assert.strictEqual(resStream.status, 401);

      const resMetrics = await fetch(`${baseUrl}/siem/live-metrics`);
      assert.strictEqual(resMetrics.status, 401);
    });

    await testAsync('6.2: Reject employee role (non-analyst/admin) with 403 Forbidden', async () => {
      const resStream = await fetch(`${baseUrl}/siem/stream`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(resStream.status, 403);

      const resMetrics = await fetch(`${baseUrl}/siem/live-metrics`, {
        headers: { Authorization: `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(resMetrics.status, 403);
    });

    await testAsync('6.3: Reject user with null organization_id with 403 Forbidden', async () => {
      const resStream = await fetch(`${baseUrl}/siem/stream`, {
        headers: { Authorization: `Bearer ${tokenNoOrg}` }
      });
      assert.strictEqual(resStream.status, 403);

      const resMetrics = await fetch(`${baseUrl}/siem/live-metrics`, {
        headers: { Authorization: `Bearer ${tokenNoOrg}` }
      });
      assert.strictEqual(resMetrics.status, 403);
    });

    console.log('\n--- TEST GROUP 7: PERFORMANCE & SCALE SLA ---');

    await testAsync('7.1: Bulk stream publish of 1,000 events completes under 10ms per event SLA', async () => {
      streamingService.reset();
      let subscriberReceived = 0;
      const subId = streamingService.subscribe({
        organizationId: testOrgAId,
        callback: () => {
          subscriberReceived++;
        }
      });

      const start = Date.now();
      for (let i = 0; i < 1000; i++) {
        streamingService.publishEvent({
          organization_id: testOrgAId,
          source_type: 'windows',
          event_type: 'event_' + i,
          severity: 'low'
        });
      }
      const totalTimeMs = Date.now() - start;
      const avgTimePerEvent = totalTimeMs / 1000;

      console.log(`      (1,000 events published in ${totalTimeMs}ms, avg ${avgTimePerEvent.toFixed(3)}ms/event)`);
      assert.strictEqual(subscriberReceived, 1000);
      assert.ok(avgTimePerEvent < 10, `Stream publish took ${avgTimePerEvent}ms (SLA: < 10ms)`);
      streamingService.unsubscribe(subId);
    });

    await testAsync('7.2: End-to-end pipeline: Ingestion -> Normalization -> Streaming -> Detection Bridge', async () => {
      streamingService.reset();
      let streamNotification = null;

      const subId = streamingService.subscribe({
        organizationId: testOrgAId,
        callback: (msg) => {
          if (msg.type === 'new_incident') {
            streamNotification = msg;
          }
        }
      });

      // Send single Windows 1102 (Audit log cleared) through EventPipelineService
      const result = await EventPipelineService.processEvents({
        organizationId: testOrgAId,
        events: [
          {
            EventID: '1102',
            EventData: {
              TargetUserName: 'evasive_actor',
              Computer: 'CORP-WIN-SRV01'
            }
          }
        ]
      });

      assert.strictEqual(result.total_events, 1);
      assert.strictEqual(result.successful_events, 1);
      assert.ok(result.detected_incidents.length > 0, 'Must create incident via detection bridge');
      assert.ok(streamNotification, 'Stream subscriber must have received new_incident payload');
      assert.strictEqual(streamNotification.incident.threat_type, 'technical_threat');

      streamingService.unsubscribe(subId);
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdDeviceIds.length > 0) {
        await db.query(`DELETE FROM public.devices WHERE id = ANY($1::uuid[]);`, [createdDeviceIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
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
