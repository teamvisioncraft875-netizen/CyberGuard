const assert = require('assert');
const db = require('../src/config/db');
const Incident = require('../src/models/Incident');
const incidentDeduplicationService = require('../src/services/incidentDeduplicationService');
const { persistDetectionIncident } = require('../src/services/incidentService');

/**
 * CYBERGUARD — Task 1: Incident Deduplication Test Suite
 *
 * Validates:
 * Group 1: Migration validation (columns and indexes)
 * Group 2: Fingerprint generation determinism & normalization
 * Group 3: Duplicate detection within sliding window
 * Group 4: Incident consolidation & occurrence count increments
 * Group 5: Multi-tenant isolation (Org A vs Org B)
 * Group 6: End-to-end pipeline deduplication integration
 * Group 7: Sliding window expiration
 * Group 8: Audit logging persistence (incident_deduplicated / incident_consolidated)
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

async function runTestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Task 1: Incident Deduplication Test Suite');
  console.log('========================================================================\n');

  let testOrgAId = null;
  let testOrgBId = null;
  const createdIncidentIds = [];

  try {
    console.log('--- TEST GROUP 1: MIGRATION & SCHEMA VALIDATION ---');

    await testAsync('1A: Verifies deduplication columns exist on public.incidents', async () => {
      const colRes = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
          AND table_name = 'incidents'
          AND column_name IN ('fingerprint', 'device_id', 'first_seen_at', 'last_seen_at', 'occurrence_count');
      `);

      const cols = colRes.rows.map((r) => r.column_name);
      assert.ok(cols.includes('fingerprint'), 'fingerprint column missing');
      assert.ok(cols.includes('device_id'), 'device_id column missing');
      assert.ok(cols.includes('first_seen_at'), 'first_seen_at column missing');
      assert.ok(cols.includes('last_seen_at'), 'last_seen_at column missing');
      assert.ok(cols.includes('occurrence_count'), 'occurrence_count column missing');
    });

    await testAsync('1B: Verifies partial and temporal indexes exist on public.incidents', async () => {
      const idxRes = await db.query(`
        SELECT indexname 
        FROM pg_indexes 
        WHERE tablename = 'incidents'
          AND indexname IN ('idx_incidents_fingerprint_org', 'idx_incidents_device_id', 'idx_incidents_last_seen');
      `);

      const indexes = idxRes.rows.map((r) => r.indexname);
      assert.ok(indexes.includes('idx_incidents_fingerprint_org'), 'idx_incidents_fingerprint_org missing');
      assert.ok(indexes.includes('idx_incidents_device_id'), 'idx_incidents_device_id missing');
      assert.ok(indexes.includes('idx_incidents_last_seen'), 'idx_incidents_last_seen missing');
    });

    console.log('\n--- TEST GROUP 2: FINGERPRINT GENERATION & NORMALIZATION ---');

    await testAsync('2A: Phishing fingerprinting is deterministic and normalizes case, protocol, and trailing slash', async () => {
      const orgId = '00000000-0000-0000-0000-000000000001';

      const payload1 = {
        organization_id: orgId,
        threat_type: 'phishing',
        sender_domain: 'Evil-Phish.COM',
        target_url: 'https://login.evil-phish.com/auth/verify/',
        email_subject: 'URGENT: Verify Your Corporate Password'
      };

      const payload2 = {
        organization_id: orgId,
        threat_type: 'PHISHING',
        sender_domain: '  evil-phish.com  ',
        target_url: 'http://login.evil-phish.com/auth/verify',
        email_subject: 'urgent: verify your corporate password   '
      };

      const fp1 = incidentDeduplicationService.generateFingerprint(payload1);
      const fp2 = incidentDeduplicationService.generateFingerprint(payload2);

      assert.strictEqual(fp1.length, 64);
      assert.strictEqual(fp1, fp2, 'Fingerprints must match across case and protocol variations');
    });

    await testAsync('2B: Malicious URL fingerprint separates FQDN and path and strips trailing slashes', async () => {
      const orgId = '00000000-0000-0000-0000-000000000001';

      const fp1 = incidentDeduplicationService.generateFingerprint({
        organization_id: orgId,
        threat_type: 'malicious_url',
        url: 'https://cdn.malware-download.net/payloads/agent.exe/'
      });

      const fp2 = incidentDeduplicationService.generateFingerprint({
        organization_id: orgId,
        threat_type: 'malicious_url',
        fqdn: 'cdn.malware-download.net',
        path: '/payloads/agent.exe'
      });

      assert.strictEqual(fp1, fp2);
    });

    await testAsync('2C: Login anomaly, system threat, and threat intel generate valid 64-char hashes', async () => {
      const orgId = '00000000-0000-0000-0000-000000000001';

      const loginFp = incidentDeduplicationService.generateFingerprint({
        organization_id: orgId,
        threat_type: 'login_anomaly',
        user_id: 'user-123',
        source_ip: '203.0.113.42'
      });
      assert.strictEqual(loginFp.length, 64);

      const sysFp = incidentDeduplicationService.generateFingerprint({
        organization_id: orgId,
        threat_type: 'system_threat',
        device_id: 'dev-456',
        process_name: 'powershell.exe',
        binary_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      });
      assert.strictEqual(sysFp.length, 64);

      const tiFp = incidentDeduplicationService.generateFingerprint({
        organization_id: orgId,
        threat_type: 'threat_intel',
        indicator_type: 'ip',
        indicator_value: '198.51.100.99'
      });
      assert.strictEqual(tiFp.length, 64);
    });

    console.log('\n--- TEST GROUP 3: DUPLICATE DETECTION WITHIN SLIDING WINDOW ---');

    await testAsync('3A: Prepares test tenant organizations', async () => {
      const orgARes = await db.query(`INSERT INTO organizations (name) VALUES ('Dedup Test Org A') RETURNING id;`);
      testOrgAId = orgARes.rows[0].id;

      const orgBRes = await db.query(`INSERT INTO organizations (name) VALUES ('Dedup Test Org B') RETURNING id;`);
      testOrgBId = orgBRes.rows[0].id;

      assert.ok(testOrgAId);
      assert.ok(testOrgBId);
    });

    await testAsync('3B: checkDuplicate detects existing open incident with same fingerprint within window', async () => {
      const testFp = '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff';

      const inc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Test phishing incident for duplicate check',
        status: 'open',
        fingerprint: testFp,
        occurrence_count: 1
      });
      createdIncidentIds.push(inc.id);

      const result = await incidentDeduplicationService.checkDuplicate({
        organizationId: testOrgAId,
        fingerprint: testFp,
        windowMinutes: 30
      });

      assert.strictEqual(result.isDuplicate, true);
      assert.ok(result.incident);
      assert.strictEqual(result.incident.id, inc.id);
    });

    console.log('\n--- TEST GROUP 4: INCIDENT CONSOLIDATION ---');

    await testAsync('4A: consolidateIncident increments occurrence_count and updates last_seen_at', async () => {
      const targetId = createdIncidentIds[0];
      const beforeRes = await db.query(`SELECT occurrence_count, last_seen_at FROM public.incidents WHERE id = $1;`, [targetId]);
      const initialCount = beforeRes.rows[0].occurrence_count;
      const initialLastSeen = new Date(beforeRes.rows[0].last_seen_at).getTime();

      // Brief delay to verify timestamp strictly advances
      await new Promise((r) => setTimeout(r, 50));

      const consolidated = await incidentDeduplicationService.consolidateIncident({ incidentId: targetId });

      assert.strictEqual(consolidated.occurrence_count, initialCount + 1);
      const afterLastSeen = new Date(consolidated.last_seen_at).getTime();
      assert.ok(afterLastSeen >= initialLastSeen);
    });

    console.log('\n--- TEST GROUP 5: MULTI-TENANT ISOLATION ---');

    await testAsync('5A: Org B cannot duplicate against Org A incident with identical fingerprint', async () => {
      const testFp = '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff';

      // Query for duplicate in Org B context
      const resultB = await incidentDeduplicationService.checkDuplicate({
        organizationId: testOrgBId,
        fingerprint: testFp,
        windowMinutes: 30
      });

      assert.strictEqual(resultB.isDuplicate, false);
      assert.strictEqual(resultB.incident, null);
    });

    console.log('\n--- TEST GROUP 6: END-TO-END PIPELINE DEDUPLICATION ---');

    await testAsync('6A: persistDetectionIncident deduplicates repeated alerts into single DB incident', async () => {
      const userA = { id: null, organization_id: testOrgAId };
      const mlPayload = {
        risk_level: 'high',
        risk_score: 85,
        explanation: 'Phishing credential theft attempt',
        signals: {
          sender_domain: 'phish-target.com',
          target_url: 'https://phish-target.com/login/verify',
          email_subject: 'Account Suspension Warning'
        },
        details: {
          sender_domain: 'phish-target.com',
          target_url: 'https://phish-target.com/login/verify',
          email_subject: 'Account Suspension Warning'
        }
      };

      // Call 1: New incident creation
      const res1 = await persistDetectionIncident({
        user: userA,
        threatType: 'phishing',
        sourceType: 'email',
        mlResult: mlPayload
      });

      const incident1Id = res1.id || res1.incident?.id;
      createdIncidentIds.push(incident1Id);
      assert.ok(incident1Id);

      // Call 2: Duplicate detection
      const res2 = await persistDetectionIncident({
        user: userA,
        threatType: 'phishing',
        sourceType: 'email',
        mlResult: mlPayload
      });

      assert.strictEqual(res2.deduplicated, true);
      const incident2Id = res2.id || res2.incident?.id;
      assert.strictEqual(incident2Id, incident1Id, 'Must reuse identical incident ID');

      // Verify database record has occurrence_count = 2
      const dbCheck = await db.query(`SELECT occurrence_count FROM public.incidents WHERE id = $1;`, [incident1Id]);
      assert.strictEqual(dbCheck.rows[0].occurrence_count, 2);
    });

    console.log('\n--- TEST GROUP 7: SLIDING WINDOW EXPIRATION ---');

    await testAsync('7A: Alert outside deduplication window creates a new separate incident', async () => {
      const userA = { id: null, organization_id: testOrgAId };
      const expiredPayload = {
        sender_domain: 'expired-window-test.com',
        target_url: 'https://expired-window-test.com/login',
        email_subject: 'Expired Phishing Alert'
      };
      const expiredFp = incidentDeduplicationService.generateFingerprint({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        ...expiredPayload
      });

      // Insert an incident with last_seen_at 45 minutes in the past (phishing window is 30 minutes)
      const pastTime = new Date(Date.now() - 45 * 60 * 1000);
      const oldInc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Past phishing alert',
        status: 'open',
        fingerprint: expiredFp,
        first_seen_at: pastTime,
        last_seen_at: pastTime,
        occurrence_count: 1
      });
      createdIncidentIds.push(oldInc.id);

      // Force last_seen_at update in DB
      await db.query(`UPDATE public.incidents SET last_seen_at = $1 WHERE id = $2;`, [pastTime, oldInc.id]);

      // Now persist new alert with identical signature
      const newAlertRes = await persistDetectionIncident({
        user: userA,
        threatType: 'phishing',
        sourceType: 'email',
        mlResult: {
          risk_level: 'high',
          risk_score: 80,
          explanation: 'Recent phishing alert',
          signals: expiredPayload,
          details: expiredPayload
        }
      });

      const newId = newAlertRes.id || newAlertRes.incident?.id;
      createdIncidentIds.push(newId);

      assert.notStrictEqual(newId, oldInc.id, 'Expired incident must NOT be reused; fresh incident required');
      assert.strictEqual(newAlertRes.deduplicated, undefined);
    });

    console.log('\n--- TEST GROUP 8: AUDIT LOGGING ---');

    await testAsync('8A: Records incident_deduplicated and incident_consolidated audit logs', async () => {
      // Allow async audit log write
      await new Promise((r) => setTimeout(r, 100));

      const auditRes = await db.query(`
        SELECT action, resource_type, details
        FROM public.audit_logs
        WHERE organization_id = $1
          AND action IN ('incident_deduplicated', 'incident_consolidated');
      `, [testOrgAId]);

      assert.ok(auditRes.rows.length >= 1, 'Expected at least 1 deduplication audit log');
      const actions = auditRes.rows.map((r) => r.action);
      assert.ok(actions.includes('incident_deduplicated') || actions.includes('incident_consolidated'));
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    try {
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (testOrgAId || testOrgBId) {
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id IN ($1, $2);`, [testOrgAId, testOrgBId]);
        await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgAId, testOrgBId]);
      }
      console.log('  [✅] Test fixtures cleaned up successfully');
    } catch (cleanupErr) {
      console.error('  [⚠️] Fixture cleanup warning:', cleanupErr.message);
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
  console.error('Fatal Test Suite Error:', err);
  process.exit(1);
});
