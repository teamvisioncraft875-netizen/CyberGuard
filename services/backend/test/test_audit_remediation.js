process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');
const Incident = require('../src/models/Incident');
const IncidentGroup = require('../src/models/IncidentGroup');
const IncidentGroupMember = require('../src/models/IncidentGroupMember');
const AttackChainSnapshot = require('../src/models/AttackChainSnapshot');
const incidentDeduplicationService = require('../src/services/incidentDeduplicationService');
const riskScoringService = require('../src/services/riskScoringService');
const incidentPrioritizationService = require('../src/services/incidentPrioritizationService');
const incidentGroupingService = require('../src/services/incidentGroupingService');

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

let passed = 0;
let failed = 0;

async function testAsync(title, fn) {
  try {
    await fn();
    console.log(`  [✅] ${title}`);
    passed++;
  } catch (err) {
    console.error(`  [❌] ${title}:`, err.message);
    failed++;
  }
}

async function runAuditRemediationSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint Audit Remediation Regression Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgId;
  let testAdminToken;
  let testNoOrgToken;
  let testEmployeeToken;
  let incUnorg;

  const cleanupIncidents = [];
  const cleanupGroups = [];
  const cleanupSnapshots = [];
  const cleanupUsers = [];
  const cleanupOrgs = [];

  try {
    // Start ephemeral server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        resolve();
      });
    });

    // Create test fixtures
    const orgRes = await db.query(`INSERT INTO organizations (name) VALUES ('Audit Remediation Org') RETURNING id;`);
    testOrgId = orgRes.rows[0].id;
    cleanupOrgs.push(testOrgId);

    const userRes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'audit_admin@test.local', 'hash', 'admin') RETURNING id;`,
      [testOrgId]
    );
    const adminUserId = userRes.rows[0].id;
    cleanupUsers.push(adminUserId);

    testAdminToken = createToken({
      id: adminUserId,
      email: 'audit_admin@test.local',
      role: 'admin',
      organization_id: testOrgId
    });

    testNoOrgToken = createToken({
      id: adminUserId,
      email: 'no_org@test.local',
      role: 'admin',
      organization_id: null
    });

    testEmployeeToken = createToken({
      id: adminUserId,
      email: 'employee@test.local',
      role: 'employee',
      organization_id: testOrgId
    });

    // ========================================================================
    // FIX 1: DEDUPLICATION SQL PRECEDENCE
    // ========================================================================
    console.log('--- TEST FIX 1: Deduplication SQL Precedence ---');
    await testAsync('FIX 1: checkDuplicate correctly filters un-orged incident by fingerprint and status', async () => {
      incUnorg = await Incident.create({
        organization_id: null,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'medium',
        risk_score: 50,
        fingerprint: 'fp_unorg_test_123',
        status: 'open'
      });
      cleanupIncidents.push(incUnorg.id);

      // Check duplicate with matching fingerprint
      const dupMatch = await incidentDeduplicationService.checkDuplicate({
        organizationId: null,
        fingerprint: 'fp_unorg_test_123',
        windowMinutes: 60
      });
      assert.strictEqual(dupMatch.isDuplicate, true);
      assert.strictEqual(dupMatch.incident.id, incUnorg.id);

      // Check duplicate with non-matching fingerprint (must NOT return incUnorg due to SQL precedence)
      const nonMatch = await incidentDeduplicationService.checkDuplicate({
        organizationId: null,
        fingerprint: 'fp_completely_different',
        windowMinutes: 60
      });
      assert.strictEqual(nonMatch.isDuplicate, false);
      assert.strictEqual(nonMatch.incident, null);
    });

    // ========================================================================
    // FIX 2: MULTI-TENANT AUTHORIZATION BYPASS (req.user.organization_id == null)
    // ========================================================================
    console.log('\n--- TEST FIX 2: Multi-Tenant Authorization Enforcement ---');
    await testAsync('FIX 2.1: Attack Chain endpoint returns 403 when user has no organization_id', async () => {
      const res = await fetch(`${baseUrl}/incidents/${incUnorg.id}/attack-chain`, {
        headers: { Authorization: `Bearer ${testNoOrgToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('FIX 2.2: Incident Related endpoint returns 403 when user has no organization_id', async () => {
      const res = await fetch(`${baseUrl}/incidents/${incUnorg.id}/related`, {
        headers: { Authorization: `Bearer ${testNoOrgToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('FIX 2.3: Incident Groups list endpoint returns 403 when user has no organization_id', async () => {
      const res = await fetch(`${baseUrl}/incident-groups`, {
        headers: { Authorization: `Bearer ${testNoOrgToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    // ========================================================================
    // FIX 3: RISK SCORE FEEDBACK LOOP ELIMINATION
    // ========================================================================
    console.log('\n--- TEST FIX 3: Risk Score Stability (No Runaway Inflation) ---');
    await testAsync('FIX 3: Multiple risk recalculations preserve score stability using baseline_severity', async () => {
      const testInc = await Incident.create({
        organization_id: testOrgId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'medium',
        risk_score: 45,
        status: 'open'
      });
      cleanupIncidents.push(testInc.id);

      // Run calculation 1
      const res1 = await riskScoringService.calculateRiskScore(testInc.id, testOrgId);
      const score1 = res1.risk_score;

      // Run calculation 2
      const res2 = await riskScoringService.calculateRiskScore(testInc.id, testOrgId);
      const score2 = res2.risk_score;

      // Run calculation 3
      const res3 = await riskScoringService.calculateRiskScore(testInc.id, testOrgId);
      const score3 = res3.risk_score;

      assert.strictEqual(score1, score2, 'Score must be deterministic across run 1 and 2');
      assert.strictEqual(score2, score3, 'Score must not escalate on repeated recalculation without new evidence');
    });

    // ========================================================================
    // FIX 4: INCIDENT GROUP RBAC
    // ========================================================================
    console.log('\n--- TEST FIX 4: Incident Group RBAC Role Protection ---');
    await testAsync('FIX 4.1: GET /incident-groups rejects non-analyst/admin role with 403', async () => {
      const res = await fetch(`${baseUrl}/incident-groups`, {
        headers: { Authorization: `Bearer ${testEmployeeToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('FIX 4.2: GET /incident-groups/:id rejects non-analyst/admin role with 403', async () => {
      const res = await fetch(`${baseUrl}/incident-groups/${incUnorg.id}`, {
        headers: { Authorization: `Bearer ${testEmployeeToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    // ========================================================================
    // FIX 5: SNAPSHOT PRESERVATION DURING GROUP MERGE
    // ========================================================================
    console.log('\n--- TEST FIX 5: Snapshot Preservation During Group Merge ---');
    await testAsync('FIX 5: Merging groups migrates attack chain snapshots to surviving group', async () => {
      const incA = await Incident.create({
        organization_id: testOrgId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 75,
        status: 'open'
      });
      const incB = await Incident.create({
        organization_id: testOrgId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 80,
        status: 'open'
      });
      cleanupIncidents.push(incA.id, incB.id);

      // Create Group A and Group B
      const grpA = await IncidentGroup.create({
        organization_id: testOrgId,
        title: 'Group A',
        group_type: 'campaign',
        confidence_score: 0.90
      });
      const grpB = await IncidentGroup.create({
        organization_id: testOrgId,
        title: 'Group B',
        group_type: 'campaign',
        confidence_score: 0.80
      });
      cleanupGroups.push(grpA.id, grpB.id);

      await IncidentGroupMember.add({ group_id: grpA.id, incident_id: incA.id, added_by: 'rule_engine', confidence: 0.90 });
      await IncidentGroupMember.add({ group_id: grpB.id, incident_id: incB.id, added_by: 'rule_engine', confidence: 0.80 });

      // Create snapshot pointing to Group B (which will be orphan during merge because confA > confB)
      const snap = await AttackChainSnapshot.create({
        organization_id: testOrgId,
        root_incident_id: incB.id,
        attack_chain_group_id: grpB.id,
        confidence_score: 0.85,
        chain_length: 2,
        timeline: []
      });
      cleanupSnapshots.push(snap.id);

      // Merge groups via assignGroup
      await incidentGroupingService.assignGroup({
        sourceId: incA.id,
        targetId: incB.id,
        relationshipType: 'shares_ioc',
        confidence: 0.95,
        organizationId: testOrgId
      });

      // Verify snapshot was preserved and now points to surviving Group A
      const updatedSnap = await AttackChainSnapshot.findById(snap.id);
      assert.ok(updatedSnap, 'Snapshot must not be cascade deleted');
      assert.strictEqual(updatedSnap.attack_chain_group_id, grpA.id, 'Snapshot must be migrated to surviving group');
    });

    // ========================================================================
    // FIX 6: NO DUPLICATE INCIDENTS IN PRIORITY QUEUE
    // ========================================================================
    console.log('\n--- TEST FIX 6: No Duplicate Incidents in Prioritization Queue ---');
    await testAsync('FIX 6: Incidents with multiple group memberships return exactly one row in queue', async () => {
      const multiInc = await Incident.create({
        organization_id: testOrgId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'critical',
        risk_score: 95,
        priority: 'P1',
        status: 'open'
      });
      cleanupIncidents.push(multiInc.id);

      // Add to two different groups
      const g1 = await IncidentGroup.create({ organization_id: testOrgId, title: 'Multi G1', group_type: 'campaign' });
      const g2 = await IncidentGroup.create({ organization_id: testOrgId, title: 'Multi G2', group_type: 'campaign' });
      cleanupGroups.push(g1.id, g2.id);

      await IncidentGroupMember.add({ group_id: g1.id, incident_id: multiInc.id, added_by: 'rule_engine', confidence: 0.9 });
      await IncidentGroupMember.add({ group_id: g2.id, incident_id: multiInc.id, added_by: 'rule_engine', confidence: 0.9 });

      // Query prioritized incidents and queue
      const prioritized = await incidentPrioritizationService.getPrioritizedIncidents(testOrgId, { limit: 10 });
      const matchingPrioritized = prioritized.filter(i => i.id === multiInc.id);
      assert.strictEqual(matchingPrioritized.length, 1, 'Incident must appear exactly once in getPrioritizedIncidents');

      const queue = await incidentPrioritizationService.getQueue(testOrgId, { limit: 10 });
      const matchingQueue = queue.filter(i => i.id === multiInc.id);
      assert.strictEqual(matchingQueue.length, 1, 'Incident must appear exactly once in getQueue');
    });

  } finally {
    console.log('\n--- CLEANUP ---');
    if (server) {
      server.close();
    }
    try {
      if (cleanupSnapshots.length > 0) {
        await db.query(`DELETE FROM public.attack_chain_snapshots WHERE id = ANY($1::uuid[]);`, [cleanupSnapshots]);
      }
      if (cleanupGroups.length > 0) {
        await db.query(`DELETE FROM public.incident_group_members WHERE group_id = ANY($1::uuid[]);`, [cleanupGroups]);
        await db.query(`DELETE FROM public.incident_groups WHERE id = ANY($1::uuid[]);`, [cleanupGroups]);
      }
      if (cleanupIncidents.length > 0) {
        await db.query(`DELETE FROM public.incident_relationships WHERE source_incident_id = ANY($1::uuid[]) OR target_incident_id = ANY($1::uuid[]);`, [cleanupIncidents]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [cleanupIncidents]);
      }
      if (cleanupUsers.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [cleanupUsers]);
      }
      if (cleanupOrgs.length > 0) {
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [cleanupOrgs]);
      }
      console.log('  [✅] Cleanup completed successfully');
    } catch (cleanErr) {
      console.error('  [⚠️] Cleanup warning:', cleanErr.message);
    }
  }

  console.log('\n========================================================================');
  console.log(`REMEDIATION RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAuditRemediationSuite().catch((err) => {
  console.error('Fatal Suite Error:', err);
  process.exit(1);
});
