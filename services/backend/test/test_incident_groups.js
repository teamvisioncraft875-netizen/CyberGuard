process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');
const Incident = require('../src/models/Incident');
const IncidentRelationship = require('../src/models/IncidentRelationship');
const IncidentGroup = require('../src/models/IncidentGroup');
const IncidentGroupMember = require('../src/models/IncidentGroupMember');
const DetectionSignal = require('../src/models/DetectionSignal');
const incidentGroupingService = require('../src/services/incidentGroupingService');
const incidentCorrelationService = require('../src/services/incidentCorrelationService');
const { persistDetectionIncident } = require('../src/services/incidentService');

/**
 * CYBERGUARD — Task 3: Incident Groups & Campaign Aggregation Test Suite
 *
 * Validates:
 * A. Migration exists and applies
 * B. Tables and constraints exist
 * C. Group creation from first relationship (Rule G1-G5)
 * D. Member attachment
 * E. Duplicate memberships prevented
 * F. Group merge works (preserves higher severity / confidence / older created_at)
 * G. Aggregate metrics correct
 * H. Tenant isolation enforced
 * I. GET /api/v1/incident-groups works
 * J. GET /api/v1/incident-groups/:id works
 * K. POST /api/v1/incident-groups/:id/resolve resolves group and member incidents
 * L. Audit logs recorded
 * M. Pipeline integration creates groups automatically after correlation
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
  console.log('CYBERGUARD — Task 3: Incident Groups & Campaign Aggregation Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgAId = null;
  let testOrgBId = null;
  let testUserAId = null;
  let testUserBId = null;

  const createdIncidentIds = [];
  const createdGroupIds = [];
  const createdOrgIds = [];
  const createdUserIds = [];

  try {
    // Start ephemeral HTTP server for API controller tests
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}/api/v1`;
        console.log(`[INIT] Test server running on ${baseUrl}\n`);
        resolve();
      });
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART A: MIGRATION APPLIED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP A: MIGRATION APPLIED ---');

    await testAsync('A1: Migration file 027_incident_groups.sql exists on disk', async () => {
      const migrationPath = path.resolve(__dirname, '../sql/027_incident_groups.sql');
      assert.ok(fs.existsSync(migrationPath), 'Migration file 027 must exist on disk');
      const content = fs.readFileSync(migrationPath, 'utf8');
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.incident_groups'), 'Must contain incident_groups table definition');
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.incident_group_members'), 'Must contain incident_group_members table definition');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART B: TABLES AND CONSTRAINTS EXIST
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP B: TABLES AND CONSTRAINTS ---');

    await testAsync('B1: Table incident_groups exists with all required columns and constraints', async () => {
      const colRes = await db.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'incident_groups';
      `);

      const cols = colRes.rows.map(r => r.column_name);
      assert.ok(cols.includes('id'), 'id missing');
      assert.ok(cols.includes('organization_id'), 'organization_id missing');
      assert.ok(cols.includes('title'), 'title missing');
      assert.ok(cols.includes('description'), 'description missing');
      assert.ok(cols.includes('group_type'), 'group_type missing');
      assert.ok(cols.includes('status'), 'status missing');
      assert.ok(cols.includes('severity'), 'severity missing');
      assert.ok(cols.includes('confidence_score'), 'confidence_score missing');
      assert.ok(cols.includes('primary_incident_id'), 'primary_incident_id missing');
      assert.ok(cols.includes('metadata'), 'metadata missing');
      assert.ok(cols.includes('created_at'), 'created_at missing');
      assert.ok(cols.includes('updated_at'), 'updated_at missing');
    });

    await testAsync('B2: Table incident_group_members exists with uniqueness constraint', async () => {
      const colRes = await db.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'incident_group_members';
      `);

      const cols = colRes.rows.map(r => r.column_name);
      assert.ok(cols.includes('id'), 'id missing');
      assert.ok(cols.includes('group_id'), 'group_id missing');
      assert.ok(cols.includes('incident_id'), 'incident_id missing');
      assert.ok(cols.includes('added_by'), 'added_by missing');
      assert.ok(cols.includes('confidence'), 'confidence missing');
      assert.ok(cols.includes('joined_at'), 'joined_at missing');

      const constRes = await db.query(`
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE table_name = 'incident_group_members';
      `);
      const constraints = constRes.rows.map(r => r.constraint_name);
      assert.ok(constraints.includes('uq_group_incident_membership'), 'uq_group_incident_membership missing');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SETUP TEST FIXTURES
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- SETUP TEST FIXTURES ---');

    const orgARes = await db.query(`INSERT INTO organizations (name) VALUES ('Grouping Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO organizations (name) VALUES ('Grouping Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'admin_a@group.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const userBRes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'admin_b@group.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    console.log('  [✅] Base test fixtures created (Org A, Org B, Admin Users)');

    // ──────────────────────────────────────────────────────────────────────────
    // PART C: GROUP CREATION FROM FIRST RELATIONSHIP
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP C: GROUP CREATION FROM FIRST RELATIONSHIP ---');

    let group1Id = null;
    let inc1Id = null;
    let inc2Id = null;

    await testAsync('C1: Case 1: creates new campaign group when linking two unassigned incidents with shares_ioc', async () => {
      const inc1 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Inc 1 for campaign grouping',
        status: 'open'
      });
      inc1Id = inc1.id;
      createdIncidentIds.push(inc1Id);

      const inc2 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'critical',
        risk_score: 95,
        explanation: 'Inc 2 for campaign grouping',
        status: 'open'
      });
      inc2Id = inc2.id;
      createdIncidentIds.push(inc2Id);

      // Link incidents with shares_ioc
      const edge = await incidentCorrelationService.linkIncidents({
        sourceId: inc1Id,
        targetId: inc2Id,
        type: 'shares_ioc',
        confidence: 0.95,
        organizationId: testOrgAId
      });
      assert.ok(edge, 'Correlation edge must be created');

      // Verify group was created automatically
      const memberGroup = await IncidentGroupMember.findGroupByIncident(inc1Id);
      assert.ok(memberGroup, 'Inc 1 must now belong to an incident group');
      assert.strictEqual(memberGroup.group_type, 'campaign');
      assert.strictEqual(parseFloat(memberGroup.confidence_score), 0.95);
      assert.strictEqual(memberGroup.primary_incident_id, inc1Id);
      assert.strictEqual(memberGroup.severity, 'critical', 'Severity must reflect the higher incident risk_level');

      group1Id = memberGroup.id;
      createdGroupIds.push(group1Id);

      // Verify both incidents are members
      const members = await IncidentGroupMember.findByGroup(group1Id);
      assert.strictEqual(members.length, 2);
      const memberIncidentIds = members.map(m => m.incident_id);
      assert.ok(memberIncidentIds.includes(inc1Id));
      assert.ok(memberIncidentIds.includes(inc2Id));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART D: MEMBER ATTACHMENT
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP D: MEMBER ATTACHMENT ---');

    let inc3Id = null;

    await testAsync('D1: Case 2: attaches unassigned incident to existing group when correlating with a member', async () => {
      const inc3 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'technical_threat',
        source_type: 'telemetry',
        risk_level: 'high',
        risk_score: 75,
        explanation: 'Inc 3 attached to campaign',
        status: 'open'
      });
      inc3Id = inc3.id;
      createdIncidentIds.push(inc3Id);

      // Link inc2 with inc3
      const edge = await incidentCorrelationService.linkIncidents({
        sourceId: inc2Id,
        targetId: inc3Id,
        type: 'same_infrastructure',
        confidence: 0.90,
        organizationId: testOrgAId
      });
      assert.ok(edge);

      // Verify inc3 is now part of group1Id
      const inc3Group = await IncidentGroupMember.findGroupByIncident(inc3Id);
      assert.ok(inc3Group);
      assert.strictEqual(inc3Group.id, group1Id);

      const members = await IncidentGroupMember.findByGroup(group1Id);
      assert.strictEqual(members.length, 3);
      assert.ok(members.map(m => m.incident_id).includes(inc3Id));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART E: DUPLICATE MEMBERSHIPS PREVENTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP E: DUPLICATE MEMBERSHIPS PREVENTED ---');

    await testAsync('E1: Duplicate membership additions are handled idempotently via ON CONFLICT DO NOTHING', async () => {
      const dup = await IncidentGroupMember.add({
        group_id: group1Id,
        incident_id: inc1Id,
        added_by: 'rule_engine',
        confidence: 1.000
      });
      assert.strictEqual(dup, null, 'Duplicate add must return null and not throw');

      const exists = await IncidentGroupMember.exists(group1Id, inc1Id);
      assert.strictEqual(exists, true);

      const members = await IncidentGroupMember.findByGroup(group1Id);
      assert.strictEqual(members.length, 3, 'Member count must remain 3');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART F: GROUP MERGE WORKS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP F: GROUP MERGE ---');

    let group2Id = null;
    let inc4Id = null;
    let inc5Id = null;

    await testAsync('F1: Case 4: merges two existing groups when an incident from Group A correlates with Group B', async () => {
      // Create separate incidents for Group 2
      const inc4 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'account_takeover',
        source_type: 'login',
        risk_level: 'medium',
        risk_score: 50,
        explanation: 'Inc 4 in separate cluster',
        status: 'open'
      });
      inc4Id = inc4.id;
      createdIncidentIds.push(inc4Id);

      const inc5 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'medium',
        risk_score: 55,
        explanation: 'Inc 5 in separate cluster',
        status: 'open'
      });
      inc5Id = inc5.id;
      createdIncidentIds.push(inc5Id);

      // Link inc4 and inc5 to create Group 2
      await incidentCorrelationService.linkIncidents({
        sourceId: inc4Id,
        targetId: inc5Id,
        type: 'same_user_campaign',
        confidence: 0.80,
        organizationId: testOrgAId
      });

      const group2 = await IncidentGroupMember.findGroupByIncident(inc4Id);
      assert.ok(group2);
      assert.notStrictEqual(group2.id, group1Id);
      group2Id = group2.id;
      createdGroupIds.push(group2Id);

      // Verify Group 2 has 2 members
      const g2MembersBefore = await IncidentGroupMember.findByGroup(group2Id);
      assert.strictEqual(g2MembersBefore.length, 2);

      // Now correlate inc1 (from Group 1) with inc4 (from Group 2)
      // Group 1 has severity 'critical' while Group 2 has 'medium', so Group 1 must be survivor!
      await incidentCorrelationService.linkIncidents({
        sourceId: inc1Id,
        targetId: inc4Id,
        type: 'same_attacker_ip',
        confidence: 0.85,
        organizationId: testOrgAId
      });

      // Verify Group 2 was merged and deleted
      const orphanCheck = await IncidentGroup.findById(group2Id);
      assert.strictEqual(orphanCheck, null, 'Orphan group must be deleted after merge');

      // Verify surviving Group 1 now contains all 5 incidents
      const survivingMembers = await IncidentGroupMember.findByGroup(group1Id);
      assert.strictEqual(survivingMembers.length, 5, 'Surviving group must contain all 5 merged member incidents');
      const allIds = survivingMembers.map(m => m.incident_id);
      assert.ok(allIds.includes(inc1Id));
      assert.ok(allIds.includes(inc2Id));
      assert.ok(allIds.includes(inc3Id));
      assert.ok(allIds.includes(inc4Id));
      assert.ok(allIds.includes(inc5Id));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART G: AGGREGATE METRICS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP G: AGGREGATE METRICS ---');

    await testAsync('G1: getGroupMetrics returns incident_count, high_risk_count, critical_count, avg_score, latest_activity', async () => {
      const metrics = await incidentGroupingService.getGroupMetrics(group1Id);
      assert.strictEqual(metrics.incident_count, 5);
      assert.strictEqual(metrics.critical_count, 1); // inc2 (95)
      assert.strictEqual(metrics.high_risk_count, 2); // inc1 (80), inc3 (75)
      assert.ok(metrics.average_risk_score > 0);
      assert.ok(metrics.latest_activity);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART H: TENANT ISOLATION ENFORCED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP H: TENANT ISOLATION ENFORCED ---');

    await testAsync('H1: assignGroup strictly respects tenant boundaries and prevents cross-tenant grouping', async () => {
      const incB = await Incident.create({
        organization_id: testOrgBId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        status: 'open'
      });
      createdIncidentIds.push(incB.id);

      const crossAttempt = await incidentGroupingService.assignGroup({
        sourceId: inc1Id, // Org A
        targetId: incB.id, // Org B
        relationshipType: 'shares_ioc',
        confidence: 0.95
      });

      assert.strictEqual(crossAttempt, null, 'Must refuse to create cross-tenant group');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART I: QUERY API GET /api/v1/incident-groups
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP I: QUERY API LIST GROUPS ---');

    await testAsync('I1: GET /api/v1/incident-groups returns groups list with metrics for tenant', async () => {
      const tokenA = createToken({
        id: testUserAId,
        email: 'admin_a@group.test',
        role: 'admin',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incident-groups`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.groups));
      assert.ok(data.groups.length >= 1);

      const foundGroup = data.groups.find(g => g.id === group1Id);
      assert.ok(foundGroup);
      assert.strictEqual(foundGroup.group_type, 'campaign');
      assert.ok(foundGroup.metrics);
      assert.strictEqual(foundGroup.metrics.incident_count, 5);
    });

    await testAsync('I2: User from Org B sees 0 groups for Org A (tenant isolation)', async () => {
      const tokenB = createToken({
        id: testUserBId,
        email: 'admin_b@group.test',
        role: 'admin',
        organization_id: testOrgBId
      });

      const res = await fetch(`${baseUrl}/incident-groups`, {
        headers: { Authorization: `Bearer ${tokenB}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.groups.length, 0);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART J: QUERY API GET /api/v1/incident-groups/:id
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP J: QUERY API GET GROUP DETAIL ---');

    await testAsync('J1: GET /api/v1/incident-groups/:id returns group, members, and metrics', async () => {
      const tokenA = createToken({
        id: testUserAId,
        email: 'admin_a@group.test',
        role: 'admin',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incident-groups/${group1Id}`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.group);
      assert.strictEqual(data.group.id, group1Id);
      assert.ok(Array.isArray(data.members));
      assert.strictEqual(data.members.length, 5);
      assert.ok(data.metrics);
      assert.strictEqual(data.metrics.incident_count, 5);
    });

    await testAsync('J2: Org B requesting Org A group returns 404 Not Found', async () => {
      const tokenB = createToken({
        id: testUserBId,
        email: 'admin_b@group.test',
        role: 'admin',
        organization_id: testOrgBId
      });

      const res = await fetch(`${baseUrl}/incident-groups/${group1Id}`, {
        headers: { Authorization: `Bearer ${tokenB}` }
      });

      assert.strictEqual(res.status, 404);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART K: GROUP RESOLUTION WORKFLOW
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP K: GROUP RESOLUTION WORKFLOW ---');

    await testAsync('K1: POST /api/v1/incident-groups/:id/resolve resolves group and member incidents atomically', async () => {
      const tokenA = createToken({
        id: testUserAId,
        email: 'admin_a@group.test',
        role: 'admin',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incident-groups/${group1Id}/resolve`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.group.status, 'resolved');
      assert.strictEqual(data.resolved_incidents_count, 5);

      // Verify in DB that group status is 'resolved'
      const updatedGroup = await IncidentGroup.findById(group1Id);
      assert.strictEqual(updatedGroup.status, 'resolved');

      // Verify in DB that all member incidents have status 'resolved'
      const incCheck = await db.query(
        `SELECT id, status FROM public.incidents WHERE id = ANY($1::uuid[]);`,
        [[inc1Id, inc2Id, inc3Id, inc4Id, inc5Id]]
      );
      assert.strictEqual(incCheck.rows.length, 5);
      for (const row of incCheck.rows) {
        assert.strictEqual(row.status, 'resolved', `Incident ${row.id} must be marked resolved`);
      }
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART L: AUDIT LOGS RECORDED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP L: AUDIT LOGS RECORDED ---');

    await testAsync('L1: Audit logs exist for INCIDENT_GROUP_CREATED, INCIDENT_GROUP_MEMBER_ADDED, INCIDENT_GROUP_MERGED, INCIDENT_GROUP_RESOLVED', async () => {
      const auditRes = await db.query(
        `SELECT action FROM public.audit_logs
         WHERE organization_id = $1
           AND action IN ('INCIDENT_GROUP_CREATED', 'INCIDENT_GROUP_MEMBER_ADDED', 'INCIDENT_GROUP_MERGED', 'INCIDENT_GROUP_RESOLVED');`,
        [testOrgAId]
      );

      assert.ok(auditRes.rows.length >= 4, 'Must have recorded multiple incident group audit logs');
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('INCIDENT_GROUP_CREATED'), 'INCIDENT_GROUP_CREATED missing');
      assert.ok(actions.includes('INCIDENT_GROUP_MEMBER_ADDED'), 'INCIDENT_GROUP_MEMBER_ADDED missing');
      assert.ok(actions.includes('INCIDENT_GROUP_MERGED'), 'INCIDENT_GROUP_MERGED missing');
      assert.ok(actions.includes('INCIDENT_GROUP_RESOLVED'), 'INCIDENT_GROUP_RESOLVED missing');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART M: PIPELINE INTEGRATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP M: PIPELINE INTEGRATION AUTOMATIC GROUPING ---');

    await testAsync('M1: persistDetectionIncident automatically assigns new incident into an incident group via correlation', async () => {
      const userA = { id: testUserAId, organization_id: testOrgAId, role: 'admin' };

      // Base incident in Org A
      const baseInc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Base pipeline grouping incident',
        status: 'open'
      });
      createdIncidentIds.push(baseInc.id);
      await DetectionSignal.create({ incident_id: baseInc.id, signal_name: 'source_ip', signal_value: '198.51.100.250' });

      // Run persistDetectionIncident with matching attacker IP
      const autoCreated = await persistDetectionIncident({
        user: userA,
        threatType: 'technical_threat',
        sourceType: 'telemetry',
        mlResult: {
          risk_level: 'high',
          risk_score: 85,
          explanation: 'Correlated telemetry alert',
          signals: {
            source_ip: '198.51.100.250'
          },
          details: {
            process_id: 'proc-999'
          }
        }
      });

      assert.ok(autoCreated && autoCreated.id);
      createdIncidentIds.push(autoCreated.id);

      // Verify that an incident group was automatically created for this correlation
      const autoGroup = await IncidentGroupMember.findGroupByIncident(autoCreated.id);
      assert.ok(autoGroup, 'Automatically correlated incident must belong to an incident group');
      createdGroupIds.push(autoGroup.id);
      assert.strictEqual(autoGroup.group_type, 'distributed_attack', 'IP correlation must map to distributed_attack group_type');

      const members = await IncidentGroupMember.findByGroup(autoGroup.id);
      const memberIds = members.map(m => m.incident_id);
      assert.ok(memberIds.includes(baseInc.id));
      assert.ok(memberIds.includes(autoCreated.id));
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdGroupIds.length > 0) {
        await db.query(`DELETE FROM public.incident_group_members WHERE group_id = ANY($1::uuid[]);`, [createdGroupIds]);
        await db.query(`DELETE FROM public.incident_groups WHERE id = ANY($1::uuid[]);`, [createdGroupIds]);
      }
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.incident_relationships WHERE source_incident_id = ANY($1::uuid[]) OR target_incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incident_ioc_matches WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (createdUserIds.length > 0) {
        await db.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [createdUserIds]);
      }
      if (createdOrgIds.length > 0) {
        await db.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1::uuid[]);`, [createdOrgIds]);
        await db.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [createdOrgIds]);
      }
      console.log('  [✅] Fixtures cleaned up successfully');
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
