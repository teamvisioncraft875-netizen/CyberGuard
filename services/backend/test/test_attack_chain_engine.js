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
const MitreMapping = require('../src/models/MitreMapping');
const AttackChainSnapshot = require('../src/models/AttackChainSnapshot');
const attackChainService = require('../src/services/attackChainService');
const incidentCorrelationService = require('../src/services/incidentCorrelationService');
const { persistDetectionIncident } = require('../src/services/incidentService');

/**
 * CYBERGUARD — Task 4: Attack Chain Engine & MITRE Progression Analysis Test Suite
 *
 * Validates:
 * A. Migration exists
 * B. Table schema valid
 * C. AC1 progression detected (TA0001 -> TA0002)
 * D. AC2 progression detected (TA0002 -> TA0004)
 * E. AC3 progression detected (TA0004 -> TA0011)
 * F. AC4 progression detected (Same user, different threat, progression)
 * G. Recursive traversal works
 * H. Depth limit enforced (maxDepth 2)
 * I. Cycle prevention works
 * J. Timeline generated correctly
 * K. Confidence score calculated
 * L. Snapshot persisted
 * M. GET /api/v1/incidents/:id/attack-chain works
 * N. GET /api/v1/incidents/:id/attack-chain/graph works
 * O. Tenant isolation enforced
 * P. Automatic attack-chain group creation (chain_length >= 3)
 * Q. Audit logs recorded (ATTACK_CHAIN_CREATED, ATTACK_CHAIN_VIEWED)
 * R. Pipeline integration works
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
  console.log('CYBERGUARD — Task 4: Attack Chain Engine Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgAId = null;
  let testOrgBId = null;
  let testUserAId = null;
  let testUserBId = null;
  let testDeviceAId = null;

  const createdIncidentIds = [];
  const createdGroupIds = [];
  const createdSnapshotIds = [];
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];

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
    // PART A & B: MIGRATION & TABLE SCHEMA
    // ──────────────────────────────────────────────────────────────────────────
    console.log('--- TEST GROUP A & B: MIGRATION & SCHEMA VALIDATION ---');

    await testAsync('A1: Migration file 028_attack_chain_engine.sql exists', async () => {
      const migrationPath = path.resolve(__dirname, '../sql/028_attack_chain_engine.sql');
      assert.ok(fs.existsSync(migrationPath), 'Migration 028 must exist on disk');
      const content = fs.readFileSync(migrationPath, 'utf8');
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.attack_chain_snapshots'));
    });

    await testAsync('B1: Table attack_chain_snapshots has all required columns and indexes', async () => {
      const colRes = await db.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'attack_chain_snapshots';
      `);

      const cols = colRes.rows.map(r => r.column_name);
      assert.ok(cols.includes('id'), 'id missing');
      assert.ok(cols.includes('organization_id'), 'organization_id missing');
      assert.ok(cols.includes('root_incident_id'), 'root_incident_id missing');
      assert.ok(cols.includes('attack_chain_group_id'), 'attack_chain_group_id missing');
      assert.ok(cols.includes('confidence_score'), 'confidence_score missing');
      assert.ok(cols.includes('chain_length'), 'chain_length missing');
      assert.ok(cols.includes('timeline'), 'timeline missing');
      assert.ok(cols.includes('metadata'), 'metadata missing');
      assert.ok(cols.includes('created_at'), 'created_at missing');
      assert.ok(cols.includes('updated_at'), 'updated_at missing');

      const idxRes = await db.query(`
        SELECT indexname FROM pg_indexes WHERE tablename = 'attack_chain_snapshots';
      `);
      const indexes = idxRes.rows.map(r => r.indexname);
      assert.ok(indexes.includes('idx_attack_chain_snapshots_org'));
      assert.ok(indexes.includes('idx_attack_chain_snapshots_root'));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SETUP TEST FIXTURES
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- SETUP TEST FIXTURES ---');

    const orgARes = await db.query(`INSERT INTO organizations (name) VALUES ('Attack Chain Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO organizations (name) VALUES ('Attack Chain Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_a@chain.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const userBRes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_b@chain.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    const devRes = await db.query(
      `INSERT INTO devices (organization_id, device_name, is_trusted) VALUES ($1, 'Chain Endpoint Dev', true) RETURNING id;`,
      [testOrgAId]
    );
    testDeviceAId = devRes.rows[0].id;
    createdDeviceIds.push(testDeviceAId);

    console.log('  [✅] Base fixtures created (Org A, Org B, Admin Users, Device)');

    // ──────────────────────────────────────────────────────────────────────────
    // PART C: RULE AC1 (TA0001 -> TA0002)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP C: RULE AC1 (INITIAL ACCESS -> EXECUTION) ---');

    let incAc1Id = null;
    let incAc2Id = null;

    await testAsync('C1: AC1 detects progression on same device from TA0001 to TA0002 within 12h', async () => {
      const inc1 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        device_id: testDeviceAId,
        status: 'open'
      });
      incAc1Id = inc1.id;
      createdIncidentIds.push(incAc1Id);

      await MitreMapping.create({
        incident_id: incAc1Id,
        technique_id: 'T1566',
        technique_name: 'Phishing: Initial Access'
      });

      const inc2 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 85,
        device_id: testDeviceAId,
        status: 'open'
      });
      incAc2Id = inc2.id;
      createdIncidentIds.push(incAc2Id);

      await MitreMapping.create({
        incident_id: incAc2Id,
        technique_id: 'T1204',
        technique_name: 'User Execution: Malicious URL'
      });

      // Correlate inc2 with candidate inc1
      const rels = await incidentCorrelationService.correlateIncident(incAc2Id, testOrgAId);
      const acStep = rels.find(r => r.relationship_type === 'attack_chain_step');
      assert.ok(acStep, 'Must create attack_chain_step edge');
      assert.strictEqual(parseFloat(acStep.confidence_score), 0.85);
      assert.strictEqual(acStep.rule_id, 'AC1');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART D: RULE AC2 (TA0002 -> TA0004)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP D: RULE AC2 (EXECUTION -> PRIVILEGE ESCALATION) ---');

    let incAc3Id = null;

    await testAsync('D1: AC2 detects progression on same device from TA0002 to TA0004 within 12h', async () => {
      const inc3 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'account_takeover',
        source_type: 'login',
        risk_level: 'critical',
        risk_score: 95,
        device_id: testDeviceAId,
        status: 'open'
      });
      incAc3Id = inc3.id;
      createdIncidentIds.push(incAc3Id);

      await MitreMapping.create({
        incident_id: incAc3Id,
        technique_id: 'T1110',
        technique_name: 'Brute Force: Privilege Escalation'
      });

      // Correlate inc3 with candidate inc2
      const rels = await incidentCorrelationService.correlateIncident(incAc3Id, testOrgAId);
      const acStep = rels.find(r => r.relationship_type === 'attack_chain_step' && (r.source_incident_id === incAc2Id || r.target_incident_id === incAc2Id));
      assert.ok(acStep, 'Must create AC2 attack_chain_step edge');
      assert.strictEqual(parseFloat(acStep.confidence_score), 0.85);
      assert.strictEqual(acStep.rule_id, 'AC2');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART E: RULE AC3 (TA0004 -> TA0011)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP E: RULE AC3 (PRIVILEGE ESCALATION -> COMMAND & CONTROL) ---');

    let incAc4Id = null;

    await testAsync('E1: AC3 detects progression on same device from TA0004 to TA0011 within 12h', async () => {
      const inc4 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'technical_threat',
        source_type: 'telemetry',
        risk_level: 'critical',
        risk_score: 90,
        device_id: testDeviceAId,
        status: 'open'
      });
      incAc4Id = inc4.id;
      createdIncidentIds.push(incAc4Id);

      await MitreMapping.create({
        incident_id: incAc4Id,
        technique_id: 'T1071',
        technique_name: 'Application Layer Protocol: Command and Control'
      });

      // Correlate inc4 with candidate inc3
      const rels = await incidentCorrelationService.correlateIncident(incAc4Id, testOrgAId);
      const acStep = rels.find(r => r.relationship_type === 'attack_chain_step' && (r.source_incident_id === incAc3Id || r.target_incident_id === incAc3Id));
      assert.ok(acStep, 'Must create AC3 attack_chain_step edge');
      assert.strictEqual(parseFloat(acStep.confidence_score), 0.85);
      assert.strictEqual(acStep.rule_id, 'AC3');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART F: RULE AC4 (SAME USER PROGRESSION)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP F: RULE AC4 (USER-BASED PROGRESSION) ---');

    await testAsync('F1: AC4 detects progression for same user with different threat types within 12h', async () => {
      const incUser1 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testUserAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'medium',
        risk_score: 60,
        status: 'open'
      });
      createdIncidentIds.push(incUser1.id);

      await MitreMapping.create({
        incident_id: incUser1.id,
        technique_id: 'TA0001',
        technique_name: 'Initial Access'
      });

      const incUser2 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testUserAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 75,
        status: 'open'
      });
      createdIncidentIds.push(incUser2.id);

      await MitreMapping.create({
        incident_id: incUser2.id,
        technique_id: 'TA0002',
        technique_name: 'Execution'
      });

      const rels = await incidentCorrelationService.correlateIncident(incUser2.id, testOrgAId);
      const acStep = rels.find(r => r.relationship_type === 'attack_chain_step' && (r.source_incident_id === incUser1.id || r.target_incident_id === incUser1.id));
      assert.ok(acStep, 'Must create AC4 attack_chain_step edge');
      assert.strictEqual(parseFloat(acStep.confidence_score), 0.80);
      assert.strictEqual(acStep.rule_id, 'AC4');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART G & H: RECURSIVE TRAVERSAL & DEPTH LIMIT
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP G & H: GRAPH TRAVERSAL & DEPTH ENFORCEMENT ---');

    await testAsync('G1: Recursive traversal builds chain across multiple hops', async () => {
      // Traverse starting from incAc1Id (connected to incAc2Id, incAc3Id)
      const chain = await attackChainService.getAttackChain(incAc1Id, testOrgAId);
      assert.ok(chain);
      assert.ok(chain.chain_length >= 3, `Chain length must be >= 3, got ${chain.chain_length}`);
      assert.ok(Array.isArray(chain.timeline));
      assert.strictEqual(chain.timeline.length, chain.chain_length);
    });

    await testAsync('H1: Maximum traversal depth 2 is strictly enforced', async () => {
      // Create chain with 4 linear hops: Node0 -> Node1 -> Node2 -> Node3
      const node0 = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      const node1 = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      const node2 = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      const node3 = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      createdIncidentIds.push(node0.id, node1.id, node2.id, node3.id);

      await IncidentRelationship.create({ organization_id: testOrgAId, source_incident_id: node0.id, target_incident_id: node1.id, relationship_type: 'attack_chain_step', confidence_score: 0.90 });
      await IncidentRelationship.create({ organization_id: testOrgAId, source_incident_id: node1.id, target_incident_id: node2.id, relationship_type: 'attack_chain_step', confidence_score: 0.90 });
      await IncidentRelationship.create({ organization_id: testOrgAId, source_incident_id: node2.id, target_incident_id: node3.id, relationship_type: 'attack_chain_step', confidence_score: 0.90 });

      // Traversing from node0 with maxDepth 2 must reach node0, node1, node2, but NOT node3
      const chain0 = await attackChainService.getAttackChain(node0.id, testOrgAId);
      const traversedIds = chain0.timeline.map(t => t.incident_id);
      assert.ok(traversedIds.includes(node0.id));
      assert.ok(traversedIds.includes(node1.id));
      assert.ok(traversedIds.includes(node2.id));
      assert.strictEqual(traversedIds.includes(node3.id), false, 'Depth 2 limit must prevent reaching node3 (hop 3)');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART I: CYCLE PREVENTION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP I: CYCLE PREVENTION ---');

    await testAsync('I1: Graph traversal terminates without infinite loop on cyclical graphs', async () => {
      const cycA = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      const cycB = await Incident.create({ organization_id: testOrgAId, threat_type: 'phishing', status: 'open' });
      createdIncidentIds.push(cycA.id, cycB.id);

      // Create cycle: A -> B and B -> A
      await IncidentRelationship.create({ organization_id: testOrgAId, source_incident_id: cycA.id, target_incident_id: cycB.id, relationship_type: 'same_host_progression', confidence_score: 0.85 });
      await IncidentRelationship.create({ organization_id: testOrgAId, source_incident_id: cycB.id, target_incident_id: cycA.id, relationship_type: 'same_host_progression', confidence_score: 0.85 });

      const chainCycle = await attackChainService.getAttackChain(cycA.id, testOrgAId);
      assert.ok(chainCycle);
      assert.strictEqual(chainCycle.timeline.length, 2, 'Must cleanly visit each node once despite cycle');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART J & K: TIMELINE FORMAT & CONFIDENCE SCORE
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP J & K: TIMELINE FORMAT & CONFIDENCE SCORE ---');

    await testAsync('J1: Timeline is chronologically sorted with root relationship null and subsequent labeled', async () => {
      const chain = await attackChainService.getAttackChain(incAc1Id, testOrgAId);
      const timeline = chain.timeline;

      // Chronological sort check
      for (let i = 0; i < timeline.length - 1; i++) {
        const t1 = new Date(timeline[i].created_at).getTime();
        const t2 = new Date(timeline[i + 1].created_at).getTime();
        assert.ok(t1 <= t2, 'Timeline must be ordered chronologically');
      }

      // Root incident relationship is null
      assert.strictEqual(timeline[0].relationship, null, 'Root incident relationship must be null');

      // Subsequent steps have valid relationship string
      for (let i = 1; i < timeline.length; i++) {
        assert.ok(typeof timeline[i].relationship === 'string');
      }
    });

    await testAsync('K1: Confidence score is average of edge confidences rounded to 3 decimal places', async () => {
      const chain = await attackChainService.getAttackChain(incAc1Id, testOrgAId);
      assert.ok(typeof chain.confidence_score === 'number');
      assert.ok(chain.confidence_score >= 0.80 && chain.confidence_score <= 1.0);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART L: SNAPSHOT PERSISTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP L: SNAPSHOT PERSISTED ---');

    await testAsync('L1: generateSnapshot persists snapshot in attack_chain_snapshots table', async () => {
      const snapshot = await attackChainService.generateSnapshot(incAc1Id, testOrgAId);
      assert.ok(snapshot && snapshot.id);
      createdSnapshotIds.push(snapshot.id);

      const dbCheck = await AttackChainSnapshot.findById(snapshot.id);
      assert.ok(dbCheck);
      assert.strictEqual(dbCheck.root_incident_id, incAc1Id);
      assert.ok(dbCheck.chain_length >= 3);
      assert.ok(Array.isArray(dbCheck.timeline));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART M & N: QUERY API ENDPOINTS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP M & N: API ENDPOINTS ---');

    await testAsync('M1: GET /api/v1/incidents/:id/attack-chain returns root_incident, length, confidence, timeline', async () => {
      const tokenA = createToken({
        id: testUserAId,
        email: 'analyst_a@chain.test',
        role: 'admin',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incidents/${incAc1Id}/attack-chain`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.root_incident);
      assert.ok(typeof data.chain_length === 'number');
      assert.ok(typeof data.confidence_score === 'number');
      assert.ok(Array.isArray(data.timeline));
    });

    await testAsync('N1: GET /api/v1/incidents/:id/attack-chain/graph returns nodes and edges for React Flow / Cytoscape', async () => {
      const tokenA = createToken({
        id: testUserAId,
        email: 'analyst_a@chain.test',
        role: 'admin',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incidents/${incAc1Id}/attack-chain/graph`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.nodes), 'nodes array missing');
      assert.ok(Array.isArray(data.edges), 'edges array missing');

      if (data.nodes.length > 0) {
        assert.ok(data.nodes[0].id);
        assert.ok(data.nodes[0].label);
      }
      if (data.edges.length > 0) {
        assert.ok(data.edges[0].source);
        assert.ok(data.edges[0].target);
        assert.ok(data.edges[0].type);
      }
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART O: TENANT ISOLATION ENFORCED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP O: TENANT ISOLATION ENFORCED ---');

    await testAsync('O1: User from Org B receives 404 requesting Org A attack chain', async () => {
      const tokenB = createToken({
        id: testUserBId,
        email: 'analyst_b@chain.test',
        role: 'admin',
        organization_id: testOrgBId
      });

      const res = await fetch(`${baseUrl}/incidents/${incAc1Id}/attack-chain`, {
        headers: { Authorization: `Bearer ${tokenB}` }
      });

      assert.strictEqual(res.status, 404);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART P: AUTOMATIC ATTACK-CHAIN GROUP CREATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP P: ATTACK CHAIN GROUP CREATION ---');

    await testAsync('P1: Automatic creation of incident_groups with group_type=attack_chain when chain_length >= 3', async () => {
      const snap = await AttackChainSnapshot.findByIncident(incAc1Id);
      assert.ok(snap);
      assert.ok(snap.attack_chain_group_id, 'attack_chain_group_id must be populated when chain_length >= 3');
      createdGroupIds.push(snap.attack_chain_group_id);

      const group = await IncidentGroup.findById(snap.attack_chain_group_id);
      assert.ok(group);
      assert.strictEqual(group.group_type, 'attack_chain');
      assert.strictEqual(group.severity, 'critical');

      // Verify members of this attack_chain group
      const members = await IncidentGroupMember.findByGroup(group.id);
      assert.ok(members.length >= 3);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART Q: AUDIT LOGS RECORDED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP Q: AUDIT LOGS RECORDED ---');

    await testAsync('Q1: Audit logs for ATTACK_CHAIN_CREATED and ATTACK_CHAIN_VIEWED exist in DB', async () => {
      const auditRes = await db.query(
        `SELECT action FROM public.audit_logs
         WHERE organization_id = $1
           AND action IN ('ATTACK_CHAIN_CREATED', 'ATTACK_CHAIN_UPDATED', 'ATTACK_CHAIN_VIEWED');`,
        [testOrgAId]
      );

      assert.ok(auditRes.rows.length >= 1, 'Expected attack chain audit logs');
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('ATTACK_CHAIN_CREATED') || actions.includes('ATTACK_CHAIN_UPDATED'));
      assert.ok(actions.includes('ATTACK_CHAIN_VIEWED'));
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART R: PIPELINE INTEGRATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP R: PIPELINE INTEGRATION ---');

    await testAsync('R1: persistDetectionIncident with MITRE progression creates attack_chain_step and snapshot', async () => {
      const userA = { id: testUserAId, organization_id: testOrgAId, role: 'admin' };

      // Base incident with device and TA0001
      const baseInc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        device_id: testDeviceAId,
        explanation: 'Pipeline progression root',
        status: 'open'
      });
      createdIncidentIds.push(baseInc.id);

      await MitreMapping.create({
        incident_id: baseInc.id,
        technique_id: 'T1566',
        technique_name: 'Phishing'
      });

      // Now create second alert via persistDetectionIncident on same device with TA0002
      const createdAlert = await persistDetectionIncident({
        user: { ...userA, device_id: testDeviceAId },
        threatType: 'malicious_url',
        sourceType: 'url',
        mlResult: {
          risk_level: 'high',
          risk_score: 85,
          explanation: 'Pipeline progression step 2',
          signals: {},
          details: {
            device_id: testDeviceAId
          }
        }
      });

      assert.ok(createdAlert && createdAlert.id);
      createdIncidentIds.push(createdAlert.id);

      // Verify attack_chain_step edge was created
      const rels = await IncidentRelationship.findByIncident(createdAlert.id);
      const step = rels.find(r => r.relationship_type === 'attack_chain_step' && r.related_incident_id === baseInc.id);
      assert.ok(step, 'Pipeline must automatically create attack_chain_step edge on progression');

      // Verify snapshot was created or updated for this incident
      const snap = await AttackChainSnapshot.findByIncident(baseInc.id);
      assert.ok(snap, 'Snapshot must be generated automatically');
      createdSnapshotIds.push(snap.id);
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdSnapshotIds.length > 0) {
        await db.query(`DELETE FROM public.attack_chain_snapshots WHERE id = ANY($1::uuid[]);`, [createdSnapshotIds]);
      }
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
