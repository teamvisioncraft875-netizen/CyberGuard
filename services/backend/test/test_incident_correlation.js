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
const DetectionSignal = require('../src/models/DetectionSignal');
const incidentCorrelationService = require('../src/services/incidentCorrelationService');
const { persistDetectionIncident } = require('../src/services/incidentService');

/**
 * CYBERGUARD — Task 2: Incident Correlation Graph & Relationship Engine Test Suite
 *
 * Validates:
 * A. Migration applied
 * B. Relationship table exists
 * C. Rule R1 same IOC
 * D. Rule R2 same IP
 * E. Rule R3 same device
 * F. Rule R4 same user
 * G. Rule R5 same domain
 * H. Duplicate edges prevented
 * I. Tenant isolation enforced
 * J. Controller returns related incidents
 * K. Pipeline integration works
 * L. Audit logs recorded
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
  console.log('CYBERGUARD — Task 2: Incident Correlation Engine Test Suite');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let testOrgAId = null;
  let testOrgBId = null;
  let testUserAId = null;
  let testUserBId = null;
  let testDeviceAId = null;
  let testIndicatorId = null;

  const createdIncidentIds = [];
  const createdOrgIds = [];
  const createdUserIds = [];
  const createdDeviceIds = [];
  const createdIndicatorIds = [];

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

    await testAsync('A1: Migration file 026_incident_correlation_graph.sql exists', async () => {
      const migrationPath = path.resolve(__dirname, '../sql/026_incident_correlation_graph.sql');
      assert.ok(fs.existsSync(migrationPath), 'Migration file 026 must exist on disk');
      const content = fs.readFileSync(migrationPath, 'utf8');
      assert.ok(content.includes('CREATE TABLE IF NOT EXISTS public.incident_relationships'), 'Migration must contain table creation');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART B: RELATIONSHIP TABLE EXISTS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP B: RELATIONSHIP TABLE SCHEMA & CONSTRAINTS ---');

    await testAsync('B1: Table incident_relationships exists with all required columns', async () => {
      const colRes = await db.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'incident_relationships';
      `);

      const cols = colRes.rows.map((r) => r.column_name);
      assert.ok(cols.includes('id'), 'id missing');
      assert.ok(cols.includes('organization_id'), 'organization_id missing');
      assert.ok(cols.includes('source_incident_id'), 'source_incident_id missing');
      assert.ok(cols.includes('target_incident_id'), 'target_incident_id missing');
      assert.ok(cols.includes('relationship_type'), 'relationship_type missing');
      assert.ok(cols.includes('confidence_score'), 'confidence_score missing');
      assert.ok(cols.includes('rule_id'), 'rule_id missing');
      assert.ok(cols.includes('metadata'), 'metadata missing');
      assert.ok(cols.includes('created_at'), 'created_at missing');
    });

    await testAsync('B2: Indexes exist on organization_id, source_incident_id, and target_incident_id', async () => {
      const idxRes = await db.query(`
        SELECT indexname
        FROM pg_indexes
        WHERE tablename = 'incident_relationships';
      `);

      const indexes = idxRes.rows.map((r) => r.indexname);
      assert.ok(indexes.includes('idx_incident_relationships_org'), 'idx_incident_relationships_org missing');
      assert.ok(indexes.includes('idx_incident_relationships_source'), 'idx_incident_relationships_source missing');
      assert.ok(indexes.includes('idx_incident_relationships_target'), 'idx_incident_relationships_target missing');
    });

    await testAsync('B3: Check constraints and unique edge constraints exist', async () => {
      const constRes = await db.query(`
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE table_name = 'incident_relationships';
      `);

      const constraints = constRes.rows.map((r) => r.constraint_name);
      assert.ok(constraints.includes('chk_no_self_references'), 'chk_no_self_references missing');
      assert.ok(constraints.includes('uq_incident_relationships_edge'), 'uq_incident_relationships_edge missing');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // SETUP FIXTURES FOR CORRELATION RULES
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- SETUP TEST FIXTURES ---');

    const orgARes = await db.query(`INSERT INTO organizations (name) VALUES ('Correlation Org A') RETURNING id;`);
    testOrgAId = orgARes.rows[0].id;
    createdOrgIds.push(testOrgAId);

    const orgBRes = await db.query(`INSERT INTO organizations (name) VALUES ('Correlation Org B') RETURNING id;`);
    testOrgBId = orgBRes.rows[0].id;
    createdOrgIds.push(testOrgBId);

    const userARes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_a@corr.test', 'hash', 'admin') RETURNING id;`,
      [testOrgAId]
    );
    testUserAId = userARes.rows[0].id;
    createdUserIds.push(testUserAId);

    const userBRes = await db.query(
      `INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, 'analyst_b@corr.test', 'hash', 'admin') RETURNING id;`,
      [testOrgBId]
    );
    testUserBId = userBRes.rows[0].id;
    createdUserIds.push(testUserBId);

    const deviceRes = await db.query(
      `INSERT INTO devices (organization_id, device_name, is_trusted) VALUES ($1, 'Corr Test Device', true) RETURNING id;`,
      [testOrgAId]
    );
    testDeviceAId = deviceRes.rows[0].id;
    createdDeviceIds.push(testDeviceAId);

    const indicatorRes = await db.query(
      `INSERT INTO threat_indicators (organization_id, indicator_type, indicator_value, severity, confidence_score, tags, observation_count, first_seen_at, last_seen_at, expires_at, is_active, metadata)
       VALUES ($1, 'ip', '198.51.100.99', 'high', 90, '{}', 1, NOW(), NOW(), NOW() + INTERVAL '7 days', true, '{}')
       RETURNING id;`,
      [testOrgAId]
    );
    testIndicatorId = indicatorRes.rows[0].id;
    createdIndicatorIds.push(testIndicatorId);

    console.log('  [✅] Base test fixtures created (Org A, Org B, Users, Device, Threat Indicator)');

    // ──────────────────────────────────────────────────────────────────────────
    // PART C: RULE R1 (SAME IOC)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP C: RULE R1 — SAME IOC ---');

    await testAsync('C1: Rule R1 correlates two incidents sharing indicator_id in incident_ioc_matches', async () => {
      const inc1 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Inc 1 with IOC',
        status: 'open'
      });
      createdIncidentIds.push(inc1.id);

      const inc2 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 85,
        explanation: 'Inc 2 with IOC',
        status: 'open'
      });
      createdIncidentIds.push(inc2.id);

      // Associate both incidents with testIndicatorId
      await db.query(
        `INSERT INTO incident_ioc_matches (organization_id, incident_id, indicator_id, matched_value, match_context, reputation_score, severity, feed_source)
         VALUES ($1, $2, $3, '198.51.100.99', 'url_domain', 90, 'high', 'otx'),
                ($1, $4, $3, '198.51.100.99', 'url_domain', 90, 'high', 'otx');`,
        [testOrgAId, inc1.id, testIndicatorId, inc2.id]
      );

      // Run correlation for inc2
      const relationships = await incidentCorrelationService.correlateIncident(inc2.id, testOrgAId);
      assert.ok(relationships.length >= 1, 'Expected at least 1 relationship created');

      const iocRel = relationships.find(r => r.relationship_type === 'shares_ioc');
      assert.ok(iocRel, 'Must create shares_ioc relationship');
      assert.strictEqual(parseFloat(iocRel.confidence_score), 0.95);
      assert.strictEqual(iocRel.rule_id, 'R1');
      assert.strictEqual(iocRel.target_incident_id, inc1.id);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART D: RULE R2 (SAME IP)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP D: RULE R2 — SAME ATTACKER IP ---');

    await testAsync('D1: Rule R2 correlates incidents sharing source_ip / ip_address signal', async () => {
      const inc3 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 75,
        explanation: 'Inc 3 with attacker IP',
        status: 'open'
      });
      createdIncidentIds.push(inc3.id);

      const inc4 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'technical_threat',
        source_type: 'telemetry',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Inc 4 with attacker IP',
        status: 'open'
      });
      createdIncidentIds.push(inc4.id);

      const attackerIP = '203.0.113.195';
      await DetectionSignal.create({ incident_id: inc3.id, signal_name: 'source_ip', signal_value: attackerIP });
      await DetectionSignal.create({ incident_id: inc4.id, signal_name: 'ip_address', signal_value: attackerIP });

      const relationships = await incidentCorrelationService.correlateIncident(inc4.id, testOrgAId);
      const ipRel = relationships.find(r => r.relationship_type === 'same_attacker_ip' && r.target_incident_id === inc3.id);
      assert.ok(ipRel, 'Must create same_attacker_ip relationship');
      assert.strictEqual(parseFloat(ipRel.confidence_score), 0.85);
      assert.strictEqual(ipRel.rule_id, 'R2');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART E: RULE R3 (SAME HOST PROGRESSION)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP E: RULE R3 — SAME HOST PROGRESSION ---');

    await testAsync('E1: Rule R3 correlates same device with different threat_type within 2 hours', async () => {
      const inc5 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 75,
        device_id: testDeviceAId,
        status: 'open'
      });
      createdIncidentIds.push(inc5.id);

      const inc6 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'account_takeover',
        source_type: 'login',
        risk_level: 'critical',
        risk_score: 90,
        device_id: testDeviceAId,
        status: 'open'
      });
      createdIncidentIds.push(inc6.id);

      const relationships = await incidentCorrelationService.correlateIncident(inc6.id, testOrgAId);
      const hostRel = relationships.find(r => r.relationship_type === 'same_host_progression' && r.target_incident_id === inc5.id);
      assert.ok(hostRel, 'Must create same_host_progression relationship');
      assert.strictEqual(parseFloat(hostRel.confidence_score), 0.90);
      assert.strictEqual(hostRel.rule_id, 'R3');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART F: RULE R4 (SAME USER CAMPAIGN)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP F: RULE R4 — SAME USER CAMPAIGN ---');

    await testAsync('F1: Rule R4 correlates same user with different threat_type within 12 hours', async () => {
      const inc7 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testUserAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'medium',
        risk_score: 55,
        status: 'open'
      });
      createdIncidentIds.push(inc7.id);

      const inc8 = await Incident.create({
        organization_id: testOrgAId,
        user_id: testUserAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 80,
        status: 'open'
      });
      createdIncidentIds.push(inc8.id);

      const relationships = await incidentCorrelationService.correlateIncident(inc8.id, testOrgAId);
      const userRel = relationships.find(r => r.relationship_type === 'same_user_campaign' && r.target_incident_id === inc7.id);
      assert.ok(userRel, 'Must create same_user_campaign relationship');
      assert.strictEqual(parseFloat(userRel.confidence_score), 0.80);
      assert.strictEqual(userRel.rule_id, 'R4');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART G: RULE R5 (SAME DOMAIN / INFRASTRUCTURE)
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP G: RULE R5 — SAME INFRASTRUCTURE ---');

    await testAsync('G1: Rule R5 correlates incidents with domain from domain or url signals', async () => {
      const inc9 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 70,
        status: 'open'
      });
      createdIncidentIds.push(inc9.id);

      const inc10 = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'malicious_url',
        source_type: 'url',
        risk_level: 'high',
        risk_score: 85,
        status: 'open'
      });
      createdIncidentIds.push(inc10.id);

      await DetectionSignal.create({ incident_id: inc9.id, signal_name: 'domain', signal_value: 'adversary-infra.com' });
      await DetectionSignal.create({ incident_id: inc10.id, signal_name: 'url', signal_value: 'https://adversary-infra.com/login/auth?token=abc' });

      const relationships = await incidentCorrelationService.correlateIncident(inc10.id, testOrgAId);
      const infraRel = relationships.find(r => r.relationship_type === 'same_infrastructure' && r.target_incident_id === inc9.id);
      assert.ok(infraRel, 'Must create same_infrastructure relationship');
      assert.strictEqual(parseFloat(infraRel.confidence_score), 0.90);
      assert.strictEqual(infraRel.rule_id, 'R5');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART H: DUPLICATE EDGES PREVENTED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP H: DUPLICATE EDGES PREVENTED ---');

    await testAsync('H1: linkIncidents prevents duplicate edges and handles idempotency', async () => {
      const incA = createdIncidentIds[0];
      const incB = createdIncidentIds[1];

      // Second attempt to link with same type
      const dupAttempt = await incidentCorrelationService.linkIncidents({
        sourceId: incA,
        targetId: incB,
        type: 'shares_ioc',
        confidence: 0.95,
        organizationId: testOrgAId
      });

      assert.strictEqual(dupAttempt, null, 'Second link attempt must return null / be ignored');

      // Verify DB edge count between incA and incB for shares_ioc is exactly 1
      const countRes = await db.query(
        `SELECT COUNT(*)::int AS count
         FROM public.incident_relationships
         WHERE ((source_incident_id = $1 AND target_incident_id = $2)
            OR  (source_incident_id = $2 AND target_incident_id = $1))
           AND relationship_type = 'shares_ioc';`,
        [incA, incB]
      );
      assert.strictEqual(countRes.rows[0].count, 1);

      // Verify exists() method returns true
      const exists = await IncidentRelationship.exists(incA, incB, 'shares_ioc');
      assert.strictEqual(exists, true);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART I: TENANT ISOLATION ENFORCED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP I: TENANT ISOLATION ENFORCED ---');

    await testAsync('I1: Correlate candidate selection strictly excludes incidents from other organizations', async () => {
      // Create incident in Org B with identical attacker IP as Inc3 in Org A
      const incB1 = await Incident.create({
        organization_id: testOrgBId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        status: 'open'
      });
      createdIncidentIds.push(incB1.id);

      await DetectionSignal.create({ incident_id: incB1.id, signal_name: 'source_ip', signal_value: '203.0.113.195' });

      // Run correlation for Org B incident
      const relsB = await incidentCorrelationService.correlateIncident(incB1.id, testOrgBId);
      assert.strictEqual(relsB.length, 0, 'Must NOT correlate across tenants');

      // Verify in DB no relationship was created between Org B and Org A incidents
      const crossEdges = await db.query(
        `SELECT * FROM public.incident_relationships WHERE source_incident_id = $1 OR target_incident_id = $1;`,
        [incB1.id]
      );
      assert.strictEqual(crossEdges.rows.length, 0);
    });

    await testAsync('I2: linkIncidents rejects cross-tenant relationship attempts', async () => {
      const incA = createdIncidentIds[0]; // in Org A
      const incB = createdIncidentIds[createdIncidentIds.length - 1]; // in Org B

      let threw = false;
      try {
        await incidentCorrelationService.linkIncidents({
          sourceId: incA,
          targetId: incB,
          type: 'shares_ioc',
          confidence: 0.95
        });
      } catch (err) {
        threw = true;
        assert.ok(err.message.includes('Tenant isolation'), 'Error must specify tenant isolation');
      }
      assert.strictEqual(threw, true, 'Cross-tenant linking must throw an error');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART J: CONTROLLER RETURNS RELATED INCIDENTS
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP J: QUERY API /api/v1/incidents/:id/related ---');

    await testAsync('J1: GET /api/v1/incidents/:id/related returns relationships for analyst/admin', async () => {
      const targetIncId = createdIncidentIds[1]; // inc2
      const analystToken = createToken({
        id: testUserAId,
        email: 'analyst_a@corr.test',
        role: 'analyst',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incidents/${targetIncId}/related`, {
        headers: { Authorization: `Bearer ${analystToken}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.incident_id, targetIncId);
      assert.ok(Array.isArray(data.relationships));
      assert.ok(data.relationships.length >= 1);

      const sample = data.relationships[0];
      assert.ok(sample.relationship_type);
      assert.ok(typeof sample.confidence_score === 'number');
      assert.ok(sample.related_incident_id);
      assert.ok(sample.created_at);
    });

    await testAsync('J2: Non-analyst/admin role receives 403 Forbidden', async () => {
      const targetIncId = createdIncidentIds[1];
      const employeeToken = createToken({
        id: testUserAId,
        email: 'emp_a@corr.test',
        role: 'employee',
        organization_id: testOrgAId
      });

      const res = await fetch(`${baseUrl}/incidents/${targetIncId}/related`, {
        headers: { Authorization: `Bearer ${employeeToken}` }
      });

      assert.strictEqual(res.status, 403);
    });

    await testAsync('J3: Tenant isolation: user from Org B receives 404 for Org A incident', async () => {
      const targetIncId = createdIncidentIds[1]; // inc in Org A
      const analystBToken = createToken({
        id: testUserBId,
        email: 'analyst_b@corr.test',
        role: 'analyst',
        organization_id: testOrgBId
      });

      const res = await fetch(`${baseUrl}/incidents/${targetIncId}/related`, {
        headers: { Authorization: `Bearer ${analystBToken}` }
      });

      assert.strictEqual(res.status, 404);
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART K: PIPELINE INTEGRATION
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP K: PIPELINE INTEGRATION ---');

    await testAsync('K1: persistDetectionIncident automatically runs correlation and creates edges', async () => {
      const userA = { id: testUserAId, organization_id: testOrgAId, role: 'analyst' };

      // First create a base incident in Org A with an attacker IP
      const baseInc = await Incident.create({
        organization_id: testOrgAId,
        threat_type: 'phishing',
        source_type: 'email',
        risk_level: 'high',
        risk_score: 80,
        explanation: 'Base incident for pipeline correlation test',
        status: 'open'
      });
      createdIncidentIds.push(baseInc.id);
      await DetectionSignal.create({ incident_id: baseInc.id, signal_name: 'source_ip', signal_value: '198.51.100.222' });

      // Now invoke persistDetectionIncident with matching attacker IP
      const createdThroughPipeline = await persistDetectionIncident({
        user: userA,
        threatType: 'technical_threat',
        sourceType: 'telemetry',
        mlResult: {
          risk_level: 'high',
          risk_score: 85,
          explanation: 'Telemetry event sharing attacker IP',
          signals: {
            source_ip: '198.51.100.222'
          },
          details: {
            target_metric: 'failed_auth_attempts'
          }
        }
      });

      assert.ok(createdThroughPipeline && createdThroughPipeline.id);
      createdIncidentIds.push(createdThroughPipeline.id);

      // Verify relationship was created automatically in DB
      const rels = await IncidentRelationship.findByIncident(createdThroughPipeline.id);
      const matched = rels.find(r => r.relationship_type === 'same_attacker_ip' && r.related_incident_id === baseInc.id);
      assert.ok(matched, 'Pipeline must automatically correlate newly created incident with existing incident');
    });

    // ──────────────────────────────────────────────────────────────────────────
    // PART L: AUDIT LOGS RECORDED
    // ──────────────────────────────────────────────────────────────────────────
    console.log('\n--- TEST GROUP L: AUDIT LOGS RECORDED ---');

    await testAsync('L1: Audit logs for INCIDENT_CORRELATED and INCIDENT_RELATIONSHIP_CREATED exist in DB', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type, resource_id, details
         FROM public.audit_logs
         WHERE organization_id = $1
           AND action IN ('INCIDENT_CORRELATED', 'INCIDENT_RELATIONSHIP_CREATED');`,
        [testOrgAId]
      );

      assert.ok(auditRes.rows.length >= 1, 'Expected correlation audit logs to be recorded');
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('INCIDENT_RELATIONSHIP_CREATED'), 'Must include INCIDENT_RELATIONSHIP_CREATED');
      assert.ok(actions.includes('INCIDENT_CORRELATED'), 'Must include INCIDENT_CORRELATED');
    });

  } finally {
    console.log('\n--- CLEANUP FIXTURES ---');
    if (server) {
      server.close();
    }
    try {
      if (createdIncidentIds.length > 0) {
        await db.query(`DELETE FROM public.incident_relationships WHERE source_incident_id = ANY($1::uuid[]) OR target_incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incident_ioc_matches WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.detection_signals WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.mitre_mappings WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.recommended_actions WHERE incident_id = ANY($1::uuid[]);`, [createdIncidentIds]);
        await db.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [createdIncidentIds]);
      }
      if (createdIndicatorIds.length > 0) {
        await db.query(`DELETE FROM public.threat_indicators WHERE id = ANY($1::uuid[]);`, [createdIndicatorIds]);
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
