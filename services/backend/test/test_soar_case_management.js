process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SoarCase = require('../src/models/SoarCase');
const SoarCaseEvidence = require('../src/models/SoarCaseEvidence');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarExecution = require('../src/models/SoarExecution');
const SoarApproval = require('../src/models/SoarApproval');
const SiemAlert = require('../src/models/SiemAlert');
const approvalService = require('../src/services/soar/approvalService');
const playbookEngine = require('../src/services/soar/playbookEngine');
const actionExecutor = require('../src/services/soar/actionExecutor');
const playbookMetricsService = require('../src/services/soar/playbookMetricsService');
const { createOrganizationFixture, createUserFixture, cleanupFixtures } = require('./fixtures');

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

function createToken(user, roleOverride = null, orgOverride = undefined) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: roleOverride || user.jwt_role || user.role,
      organization_id: orgOverride !== undefined ? orgOverride : (user.organization_id || null)
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

async function runSoarCaseManagementSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint B Phase 2: SOAR Case Management & Orchestration Tests');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;

  let orgA;
  let orgB;
  let adminA;
  let seniorAnalystA;
  let analystA;
  let employeeA;
  let adminB;

  let tokenAdminA;
  let tokenSeniorAnalystA;
  let tokenAnalystA;
  let tokenEmployeeA;
  let tokenAdminB;

  try {
    // 1. Setup Test Server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    // 2. Setup Fixtures
    orgA = await createOrganizationFixture({ name: `SOAR Case Org A ${Date.now()}` });
    orgB = await createOrganizationFixture({ name: `SOAR Case Org B ${Date.now()}` });

    adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    seniorAnalystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });
    adminB = await createUserFixture({ organization_id: orgB.id, role: 'admin' });

    tokenAdminA = createToken(adminA, 'admin');
    tokenSeniorAnalystA = createToken(seniorAnalystA, 'senior_analyst');
    tokenAnalystA = createToken(analystA, 'analyst');
    tokenEmployeeA = createToken(employeeA, 'employee');
    tokenAdminB = createToken(adminB, 'admin');

    // =========================================================================
    // GROUP 1: SOAR Case Management Lifecycle
    // =========================================================================
    console.log('--- Group 1: SOAR Case Management Lifecycle ---');
    let caseA1Id = null;

    await testAsync('1.1 Create case manually with title, severity, priority, and tags', async () => {
      const soarCase = await SoarCase.create({
        organization_id: orgA.id,
        title: 'Suspected Lateral Movement in Finance Subnet',
        description: 'Multiple SMB login anomalies detected on subnet 10.0.5.0/24',
        severity: 'high',
        priority: 'high',
        assigned_to: analystA.id,
        created_by: adminA.id,
        tags: ['finance', 'smb', 'lateral_movement']
      });

      assert(soarCase.id, 'Case must have generated ID');
      assert.strictEqual(soarCase.title, 'Suspected Lateral Movement in Finance Subnet');
      assert.strictEqual(soarCase.status, 'open');
      assert.strictEqual(soarCase.severity, 'high');
      assert.strictEqual(soarCase.assigned_to, analystA.id);
      caseA1Id = soarCase.id;
    });

    let caseFromAlertId = null;
    let fixtureAlert = null;
    await testAsync('1.2 Create case initialized directly from SIEM alert', async () => {
      fixtureAlert = await SiemAlert.create({
        organization_id: orgA.id,
        title: 'Cobalt Strike Beacon Outbound to Bulletproof VPS',
        severity: 'critical',
        status: 'new',
        rule_code: 'CRIT-C2-COBALT',
        metadata: {
          threat_intel: { threat_actor: 'APT29', malware_family: 'CobaltStrike' }
        }
      });

      const caseFromAlert = await SoarCase.createFromAlert(fixtureAlert.id, orgA.id, {
        created_by: analystA.id
      });

      assert(caseFromAlert.id);
      assert.strictEqual(caseFromAlert.alert_id, fixtureAlert.id);
      assert.strictEqual(caseFromAlert.severity, 'critical');
      assert(caseFromAlert.title.includes('Cobalt Strike'));
      assert.strictEqual(caseFromAlert.threat_intel_findings.threat_actor, 'APT29');
      caseFromAlertId = caseFromAlert.id;
    });

    await testAsync('1.3 Retrieve case by ID with joined analyst and alert details', async () => {
      const found = await SoarCase.findById(caseFromAlertId, orgA.id);
      assert(found);
      assert.strictEqual(found.id, caseFromAlertId);
      assert.strictEqual(found.alert_title, fixtureAlert.title);
      assert.strictEqual(found.alert_severity, 'critical');
    });

    await testAsync('1.4 List cases with status and severity filters', async () => {
      const res = await SoarCase.findMany({
        organization_id: orgA.id,
        status: 'open',
        severity: 'critical'
      });

      assert(res.data.length >= 1);
      assert(res.data.some(c => c.id === caseFromAlertId));
    });

    await testAsync('1.5 Update case attributes (description, priority, tags)', async () => {
      const updated = await SoarCase.update(caseA1Id, orgA.id, {
        description: 'Updated investigation scope to encompass domain controllers',
        priority: 'critical',
        tags: ['finance', 'smb', 'lateral_movement', 'escalated']
      });

      assert.strictEqual(updated.description, 'Updated investigation scope to encompass domain controllers');
      assert.strictEqual(updated.priority, 'critical');
      assert.strictEqual(updated.tags.length, 4);
    });

    await testAsync('1.6 Transition case status: open -> investigating -> contained -> resolved -> closed', async () => {
      // open -> investigating
      let c = await SoarCase.updateStatus(caseA1Id, orgA.id, 'investigating', { reason: 'Analyst assigned' });
      assert.strictEqual(c.status, 'investigating');
      assert.strictEqual(c.closed_at, null);

      // investigating -> contained
      c = await SoarCase.updateStatus(caseA1Id, orgA.id, 'contained', { reason: 'Host network isolated' });
      assert.strictEqual(c.status, 'contained');

      // contained -> resolved
      c = await SoarCase.updateStatus(caseA1Id, orgA.id, 'resolved', { reason: 'Malware removed' });
      assert.strictEqual(c.status, 'resolved');
      assert(c.closed_at, 'closed_at must be populated on resolved');

      // resolved -> closed
      c = await SoarCase.updateStatus(caseA1Id, orgA.id, 'closed', { reason: 'Post-incident review complete' });
      assert.strictEqual(c.status, 'closed');
      assert(c.closed_at);
    });

    await testAsync('1.7 Delete case via Admin API', async () => {
      const tempCase = await SoarCase.create({
        organization_id: orgA.id,
        title: 'Temporary Case for Deletion'
      });

      const res = await fetch(`${baseUrl}/api/v1/soar/cases/${tempCase.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const check = await SoarCase.findById(tempCase.id, orgA.id);
      assert.strictEqual(check, null);
    });

    // =========================================================================
    // GROUP 2: Case Relationship & Artifact Attachments
    // =========================================================================
    console.log('\n--- Group 2: Case Relationship & Artifact Attachments ---');

    await testAsync('2.1 Attach incident IDs to case without duplicates', async () => {
      const dummyInc1 = '11111111-1111-1111-1111-111111111111';
      const dummyInc2 = '22222222-2222-2222-2222-222222222222';

      await SoarCase.attachIncidents(caseA1Id, orgA.id, [dummyInc1, dummyInc2]);
      // Duplicate attempt
      const updated = await SoarCase.attachIncidents(caseA1Id, orgA.id, [dummyInc1]);

      assert.strictEqual(updated.incident_ids.length, 2);
      assert(updated.incident_ids.includes(dummyInc1));
      assert(updated.incident_ids.includes(dummyInc2));
    });

    await testAsync('2.2 Attach IOC IDs to case without duplicates', async () => {
      const dummyIoc1 = '33333333-3333-3333-3333-333333333333';
      const dummyIoc2 = '44444444-4444-4444-4444-444444444444';

      await SoarCase.attachIOCs(caseA1Id, orgA.id, [dummyIoc1]);
      const updated = await SoarCase.attachIOCs(caseA1Id, orgA.id, [dummyIoc1, dummyIoc2]);

      assert.strictEqual(updated.ioc_ids.length, 2);
      assert(updated.ioc_ids.includes(dummyIoc1));
      assert(updated.ioc_ids.includes(dummyIoc2));
    });

    await testAsync('2.3 Attach threat intelligence findings to case', async () => {
      const updated = await SoarCase.attachThreatIntelFindings(caseA1Id, orgA.id, {
        c2_ip: '198.51.100.77',
        asn: 'AS13335',
        confidence_score: 95
      });

      assert.strictEqual(updated.threat_intel_findings.c2_ip, '198.51.100.77');
      assert.strictEqual(updated.threat_intel_findings.confidence_score, 95);
    });

    await testAsync('2.4 Attached artifacts persist across case status changes', async () => {
      await SoarCase.updateStatus(caseA1Id, orgA.id, 'investigating');
      const retrieved = await SoarCase.findById(caseA1Id, orgA.id);

      assert.strictEqual(retrieved.status, 'investigating');
      assert.strictEqual(retrieved.incident_ids.length, 2);
      assert.strictEqual(retrieved.ioc_ids.length, 2);
      assert.strictEqual(retrieved.threat_intel_findings.asn, 'AS13335');
    });

    // =========================================================================
    // GROUP 3: Approval Escalation Chains & SLA Expiration
    // =========================================================================
    console.log('\n--- Group 3: Approval Escalation Chains & SLA Expiration ---');
    let l1Approval = null;
    let l2Approval = null;
    let expiringApproval = null;

    // Helper: Create a pending execution for approval testing
    const pbForApproval = await SoarPlaybook.create({
      organization_id: orgA.id,
      name: 'Escalation Test Playbook',
      steps: [{ step_order: 1, action_type: 'isolate_host', requires_approval: true }]
    });

    const execForApproval = await SoarExecution.create({
      organization_id: orgA.id,
      playbook_id: pbForApproval.id,
      status: 'pending'
    });

    await testAsync('3.1 Request approval with level L1, L2, L3 and expiration SLA', async () => {
      l1Approval = await approvalService.requestApproval({
        execution_id: execForApproval.id,
        organization_id: orgA.id,
        level: 'L1',
        reason: 'L1 Analyst review for host isolation',
        ttl_minutes: 60
      });

      assert.strictEqual(l1Approval.level, 'L1');
      assert.strictEqual(l1Approval.status, 'pending');
      assert(l1Approval.expires_at, 'expires_at must be populated');

      const execCheck = await SoarExecution.findById(execForApproval.id, orgA.id);
      assert.strictEqual(execCheck.status, 'waiting_approval');
    });

    await testAsync('3.2 L1 approval can be approved by Analyst', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${l1Approval.id}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'L1 Analyst authorized action' })
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert.strictEqual(body.data.approval.status, 'approved');
    });

    await testAsync('3.3 L2 approval rejects Analyst (403) and succeeds with Senior Analyst', async () => {
      const exec2 = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: pbForApproval.id
      });

      l2Approval = await approvalService.requestApproval({
        execution_id: exec2.id,
        organization_id: orgA.id,
        level: 'L2',
        reason: 'L2 Senior Analyst review required'
      });

      // Analyst attempts L2 approval -> 403 Forbidden
      const resAnalyst = await fetch(`${baseUrl}/api/v1/soar/approvals/${l2Approval.id}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'Junior analyst trying L2' })
      });
      assert.strictEqual(resAnalyst.status, 403);

      // Senior Analyst attempts L2 approval -> 200 OK
      const resSenior = await fetch(`${baseUrl}/api/v1/soar/approvals/${l2Approval.id}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenSeniorAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'Senior analyst approved L2' })
      });
      assert.strictEqual(resSenior.status, 200);
    });

    await testAsync('3.4 Escalate pending approval from L1 to L2 or L2 to L3 with audit trail', async () => {
      const exec3 = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: pbForApproval.id
      });

      const appr = await approvalService.requestApproval({
        execution_id: exec3.id,
        organization_id: orgA.id,
        level: 'L1',
        reason: 'Initial L1 request'
      });

      const escalated = await approvalService.escalateApproval({
        approval_id: appr.id,
        organization_id: orgA.id,
        escalated_by: analystA.id,
        target_level: 'L2',
        reason: 'High impact asset; escalated to Senior Analyst'
      });

      assert.strictEqual(escalated.level, 'L2');
      assert.strictEqual(escalated.escalated_to_level, 'L2');
    });

    await testAsync('3.5 Expired approval automatically sweeps and transitions execution to cancelled', async () => {
      const exec4 = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: pbForApproval.id
      });

      expiringApproval = await approvalService.requestApproval({
        execution_id: exec4.id,
        organization_id: orgA.id,
        level: 'L1',
        reason: 'Immediate timeout test',
        ttl_minutes: -5 // Already in past
      });

      const expiredList = await approvalService.checkAndExpireApprovals();
      assert(expiredList.some(a => a.id === expiringApproval.id), 'Must have expired test approval');

      const updatedAppr = await SoarApproval.findById(expiringApproval.id, orgA.id);
      assert.strictEqual(updatedAppr.status, 'rejected');
      assert.strictEqual(updatedAppr.is_expired, true);

      const updatedExec = await SoarExecution.findById(exec4.id, orgA.id);
      assert.strictEqual(updatedExec.status, 'cancelled');
    });

    await testAsync('3.6 Rejection records rejection_comment in approval record', async () => {
      const exec5 = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: pbForApproval.id
      });

      const appr5 = await approvalService.requestApproval({
        execution_id: exec5.id,
        organization_id: orgA.id,
        level: 'L3',
        reason: 'Executive machine lock'
      });

      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${appr5.id}/reject`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAdminA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          reason: 'Do not isolate executive laptop',
          rejection_comment: 'Approved alternate containment via EDR credential reset'
        })
      });

      assert.strictEqual(res.status, 200);
      const apprRecord = await SoarApproval.findById(appr5.id, orgA.id);
      assert.strictEqual(apprRecord.status, 'rejected');
      assert(apprRecord.rejection_comment.includes('credential reset'));
    });

    // =========================================================================
    // GROUP 4: Execution Resiliency, Retries & Exponential Backoff
    // =========================================================================
    console.log('\n--- Group 4: Execution Resiliency, Retries & Exponential Backoff ---');

    await testAsync('4.1 Step configured with retry policy retries on failure up to max_retries', async () => {
      let runCount = 0;
      actionExecutor.registerAction('transient_flaky_action', async () => {
        runCount++;
        if (runCount < 3) {
          throw new Error(`Temporary 503 gateway error (attempt ${runCount})`);
        }
        return { recovered: true, attempts: runCount };
      });

      const resilientPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Resilient Retry Test Playbook',
        steps: [
          {
            step_order: 1,
            action_type: 'transient_flaky_action',
            retry_policy: { max_retries: 3, backoff_ms: 10, backoff_multiplier: 2 }
          }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Flaky Network Alert'
      }, { playbookId: resilientPlaybook.id, skipBackoffDelay: true });

      assert.strictEqual(exec.status, 'completed');
      assert.strictEqual(runCount, 3);
    });

    await testAsync('4.2 Retry records backoff metadata and retry_count in execution step', async () => {
      let flakyCount = 0;
      actionExecutor.registerAction('backoff_metadata_action', async () => {
        flakyCount++;
        if (flakyCount === 1) throw new Error('Attempt 1 fail');
        return { success: true };
      });

      const pb = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Backoff Metadata Verification Playbook',
        steps: [
          {
            step_order: 1,
            action_type: 'backoff_metadata_action',
            retry_policy: { max_retries: 2, backoff_ms: 20, backoff_multiplier: 2 }
          }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Metadata Alert'
      }, { playbookId: pb.id, skipBackoffDelay: true });

      const steps = await SoarExecution.getExecutionSteps(exec.id);
      assert.strictEqual(steps[0].status, 'completed');
      assert.strictEqual(steps[0].retry_count, 1, 'Step should record 1 retry attempt');
    });

    await testAsync('4.3 Step failing all retries transitions execution to failed state', async () => {
      actionExecutor.registerAction('permanently_failing_action', async () => {
        throw new Error('Permanent API failure');
      });

      const failPb = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Permanent Fail Playbook',
        steps: [
          {
            step_order: 1,
            action_type: 'permanently_failing_action',
            retry_policy: { max_retries: 2, backoff_ms: 10, backoff_multiplier: 2 }
          }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Permanent Fail Alert'
      }, { playbookId: failPb.id, skipBackoffDelay: true });

      assert.strictEqual(exec.status, 'failed');
      const steps = await SoarExecution.getExecutionSteps(exec.id);
      assert.strictEqual(steps[0].status, 'failed');
      assert.strictEqual(steps[0].retry_count, 2);
    });

    await testAsync('4.4 Stale execution recovery resumes and recovers executions across restarts', async () => {
      const restartPb = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Crash Recovery Playbook',
        steps: [
          { step_order: 1, action_type: 'block_ip', action_config: { ip: '10.99.88.77' } }
        ]
      });

      // Simulate execution left in 'running' state during crash
      const crashedExec = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: restartPb.id,
        status: 'running'
      });

      const steps = await SoarPlaybook.getSteps(restartPb.id);
      await SoarExecution.createStepRecord({
        execution_id: crashedExec.id,
        playbook_step_id: steps[0].id,
        status: 'pending'
      });

      // Run recovery
      const recovered = await playbookEngine.recoverStaleExecutions({ organization_id: orgA.id });
      assert(recovered.some(e => e.id === crashedExec.id), 'Crashed execution must be recovered');

      const check = await SoarExecution.findById(crashedExec.id, orgA.id);
      assert.strictEqual(check.status, 'completed');
    });

    await testAsync('4.5 POST /api/v1/soar/executions/recover triggers recovery API', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/executions/recover`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert(Array.isArray(body.data));
    });

    // =========================================================================
    // GROUP 5: Response Evidence Collection
    // =========================================================================
    console.log('\n--- Group 5: Response Evidence Collection ---');

    await testAsync('5.1 Playbook step execution automatically records remediation_output evidence linked to case', async () => {
      const evidencePb = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Evidence Generating Playbook',
        steps: [
          { step_order: 1, action_type: 'block_ip', action_config: { ip: '203.0.113.88' } }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Evidence Alert'
      }, { playbookId: evidencePb.id, caseId: caseA1Id });

      assert.strictEqual(exec.status, 'completed');

      const evRes = await SoarCaseEvidence.findByCaseId(caseA1Id, orgA.id, { evidence_type: 'remediation_output' });
      assert(evRes.data.length >= 1, 'Should find remediation_output evidence linked to case');
      assert.strictEqual(evRes.data[0].data.action_type, 'block_ip');
    });

    await testAsync('5.2 Playbook completion attaches execution_log evidence to case', async () => {
      const evRes = await SoarCaseEvidence.findByCaseId(caseA1Id, orgA.id, { evidence_type: 'execution_log' });
      assert(evRes.data.length >= 1, 'Should find execution_log evidence');
      assert.strictEqual(evRes.data[0].data.status, 'completed');
    });

    await testAsync('5.3 Playbook failure attaches error execution_log evidence to case', async () => {
      const failPb = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Failure Evidence Playbook',
        steps: [{ step_order: 1, action_type: 'unsupported_test_evidence_fail' }]
      });

      await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Fail Evidence Alert'
      }, { playbookId: failPb.id, caseId: caseA1Id });

      const evRes = await SoarCaseEvidence.findByCaseId(caseA1Id, orgA.id, { evidence_type: 'execution_log' });
      const failLog = evRes.data.find(e => e.data.status === 'failed');
      assert(failLog, 'Must find failed execution_log');
      assert(failLog.data.error);
    });

    let manualEvidenceId = null;
    await testAsync('5.4 Add analyst_note evidence to case via REST API', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/cases/${caseA1Id}/evidence`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          evidence_type: 'analyst_note',
          data: {
            note: 'Host memory dump collected for volatility analysis',
            md5: 'd41d8cd98f00b204e9800998ecf8427e'
          }
        })
      });

      assert.strictEqual(res.status, 201);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert.strictEqual(body.data.evidence_type, 'analyst_note');
      manualEvidenceId = body.data.id;
    });

    await testAsync('5.5 GET /api/v1/soar/cases/:id/evidence with filters and pagination', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/cases/${caseA1Id}/evidence?evidence_type=analyst_note`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert(body.data.length >= 1);
      assert.strictEqual(body.data[0].evidence_type, 'analyst_note');
    });

    // =========================================================================
    // GROUP 6: Playbook Analytics & Metrics Service
    // =========================================================================
    console.log('\n--- Group 6: Playbook Analytics & Metrics Service ---');

    await testAsync('6.1 GET /api/v1/soar/metrics returns execution counts and rates', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/metrics`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert(body.data.summary.total_executions > 0);
      assert(typeof body.data.summary.success_rate === 'number');
      assert(typeof body.data.summary.failure_rate === 'number');
    });

    await testAsync('6.2 GET /api/v1/soar/metrics returns approval bottlenecks and counts by escalation level', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/metrics`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });

      const body = await res.json();
      const bottlenecks = body.data.approval_bottlenecks;
      assert(bottlenecks);
      assert(bottlenecks.total_approvals > 0);
      assert(bottlenecks.by_level.L1 !== undefined);
      assert(bottlenecks.by_level.L2 !== undefined);
      assert(bottlenecks.by_level.L3 !== undefined);
    });

    await testAsync('6.3 GET /api/v1/soar/metrics returns most used playbooks and latency distributions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/metrics`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });

      const body = await res.json();
      assert(Array.isArray(body.data.most_used_playbooks));
      assert(body.data.most_used_playbooks.length > 0);
      assert(body.data.response_time_distributions.under_1s !== undefined);
    });

    await testAsync('6.4 GET /api/v1/soar/metrics/playbooks/:id returns single playbook performance', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/metrics/playbooks/${pbForApproval.id}`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert.strictEqual(body.data.playbook.id, pbForApproval.id);
      assert(typeof body.data.metrics.total_executions === 'number');
    });

    await testAsync('6.5 Tenant B metrics do not reflect Tenant A executions (Strict Isolation)', async () => {
      const resB = await fetch(`${baseUrl}/api/v1/soar/metrics`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });

      assert.strictEqual(resB.status, 200);
      const bodyB = await resB.json();
      assert.strictEqual(bodyB.data.summary.total_executions, 0, 'Tenant B must have 0 executions');
    });

    // =========================================================================
    // GROUP 7: Security, Multi-Tenant Isolation & RBAC
    // =========================================================================
    console.log('\n--- Group 7: Security, Multi-Tenant Isolation & RBAC ---');

    await testAsync('7.1 Reject unauthenticated request with 401 Unauthorized', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/cases`);
      assert.strictEqual(res.status, 401);
    });

    await testAsync('7.2 Reject employee role with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/cases`, {
        headers: { 'Authorization': `Bearer ${tokenEmployeeA}` }
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('7.3 Tenant B cannot access or modify Tenant A cases or evidence (404/empty)', async () => {
      // Direct GET
      const resGet = await fetch(`${baseUrl}/api/v1/soar/cases/${caseA1Id}`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(resGet.status, 404);

      // List Cases
      const resList = await fetch(`${baseUrl}/api/v1/soar/cases`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      const listBody = await resList.json();
      assert(!listBody.data.some(c => c.id === caseA1Id), 'Tenant A case must not appear for Tenant B');

      // Evidence GET
      const resEv = await fetch(`${baseUrl}/api/v1/soar/cases/${caseA1Id}/evidence`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(resEv.status, 404);
    });

    await testAsync('7.4 Verify audit logs recorded for Phase 2 SOAR operations', async () => {
      const auditRes = await db.query(
        `SELECT action FROM public.audit_logs WHERE organization_id = $1 AND action LIKE 'SOAR_%';`,
        [orgA.id]
      );
      const actions = new Set(auditRes.rows.map(r => r.action));
      assert(actions.has('SOAR_CASE_CREATED'), 'Must have SOAR_CASE_CREATED');
      assert(actions.has('SOAR_CASE_STATUS_CHANGED'), 'Must have SOAR_CASE_STATUS_CHANGED');
      assert(actions.has('SOAR_EVIDENCE_ATTACHED'), 'Must have SOAR_EVIDENCE_ATTACHED');
      assert(actions.has('SOAR_APPROVAL_ESCALATED'), 'Must have SOAR_APPROVAL_ESCALATED');
      assert(actions.has('SOAR_APPROVAL_EXPIRED'), 'Must have SOAR_APPROVAL_EXPIRED');
      assert(actions.has('SOAR_EXECUTION_RETRIED'), 'Must have SOAR_EXECUTION_RETRIED');
      assert(actions.has('SOAR_EXECUTION_RECOVERED'), 'Must have SOAR_EXECUTION_RECOVERED');
    });

  } catch (suiteErr) {
    console.error('Fatal Suite Error:', suiteErr);
  } finally {
    // Teardown server
    if (server) {
      server.close();
    }
    // Teardown fixtures
    try {
      const orgIds = [orgA?.id, orgB?.id].filter(Boolean);
      await cleanupFixtures({ orgIds });
    } catch (cleanupErr) {
      console.warn('Teardown warning:', cleanupErr.message);
    }
  }

  console.log('\n========================================================================');
  console.log(`SOAR Case Management Suite Results: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runSoarCaseManagementSuite().then(() => {
  process.exit(failed > 0 ? 1 : 0);
}).catch((err) => {
  console.error('Execution failure:', err);
  process.exit(1);
});
