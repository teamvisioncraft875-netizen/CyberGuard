process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarExecution = require('../src/models/SoarExecution');
const SoarApproval = require('../src/models/SoarApproval');
const ThreatIOC = require('../src/models/ThreatIOC');
const SiemAlert = require('../src/models/SiemAlert');
const actionExecutor = require('../src/services/soar/actionExecutor');
const playbookEngine = require('../src/services/soar/playbookEngine');
const approvalService = require('../src/services/soar/approvalService');
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

async function runSoarAutomationSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint B Phase 1: SOAR Playbook Automation Platform Tests');
  console.log('========================================================================\n');

  let server;
  let baseUrl;
  let port;

  let orgA;
  let orgB;
  let adminA;
  let analystA;
  let employeeA;
  let adminB;

  let tokenAdminA;
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

    // 2. Setup Database Fixtures
    orgA = await createOrganizationFixture({ name: `SOAR Tenant Alpha ${Date.now()}` });
    orgB = await createOrganizationFixture({ name: `SOAR Tenant Beta ${Date.now()}` });

    adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });
    adminB = await createUserFixture({ organization_id: orgB.id, role: 'admin' });

    tokenAdminA = createToken(adminA, 'admin');
    tokenAnalystA = createToken(analystA, 'analyst');
    tokenEmployeeA = createToken(employeeA, 'employee');
    tokenAdminB = createToken(adminB, 'admin');

    // =========================================================================
    // GROUP 1: Playbook CRUD Operations
    // =========================================================================
    console.log('--- Group 1: Playbook CRUD Operations ---');
    let testPlaybookId = null;

    await testAsync('1.1 Create playbook with ordered sequential steps', async () => {
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Automated Ransomware Containment',
        description: 'Blocks C2 IP and alerts on-call SOC admin',
        enabled: true,
        trigger_type: 'alert',
        trigger_conditions: { severity: 'critical', threat_type: 'ransomware' },
        created_by: adminA.id,
        steps: [
          {
            step_order: 1,
            action_type: 'block_ip',
            action_config: { ip: '198.51.100.99' },
            requires_approval: false
          },
          {
            step_order: 2,
            action_type: 'send_email',
            action_config: { recipient: 'soc-lead@cyberguard.internal', subject: 'Ransomware isolated' },
            requires_approval: false
          }
        ]
      });

      assert(playbook.id, 'Playbook must have generated ID');
      assert.strictEqual(playbook.name, 'Automated Ransomware Containment');
      assert.strictEqual(playbook.steps.length, 2);
      assert.strictEqual(playbook.steps[0].action_type, 'block_ip');
      assert.strictEqual(playbook.steps[1].action_type, 'send_email');
      testPlaybookId = playbook.id;
    });

    await testAsync('1.2 Retrieve playbook by ID with ordered steps', async () => {
      const playbook = await SoarPlaybook.findById(testPlaybookId, orgA.id);
      assert(playbook, 'Playbook should be found');
      assert.strictEqual(playbook.steps.length, 2);
      assert.strictEqual(playbook.steps[0].step_order, 1);
      assert.strictEqual(playbook.steps[1].step_order, 2);
    });

    await testAsync('1.3 Update playbook properties', async () => {
      const updated = await SoarPlaybook.update(testPlaybookId, orgA.id, {
        description: 'Updated ransomware playbook description',
        enabled: false
      });
      assert.strictEqual(updated.description, 'Updated ransomware playbook description');
      assert.strictEqual(updated.enabled, false);

      // Restore enabled
      await SoarPlaybook.update(testPlaybookId, orgA.id, { enabled: true });
    });

    await testAsync('1.4 List playbooks with filters and pagination', async () => {
      const res = await SoarPlaybook.findMany({
        organization_id: orgA.id,
        enabled: true,
        trigger_type: 'alert'
      });
      assert(res.data.length >= 1, 'Should find at least 1 enabled alert playbook');
      assert(res.total >= 1, 'Total count should be at least 1');
    });

    await testAsync('1.5 Delete playbook and cascade step records', async () => {
      const tempPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Temporary Deletion Playbook',
        steps: [{ step_order: 1, action_type: 'block_ip' }]
      });
      const deleted = await SoarPlaybook.delete(tempPlaybook.id, orgA.id);
      assert.strictEqual(deleted, true);

      const check = await SoarPlaybook.findById(tempPlaybook.id, orgA.id);
      assert.strictEqual(check, null);
    });

    // =========================================================================
    // GROUP 2: Action Executor Framework
    // =========================================================================
    console.log('\n--- Group 2: Action Executor Framework ---');

    await testAsync('2.1 Execute block_ip action', async () => {
      const res = await actionExecutor.executeAction('block_ip', { ip: '203.0.113.50' });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'block_ip');
      assert.strictEqual(res.target_ip, '203.0.113.50');
      assert(res.firewall_rule_id);
    });

    await testAsync('2.2 Execute disable_user action', async () => {
      const res = await actionExecutor.executeAction('disable_user', { user: 'compromised_analyst' });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'disable_user');
      assert.strictEqual(res.target_user, 'compromised_analyst');
      assert.strictEqual(res.status, 'disabled');
    });

    await testAsync('2.3 Execute isolate_host action', async () => {
      const res = await actionExecutor.executeAction('isolate_host', { host: 'FINANCE-WKSTN-04' });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'isolate_host');
      assert.strictEqual(res.target_host, 'FINANCE-WKSTN-04');
      assert.strictEqual(res.network_status, 'isolated');
    });

    await testAsync('2.4 Execute create_ticket action', async () => {
      const res = await actionExecutor.executeAction('create_ticket', { title: 'High Severity Incident' });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'create_ticket');
      assert(res.ticket_id);
      assert.strictEqual(res.status, 'open');
    });

    await testAsync('2.5 Execute send_email action', async () => {
      const res = await actionExecutor.executeAction('send_email', {
        recipient: 'soc@cyberguard.internal',
        subject: 'Host Isolated Alert'
      });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'send_email');
      assert.strictEqual(res.status, 'sent');
    });

    await testAsync('2.6 Execute add_ioc action with ThreatIOC persistence', async () => {
      const res = await actionExecutor.executeAction('add_ioc', {
        ioc_type: 'ip',
        ioc_value: '198.51.100.111',
        threat_actor: 'APT29',
        malware_family: 'CozyBear'
      }, {
        organization_id: orgA.id
      });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, 'add_ioc');
      assert(res.ioc_id);
      assert.strictEqual(res.ioc_value, '198.51.100.111');

      // Verify IOC exists in database
      const found = await ThreatIOC.findById(res.ioc_id, orgA.id);
      assert(found);
      assert.strictEqual(found.ioc_value, '198.51.100.111');
      assert.strictEqual(found.threat_actor, 'APT29');
    });

    await testAsync('2.7 Register and execute custom action handler', async () => {
      actionExecutor.registerAction('flush_dns_cache', async (config) => {
        return { action: 'flush_dns_cache', domain: config.domain, flushed: true };
      });
      const res = await actionExecutor.executeAction('flush_dns_cache', { domain: 'evil-c2.example.com' });
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.flushed, true);
    });

    await testAsync('2.8 Unsupported action returns structured error', async () => {
      const res = await actionExecutor.executeAction('non_existent_action_xyz');
      assert.strictEqual(res.success, false);
      assert(res.error.includes('Unsupported action_type'));
    });

    // =========================================================================
    // GROUP 3: Playbook Execution Engine
    // =========================================================================
    console.log('\n--- Group 3: Playbook Execution Engine ---');

    await testAsync('3.1 Sequential execution transitions status pending -> running -> completed', async () => {
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Auto Containment Sequential Engine Test',
        steps: [
          { step_order: 1, action_type: 'block_ip', action_config: { ip: '10.20.30.40' } },
          { step_order: 2, action_type: 'create_ticket', action_config: { title: 'Automated containment' } }
        ]
      });

      const executions = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        id: null,
        title: 'High Sev Test Alert',
        severity: 'high'
      }, { playbookId: playbook.id });

      assert.strictEqual(executions.length, 1);
      const exec = executions[0];
      assert.strictEqual(exec.status, 'completed');
      assert(exec.started_at);
      assert(exec.completed_at);
    });

    await testAsync('3.2 Verify step record status and result_payload tracking', async () => {
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Step Tracking Verification Playbook',
        steps: [
          { step_order: 1, action_type: 'isolate_host', action_config: { host: 'FIN-01' } }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Step Tracking Test Alert'
      }, { playbookId: playbook.id });

      const steps = await SoarExecution.getExecutionSteps(exec.id);
      assert.strictEqual(steps.length, 1);
      assert.strictEqual(steps[0].status, 'completed');
      assert.strictEqual(steps[0].result_payload.action, 'isolate_host');
      assert.strictEqual(steps[0].result_payload.target_host, 'FIN-01');
    });

    await testAsync('3.3 Execution handles step failure and transitions to failed state', async () => {
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Failing Step Playbook',
        steps: [
          { step_order: 1, action_type: 'invalid_failing_action_test' }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Failure Test Alert'
      }, { playbookId: playbook.id });

      assert.strictEqual(exec.status, 'failed');
      const steps = await SoarExecution.getExecutionSteps(exec.id);
      assert.strictEqual(steps[0].status, 'failed');
      assert(steps[0].result_payload.error);
    });

    // =========================================================================
    // GROUP 4: Human-in-the-Loop Approval Workflow
    // =========================================================================
    console.log('\n--- Group 4: Human-in-the-Loop Approval Workflow ---');
    let approvalExecutionId = null;
    let createdApprovalId = null;

    await testAsync('4.1 Step requiring approval pauses execution in waiting_approval status', async () => {
      const gatedPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Domain Controller Lock Playbook',
        steps: [
          {
            step_order: 1,
            action_type: 'isolate_host',
            action_config: { host: 'DC-PRIMARY-01' },
            requires_approval: true
          },
          {
            step_order: 2,
            action_type: 'send_email',
            action_config: { recipient: 'ciso@cyberguard.internal', subject: 'DC Isolated' },
            requires_approval: false
          }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'DC Compromise Alert',
        severity: 'critical'
      }, { playbookId: gatedPlaybook.id });

      assert.strictEqual(exec.status, 'waiting_approval');
      approvalExecutionId = exec.id;

      const approval = await SoarApproval.findByExecutionId(approvalExecutionId);
      assert(approval, 'Approval record must be created');
      assert.strictEqual(approval.status, 'pending');
      createdApprovalId = approval.id;
    });

    await testAsync('4.2 Non-admin analyst approval attempt on L2 returns 403 Forbidden', async () => {
      // Escalate approval to L2 (under Phase 2 tiered approvals, analyst is only authorized for L1)
      const escRes = await fetch(`${baseUrl}/api/v1/soar/approvals/${createdApprovalId}/escalate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAdminA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target_level: 'L2', reason: 'Escalating for senior authorization' })
      });
      assert.strictEqual(escRes.status, 200);

      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${createdApprovalId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'Analyst attempting unauthorized approval on L2 request' })
      });
      assert.strictEqual(res.status, 403);
    });

    await testAsync('4.3 Admin approves execution -> resumes and transitions to completed', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${createdApprovalId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAdminA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'Approved by Security Lead' })
      });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert.strictEqual(body.data.approval.status, 'approved');
      assert.strictEqual(body.data.execution.status, 'completed');

      // Verify execution steps completed
      const steps = await SoarExecution.getExecutionSteps(approvalExecutionId);
      assert(steps.every(s => s.status === 'completed'), 'All steps should be completed');
    });

    await testAsync('4.4 Admin rejects execution -> status transitions to cancelled', async () => {
      const gatedPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Rejected Workflow Playbook',
        steps: [
          {
            step_order: 1,
            action_type: 'disable_user',
            action_config: { user: 'ceo_account' },
            requires_approval: true
          }
        ]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'False Positive Alert'
      }, { playbookId: gatedPlaybook.id });

      const approval = await SoarApproval.findByExecutionId(exec.id);

      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${approval.id}/reject`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAdminA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'False positive; do not disable CEO' })
      });
      assert.strictEqual(res.status, 200);

      const execRecord = await SoarExecution.findById(exec.id, orgA.id);
      assert.strictEqual(execRecord.status, 'cancelled');
    });

    // =========================================================================
    // GROUP 5: Automatic Alert Triggering
    // =========================================================================
    console.log('\n--- Group 5: Automatic Alert Triggering ---');

    await testAsync('5.1 Critical alert automatically triggers matching enabled playbook', async () => {
      // 1. Create enabled critical alert playbook
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Critical Beaconing Defense Playbook',
        enabled: true,
        trigger_type: 'alert',
        trigger_conditions: { severity: 'critical' },
        steps: [
          { step_order: 1, action_type: 'block_ip', action_config: { ip: '198.51.100.222' } }
        ]
      });

      // 2. Create critical SIEM alert
      const alert = await SiemAlert.create({
        organization_id: orgA.id,
        title: 'Critical Cobalt Strike Beaconing Detected',
        severity: 'critical',
        status: 'new',
        rule_code: 'CRIT-BEACON-01'
      });

      // 3. Trigger matching playbooks
      const executions = await playbookEngine.triggerMatchingPlaybooks(alert);
      assert(executions.length >= 1, 'Should trigger at least 1 matching playbook');
      const triggeredExec = executions.find(e => e.playbook_id === playbook.id);
      assert(triggeredExec, 'Our playbook must be executed');
      assert.strictEqual(triggeredExec.status, 'completed');
    });

    await testAsync('5.2 Disabled playbook is NOT automatically triggered', async () => {
      const disabledPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Disabled Inactive Playbook',
        enabled: false,
        trigger_type: 'alert',
        trigger_conditions: { severity: 'critical' },
        steps: [{ step_order: 1, action_type: 'block_ip' }]
      });

      const alert = await SiemAlert.create({
        organization_id: orgA.id,
        title: 'Critical Alert for Inactive Playbook Test',
        severity: 'critical'
      });

      const executions = await playbookEngine.triggerMatchingPlaybooks(alert);
      const found = executions.find(e => e.playbook_id === disabledPlaybook.id);
      assert.strictEqual(found, undefined, 'Disabled playbook must not be triggered');
    });

    await testAsync('5.3 Confirm no duplicate execution records are generated for same alert and playbook', async () => {
      // Create dedicated alert for deduplication verification
      const dupAlert = await SiemAlert.create({
        organization_id: orgA.id,
        title: 'Duplicate Prevention Critical Alert',
        severity: 'critical'
      });

      // First trigger
      const firstRun = await playbookEngine.triggerMatchingPlaybooks(dupAlert);
      assert(firstRun.length >= 1, 'First trigger should execute playbooks');

      // Second trigger with same alert
      const secondRun = await playbookEngine.triggerMatchingPlaybooks(dupAlert);
      assert.strictEqual(secondRun.length, 0, 'Second trigger must NOT create duplicate executions');

      // Verify DB count
      const checkCount = await db.query(
        'SELECT COUNT(*)::int AS count FROM public.soar_executions WHERE trigger_alert_id = $1;',
        [dupAlert.id]
      );
      assert.strictEqual(checkCount.rows[0].count, firstRun.length, 'Execution count in DB must match initial run exactly');
    });

    // =========================================================================
    // GROUP 6: REST API Endpoints & RBAC
    // =========================================================================
    console.log('\n--- Group 6: REST API Endpoints & RBAC ---');

    await testAsync('6.1 Reject unauthenticated request with 401', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks`);
      assert.strictEqual(res.status, 401);
    });

    await testAsync('6.2 Reject missing organization_id with 403 fail-closed', async () => {
      const noOrgToken = createToken(adminA, 'admin', null);
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks`, {
        headers: { 'Authorization': `Bearer ${noOrgToken}` }
      });
      assert.strictEqual(res.status, 403);
    });

    let apiPlaybookId = null;
    await testAsync('6.3 POST /api/v1/soar/playbooks creates playbook', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: 'API Created Playbook',
          description: 'Via REST API',
          steps: [
            { step_order: 1, action_type: 'create_ticket', action_config: { priority: 'high' } }
          ]
        })
      });
      assert.strictEqual(res.status, 201);
      const body = await res.json();
      assert.strictEqual(body.success, true);
      assert.strictEqual(body.data.name, 'API Created Playbook');
      apiPlaybookId = body.data.id;
    });

    await testAsync('6.4 GET /api/v1/soar/playbooks returns playbooks list', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert(body.data.length >= 1);
    });

    await testAsync('6.5 GET /api/v1/soar/playbooks/:id returns single playbook', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks/${apiPlaybookId}`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.data.id, apiPlaybookId);
    });

    await testAsync('6.6 PATCH /api/v1/soar/playbooks/:id updates playbook', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks/${apiPlaybookId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${tokenAnalystA}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: 'Renamed API Playbook' })
      });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert.strictEqual(body.data.name, 'Renamed API Playbook');
    });

    await testAsync('6.7 GET /api/v1/soar/executions lists executions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/executions`, {
        headers: { 'Authorization': `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      assert(Array.isArray(body.data));
    });

    await testAsync('6.8 DELETE /api/v1/soar/playbooks/:id deletes playbook', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/playbooks/${apiPlaybookId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${tokenAdminA}` }
      });
      assert.strictEqual(res.status, 200);
    });

    // =========================================================================
    // GROUP 7: Multi-tenant Isolation
    // =========================================================================
    console.log('\n--- Group 7: Multi-tenant Isolation ---');

    let tenantAPlaybook = null;
    await testAsync('7.1 Tenant B cannot access or see Tenant A playbooks (404/empty)', async () => {
      tenantAPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Confidential Tenant A Playbook'
      });

      // Tenant B direct GET
      const getRes = await fetch(`${baseUrl}/api/v1/soar/playbooks/${tenantAPlaybook.id}`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(getRes.status, 404);

      // Tenant B list
      const listRes = await fetch(`${baseUrl}/api/v1/soar/playbooks`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      const listBody = await listRes.json();
      assert(!listBody.data.some(p => p.id === tenantAPlaybook.id), 'Tenant A playbook must not appear in Tenant B list');
    });

    await testAsync('7.2 Tenant B cannot access Tenant A executions', async () => {
      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Tenant A Alert'
      }, { playbookId: tenantAPlaybook.id });

      const res = await fetch(`${baseUrl}/api/v1/soar/executions/${exec.id}`, {
        headers: { 'Authorization': `Bearer ${tokenAdminB}` }
      });
      assert.strictEqual(res.status, 404);
    });

    await testAsync('7.3 Tenant B cannot approve or reject Tenant A approvals', async () => {
      const gatedPlaybook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Gated Cross-Tenant Playbook',
        steps: [{ step_order: 1, action_type: 'block_ip', requires_approval: true }]
      });

      const [exec] = await playbookEngine.triggerPlaybook({
        organization_id: orgA.id,
        title: 'Cross Tenant Gated Alert'
      }, { playbookId: gatedPlaybook.id });

      const approval = await SoarApproval.findByExecutionId(exec.id);

      const res = await fetch(`${baseUrl}/api/v1/soar/approvals/${approval.id}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenAdminB}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: 'Tenant B attempting cross-tenant approval' })
      });
      assert(res.status === 404 || res.status === 400 || res.status === 403);
    });

    // =========================================================================
    // GROUP 8: Audit Trail Verification
    // =========================================================================
    console.log('\n--- Group 8: Audit Trail Verification ---');

    await testAsync('8.1 Verify audit logs created for SOAR playbook lifecycle', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type FROM public.audit_logs WHERE organization_id = $1 AND action LIKE 'SOAR_%';`,
        [orgA.id]
      );
      const actions = auditRes.rows.map(r => r.action);
      assert(actions.includes('SOAR_PLAYBOOK_CREATED'), 'Should record SOAR_PLAYBOOK_CREATED');
      assert(actions.includes('SOAR_PLAYBOOK_UPDATED'), 'Should record SOAR_PLAYBOOK_UPDATED');
      assert(actions.includes('SOAR_PLAYBOOK_DELETED'), 'Should record SOAR_PLAYBOOK_DELETED');
    });

    await testAsync('8.2 Verify audit logs created for executions and approvals', async () => {
      const auditRes = await db.query(
        `SELECT action FROM public.audit_logs WHERE organization_id = $1 AND action IN (
          'SOAR_EXECUTION_STARTED', 'SOAR_EXECUTION_COMPLETED', 'SOAR_EXECUTION_FAILED',
          'SOAR_APPROVAL_REQUESTED', 'SOAR_APPROVAL_APPROVED', 'SOAR_APPROVAL_REJECTED'
        );`,
        [orgA.id]
      );
      const actions = new Set(auditRes.rows.map(r => r.action));
      assert(actions.has('SOAR_EXECUTION_STARTED'), 'Must have SOAR_EXECUTION_STARTED');
      assert(actions.has('SOAR_EXECUTION_COMPLETED'), 'Must have SOAR_EXECUTION_COMPLETED');
      assert(actions.has('SOAR_EXECUTION_FAILED'), 'Must have SOAR_EXECUTION_FAILED');
      assert(actions.has('SOAR_APPROVAL_REQUESTED'), 'Must have SOAR_APPROVAL_REQUESTED');
      assert(actions.has('SOAR_APPROVAL_APPROVED'), 'Must have SOAR_APPROVAL_APPROVED');
      assert(actions.has('SOAR_APPROVAL_REJECTED'), 'Must have SOAR_APPROVAL_REJECTED');
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
  console.log(`SOAR Playbook Automation Suite Results: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runSoarAutomationSuite().then(() => {
  process.exit(failed > 0 ? 1 : 0);
}).catch((err) => {
  console.error('Execution failure:', err);
  process.exit(1);
});
