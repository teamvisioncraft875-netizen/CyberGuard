process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const Organization = require('../src/models/Organization');
const User = require('../src/models/User');
const SiemAlert = require('../src/models/SiemAlert');
const Incident = require('../src/models/Incident');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarCase = require('../src/models/SoarCase');
const SoarApproval = require('../src/models/SoarApproval');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotMessage = require('../src/models/CopilotMessage');
const CopilotSessionAction = require('../src/models/CopilotSessionAction');
const AuditLog = require('../src/models/AuditLog');

const intentDetectionService = require('../src/services/copilot/intentDetectionService');
const entityExtractionService = require('../src/services/copilot/entityExtractionService');
const commandPlannerService = require('../src/services/copilot/commandPlannerService');
const naturalLanguageExecutionService = require('../src/services/copilot/naturalLanguageExecutionService');
const copilotService = require('../src/services/copilot/copilotService');

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

async function runCopilotPhase4Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 4: Natural Language SOC Operations Tests');
  console.log('========================================================================\n');

  let server;
  let baseUrl;

  try {
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;

    // 1. Fixtures Setup
    const orgA = await createOrganizationFixture({ name: 'Tenant Copilot Alpha P4' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Copilot Beta P4' });

    const adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    const analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    const employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });

    const analystB = await createUserFixture({ organization_id: orgB.id, role: 'analyst' });

    const tokenAdminA = createToken(adminA);
    const tokenAnalystA = createToken(analystA);
    const tokenEmployeeA = createToken(employeeA);
    const tokenAnalystB = createToken(analystB);
    const tokenNoOrg = createToken(analystA, 'analyst', null);

    // 2. Seed Data for Tenant A
    const alertA = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Mimikatz In-Memory Credential Dumping on DC-01',
      severity: 'critical',
      status: 'new',
      source_type: 'windows_sysmon',
      mitre_technique: 'T1003',
      metadata: { host: 'DC-01', ip: '10.0.1.10', target_user: 'Administrator' }
    });

    const caseA = await SoarCase.create({
      organization_id: orgA.id,
      title: 'Case 42: Active Triage on DC-01',
      description: 'Domain Controller compromise triage',
      severity: 'high',
      status: 'open',
      priority: 'high',
      alert_id: alertA.id,
      created_by: adminA.id
    });

    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: analystA.id,
      title: 'Investigation Workspace for DC-01',
      entity_type: 'case',
      entity_id: caseA.id
    });

    // Mock Gemini
    copilotService.setMockHandler(async ({ question }) => {
      return {
        answer: `[MOCKED COPILOT RESPONSE] Analyzed instruction: "${question}".`,
        tokens_used: 110
      };
    });

    console.log('--- Group 1: Intent Detection (16 Supported Intents) ---');

    await testAsync('1. Intent: block_ip', async () => {
      const res = await intentDetectionService.detectIntent('block 185.220.101.5', { organization_id: orgA.id, actor_id: analystA.id });
      assert.strictEqual(res.intent, 'block_ip');
      assert.ok(res.confidence >= 0.90);
    });

    await testAsync('2. Intent: create_case', async () => {
      const res = await intentDetectionService.detectIntent('create case for alert 123', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'create_case');
    });

    await testAsync('3. Intent: escalate_case', async () => {
      const res = await intentDetectionService.detectIntent('escalate case 42', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'escalate_case');
    });

    await testAsync('4. Intent: execute_playbook', async () => {
      const res = await intentDetectionService.detectIntent('run ransomware containment on case 42', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'execute_playbook');
    });

    await testAsync('5. Intent: recommend_playbook', async () => {
      const res = await intentDetectionService.detectIntent('what playbook should I run for ransomware?', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'recommend_playbook');
    });

    await testAsync('6. Intent: block_domain', async () => {
      const res = await intentDetectionService.detectIntent('block domain evil-c2.com', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'block_domain');
    });

    await testAsync('7. Intent: disable_account', async () => {
      const res = await intentDetectionService.detectIntent('disable user jsmith', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'disable_account');
    });

    await testAsync('8. Intent: isolate_endpoint', async () => {
      const res = await intentDetectionService.detectIntent('isolate host WORKSTATION-99', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'isolate_endpoint');
    });

    await testAsync('9. Intent: create_jira_ticket', async () => {
      const res = await intentDetectionService.detectIntent('create jira ticket for case 42', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'create_jira_ticket');
    });

    await testAsync('10. Intent: send_slack_message', async () => {
      const res = await intentDetectionService.detectIntent('notify slack #soc-alerts', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'send_slack_message');
    });

    await testAsync('11. Intent: send_teams_message', async () => {
      const res = await intentDetectionService.detectIntent('send teams message', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'send_teams_message');
    });

    await testAsync('12. Intent: create_approval', async () => {
      const res = await intentDetectionService.detectIntent('request approval for containment', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'create_approval');
    });

    await testAsync('13. Intent: summarize_session', async () => {
      const res = await intentDetectionService.detectIntent('what actions have we taken?', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'summarize_session');
    });

    await testAsync('14. Intent: list_incidents', async () => {
      const res = await intentDetectionService.detectIntent('list active incidents', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'list_incidents');
    });

    await testAsync('15. Intent: list_alerts', async () => {
      const res = await intentDetectionService.detectIntent('show critical alerts', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'list_alerts');
    });

    await testAsync('16. Intent: show_case', async () => {
      const res = await intentDetectionService.detectIntent('show case 42', { organization_id: orgA.id });
      assert.strictEqual(res.intent, 'show_case');
    });

    console.log('--- Group 2: Entity Extraction Engine ---');

    await testAsync('17. Entity: IPv4 and IPv6 extraction', async () => {
      const entities = await entityExtractionService.extractEntities(
        'isolate 185.220.101.5 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        { organization_id: orgA.id }
      );
      assert.strictEqual(entities.ipv4, '185.220.101.5');
      assert.strictEqual(entities.ipv6, '2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    });

    await testAsync('18. Entity: domain, URL, and email extraction', async () => {
      const entities = await entityExtractionService.extractEntities(
        'block https://c2.evil-corp.com/payload.exe domain malware-drop.com contact soc@victim.org'
      );
      assert.strictEqual(entities.url, 'https://c2.evil-corp.com/payload.exe');
      assert.strictEqual(entities.domain, 'malware-drop.com');
      assert.strictEqual(entities.email, 'soc@victim.org');
    });

    await testAsync('19. Entity: hash, username, and MITRE technique extraction', async () => {
      const entities = await entityExtractionService.extractEntities(
        'investigate e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 user svc_backup technique T1003'
      );
      assert.strictEqual(entities.hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      assert.strictEqual(entities.username, 'svc_backup');
      assert.strictEqual(entities.mitre_technique, 'T1003');
    });

    await testAsync('20. Entity: case ID, alert ID, incident ID, and playbook name extraction', async () => {
      const entities = await entityExtractionService.extractEntities(
        'run ransomware containment on case 42 for alert 123'
      );
      assert.strictEqual(entities.case_id, 42);
      assert.strictEqual(entities.alert_id, '123');
      assert.strictEqual(entities.playbook_name, 'ransomware containment');
    });

    console.log('--- Group 3: Command Planner ---');

    await testAsync('21. Command Planner: single-step low-risk plan', async () => {
      const planRes = await commandPlannerService.createPlan({
        intent: 'create_jira_ticket',
        entities: { case_id: 42 },
        organization_id: orgA.id,
        actor_id: analystA.id
      });
      assert.strictEqual(planRes.plan.length, 1);
      assert.strictEqual(planRes.plan[0].action, 'create_jira_ticket');
      assert.strictEqual(planRes.plan[0].requires_approval, false);
      assert.strictEqual(planRes.plan[0].risk_level, 'low');
    });

    await testAsync('22. Command Planner: single-step high-risk plan with approval gating', async () => {
      const planRes = await commandPlannerService.createPlan({
        intent: 'isolate_endpoint',
        entities: { host: 'WORKSTATION-99' },
        organization_id: orgA.id,
        actor_id: analystA.id
      });
      assert.strictEqual(planRes.plan.length, 1);
      assert.strictEqual(planRes.plan[0].action, 'isolate_endpoint');
      assert.strictEqual(planRes.plan[0].requires_approval, true);
      assert.strictEqual(planRes.plan[0].risk_level, 'critical');
    });

    await testAsync('23. Command Planner: multi-step plan (create jira ticket and notify slack)', async () => {
      const planRes = await commandPlannerService.createPlan({
        intent: 'create_jira_ticket',
        intents: ['create_jira_ticket', 'send_slack_message'],
        entities: { case_id: 42 },
        organization_id: orgA.id
      });
      assert.strictEqual(planRes.plan.length, 2);
      assert.strictEqual(planRes.plan[0].action, 'create_jira_ticket');
      assert.strictEqual(planRes.plan[1].action, 'send_slack_message');
    });

    await testAsync('24. Command Planner: multi-step plan (create case and run containment playbook)', async () => {
      const planRes = await commandPlannerService.createPlan({
        intent: 'create_case',
        intents: ['create_case', 'execute_playbook'],
        entities: { alert_id: '123', playbook_name: 'ransomware containment' },
        organization_id: orgA.id
      });
      assert.strictEqual(planRes.plan.length, 2);
      assert.strictEqual(planRes.plan[0].action, 'create_soar_case');
      assert.strictEqual(planRes.plan[1].action, 'launch_playbook');
    });

    console.log('--- Group 4: Natural Language Execution Engine ---');

    await testAsync('25. NL Execution: executes safe command via POST /api/v1/copilot/command', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'create jira ticket for case 42',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'completed');
      assert.ok(data.executed_steps.length > 0);
      assert.strictEqual(data.executed_steps[0].action, 'create_jira_ticket');
    });

    await testAsync('26. NL Execution: executes create_case command via POST /api/v1/copilot/command', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'create case for alert 123',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'completed');
      assert.strictEqual(data.executed_steps[0].action, 'create_soar_case');
    });

    console.log('--- Group 5: Approval Enforcement ---');

    let approvalIdBlockIp;

    await testAsync('27. Approval Enforcement: block_ip halts with approval_required', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'block 185.220.101.5',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'approval_required');
      assert.strictEqual(data.requires_approval, true);
      assert.ok(data.approval_id);
      approvalIdBlockIp = data.approval_id;
    });

    await testAsync('28. Approval Enforcement: isolate_endpoint halts with approval_required', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'isolate host WORKSTATION-99',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'approval_required');
      assert.strictEqual(data.requires_approval, true);
      assert.ok(data.approval_id);
    });

    await testAsync('29. Analysts cannot bypass approval: command cannot force unapproved execution', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'isolate host WORKSTATION-99',
          session_id: sessionA.id,
          options: { bypass_approval: true }
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'approval_required');
      assert.strictEqual(data.requires_approval, true);
    });

    await testAsync('30. Execution proceeds once pre-approved approval_id is supplied', async () => {
      // Approve approvalIdBlockIp in DB
      await SoarApproval.decide(approvalIdBlockIp, {
        status: 'approved',
        decided_by: adminA.id,
        reason: 'Authorized perimeter block'
      });

      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'block 185.220.101.5',
          session_id: sessionA.id,
          options: { approval_id: approvalIdBlockIp }
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'completed');
      assert.strictEqual(data.executed_steps[0].action, 'block_ip');
      assert.strictEqual(data.executed_steps[0].status, 'executed');
    });

    console.log('--- Group 6: Multi-Step Action Chains ---');

    await testAsync('31. Multi-Step Chain: executes all steps sequentially for low-risk actions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'create jira ticket and notify slack',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'completed');
      assert.strictEqual(data.executed_steps.length, 2);
      assert.strictEqual(data.executed_steps[0].action, 'create_jira_ticket');
      assert.strictEqual(data.executed_steps[1].action, 'send_slack_message');
    });

    await testAsync('32. Multi-Step Chain: stops at high-risk step when unapproved', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          command: 'create case for alert 123 and isolate host DC-01',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      // Step 1 executed, Step 2 paused for approval
      assert.strictEqual(data.status, 'approval_required');
      assert.strictEqual(data.executed_steps.length, 1);
      assert.strictEqual(data.executed_steps[0].action, 'create_soar_case');
      assert.ok(data.approval_id);
    });

    console.log('--- Group 7: Session Memory & Investigation Timeline ---');

    await testAsync('33. Session Memory: command execution records user and assistant messages', async () => {
      const messages = await CopilotMessage.findRecent(sessionA.id, 10);
      assert.ok(messages.length >= 2);
      assert.ok(messages.some(m => m.role === 'user'));
      assert.ok(messages.some(m => m.role === 'assistant'));
    });

    await testAsync('34. Session Timeline: GET /api/v1/copilot/sessions/:id/timeline returns chronological events', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}/timeline`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.data.timeline));
      assert.ok(data.data.timeline.length > 0);
      assert.ok(data.data.summary);
      assert.ok(data.data.summary.total_events > 0);
    });

    console.log('--- Group 8: Action Explainability ---');

    await testAsync('35. Explainability: POST /api/v1/copilot/explain returns action rationale and MITRE mapping', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/explain`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          action: 'isolate_endpoint',
          reason: 'Host exhibits ransomware encryption traits',
          evidence: 'Suspicious process spawning vssadmin delete shadows',
          mitre_mapping: 'T1486'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.explanation.action, 'isolate_endpoint');
      assert.strictEqual(data.explanation.mitre_mapping, 'T1486');
      assert.strictEqual(data.explanation.risk_level, 'high');
      assert.strictEqual(data.explanation.requires_approval, true);
    });

    console.log('--- Group 9: Audit Logging ---');

    await testAsync('36. Audit Logging: records COPILOT_INTENT_DETECTED and COPILOT_ENTITY_EXTRACTED', async () => {
      const logsIntent = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_INTENT_DETECTED',
        limit: 5
      });
      assert.ok(logsIntent.logs.length > 0);

      const logsEntity = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_ENTITY_EXTRACTED',
        limit: 5
      });
      assert.ok(logsEntity.logs.length > 0);
    });

    await testAsync('37. Audit Logging: records COPILOT_PLAN_GENERATED and COPILOT_COMMAND_EXECUTED', async () => {
      const logsPlan = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_PLAN_GENERATED',
        limit: 5
      });
      assert.ok(logsPlan.logs.length > 0);

      const logsCmd = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_COMMAND_EXECUTED',
        limit: 5
      });
      assert.ok(logsCmd.logs.length > 0);
    });

    console.log('--- Group 10: RBAC Validation ---');

    await testAsync('38. RBAC: employee receives HTTP 403 on command and plan endpoints', async () => {
      const resCmd = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ command: 'show critical alerts' })
      });
      assert.strictEqual(resCmd.status, 403);

      const resPlan = await fetch(`${baseUrl}/api/v1/copilot/plan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ command: 'show critical alerts' })
      });
      assert.strictEqual(resPlan.status, 403);
    });

    await testAsync('39. Missing organization_id fails closed with HTTP 403', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenNoOrg}`
        },
        body: JSON.stringify({ command: 'show critical alerts' })
      });
      assert.strictEqual(res.status, 403);
    });

    console.log('--- Group 11: Tenant Isolation ---');

    await testAsync('40. Tenant Isolation: Tenant B cannot execute command or view timeline for Tenant A session', async () => {
      const resTimeline = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}/timeline`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(resTimeline.status, 404);

      const resCmd = await fetch(`${baseUrl}/api/v1/copilot/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystB}`
        },
        body: JSON.stringify({
          command: 'create jira ticket for case 42',
          session_id: sessionA.id
        })
      });
      assert.strictEqual(resCmd.status, 404);
    });

  } finally {
    if (server) {
      server.close();
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runCopilotPhase4Suite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test Suite Fatal Error:', err);
    process.exit(1);
  });
