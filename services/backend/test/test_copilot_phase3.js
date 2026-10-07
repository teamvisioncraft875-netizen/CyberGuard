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
const ThreatIOC = require('../src/models/ThreatIOC');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarCase = require('../src/models/SoarCase');
const SoarApproval = require('../src/models/SoarApproval');
const CopilotSession = require('../src/models/CopilotSession');
const CopilotMessage = require('../src/models/CopilotMessage');
const CopilotSessionAction = require('../src/models/CopilotSessionAction');
const AuditLog = require('../src/models/AuditLog');

const actionRecommendationService = require('../src/services/copilot/actionRecommendationService');
const playbookRecommendationService = require('../src/services/copilot/playbookRecommendationService');
const copilotActionService = require('../src/services/copilot/copilotActionService');
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

async function runCopilotPhase3Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 3: AI Copilot Actions & SOAR Integration Tests');
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
    const orgA = await createOrganizationFixture({ name: 'Tenant Copilot Alpha P3' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Copilot Beta P3' });

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
      title: 'Active Ransomware Encryption & Shadow Copy Deletion on WORKSTATION-99',
      severity: 'critical',
      status: 'new',
      source_type: 'endpoint_edr',
      mitre_technique: 'T1486',
      metadata: { host: 'WORKSTATION-99', ip: '10.0.5.99', target_user: 'svc_backup' }
    });

    const incidentA = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'technical_threat',
      risk_level: 'critical',
      risk_score: 95,
      status: 'open',
      explanation: 'Critical credential dumping activity detected across domain controller.'
    });

    const createIocFn = ThreatIOC.createIOC || ThreatIOC.create;
    const iocA = await createIocFn.call(ThreatIOC, {
      organization_id: orgA.id,
      ioc_type: 'ip',
      ioc_value: '203.0.113.88',
      confidence: 90,
      risk_score: 95,
      threat_actor: 'APT28',
      malware_family: 'FancyBear'
    });

    // Seed SOAR Playbooks for Tenant A
    const playbookA = await SoarPlaybook.create({
      organization_id: orgA.id,
      name: 'Ransomware Emergency Response & Containment Playbook',
      description: 'Isolates endpoint, disables user account, and collects memory artifacts.',
      enabled: true,
      trigger_type: 'alert',
      trigger_conditions: { severity: 'critical', technique: 'T1486' },
      created_by: adminA.id
    });

    // Seed Investigation Session for Tenant A
    const sessionA = await CopilotSession.create({
      organization_id: orgA.id,
      created_by: analystA.id,
      title: 'Ransomware Outbreak on WORKSTATION-99',
      entity_type: 'alert',
      entity_id: alertA.id
    });

    // Mock Copilot Gemini Invocation (ensures zero external API calls)
    copilotService.setMockHandler(async ({ question, sessionActions }) => {
      const actionCount = (sessionActions || []).length;
      return {
        answer: `[MOCKED COPILOT RESPONSE] Analyzed question: "${question}". Recorded session actions in context: ${actionCount}.`,
        tokens_used: 125
      };
    });

    console.log('--- Group 1: Action Recommendations ---');

    // 1. Recommend actions for high-severity endpoint alert
    await testAsync('1. recommendActions for high-severity alert: recommends isolate_endpoint with requires_approval=true', async () => {
      const res = await actionRecommendationService.recommendActions({
        organization_id: orgA.id,
        alert_id: alertA.id,
        actor_id: analystA.id
      });
      assert.ok(res.recommendations.length > 0);
      const isoRec = res.recommendations.find(r => r.action === 'isolate_endpoint');
      assert.ok(isoRec, 'Should recommend isolate_endpoint');
      assert.strictEqual(isoRec.requires_approval, true);
      assert.ok(isoRec.confidence >= 0.85);
    });

    // 2. Recommend actions for IP threat context
    await testAsync('2. recommendActions for IP and C2 threat context: recommends block_ip with requires_approval=true', async () => {
      const res = await actionRecommendationService.recommendActions({
        organization_id: orgA.id,
        ioc_id: iocA.id,
        context: { ip: '203.0.113.88' },
        actor_id: analystA.id
      });
      const blockRec = res.recommendations.find(r => r.action === 'block_ip');
      assert.ok(blockRec, 'Should recommend block_ip');
      assert.strictEqual(blockRec.requires_approval, true);
      assert.ok(blockRec.reason.includes('203.0.113.88'));
    });

    // 3. Recommend actions for account compromise
    await testAsync('3. recommendActions for account compromise: recommends disable_account with requires_approval=true', async () => {
      const res = await actionRecommendationService.recommendActions({
        organization_id: orgA.id,
        context: { user: 'compromised_admin' },
        mitre_technique: 'T1078',
        actor_id: analystA.id
      });
      const userRec = res.recommendations.find(r => r.action === 'disable_account');
      assert.ok(userRec, 'Should recommend disable_account');
      assert.strictEqual(userRec.requires_approval, true);
    });

    // 4. Recommend actions explanation engine
    await testAsync('4. recommendActions explanation engine: returns why, mitre_mapping, threat_evidence, expected_outcome, and risk_level', async () => {
      const res = await actionRecommendationService.recommendActions({
        organization_id: orgA.id,
        alert_id: alertA.id,
        actor_id: analystA.id
      });
      const topRec = res.recommendations[0];
      assert.ok(topRec.explanation);
      assert.ok(topRec.explanation.why);
      assert.ok(topRec.explanation.mitre_mapping);
      assert.ok(topRec.explanation.threat_evidence);
      assert.ok(topRec.explanation.expected_outcome);
      assert.ok(topRec.explanation.risk_level);
    });

    // 5. Recommend actions returns low-risk actions
    await testAsync('5. recommendActions returns low-risk actions: recommends create_soar_case and execute_playbook with requires_approval=false', async () => {
      const res = await actionRecommendationService.recommendActions({
        organization_id: orgA.id,
        alert_id: alertA.id,
        actor_id: analystA.id
      });
      const caseRec = res.recommendations.find(r => r.action === 'create_soar_case');
      assert.ok(caseRec, 'Should recommend create_soar_case');
      assert.strictEqual(caseRec.requires_approval, false);

      const pbRec = res.recommendations.find(r => r.action === 'execute_playbook');
      assert.ok(pbRec, 'Should recommend execute_playbook');
      assert.strictEqual(pbRec.requires_approval, false);
    });

    console.log('--- Group 2: Playbook Recommendations ---');

    // 6. Recommend playbooks for natural language query
    await testAsync('6. recommendPlaybooks for natural language ransomware query: discovers matching ransomware playbooks', async () => {
      const res = await playbookRecommendationService.recommendPlaybooks({
        organization_id: orgA.id,
        query: 'What playbook should I run for ransomware?',
        actor_id: analystA.id
      });
      assert.ok(res.recommendations.length > 0);
      const topMatch = res.recommendations[0];
      assert.ok(topMatch.name.toLowerCase().includes('ransomware'));
      assert.ok(topMatch.confidence >= 0.80);
    });

    // 7. Rank playbooks with confidence score and human-readable reasoning
    await testAsync('7. recommendPlaybooks ranking: calculates confidence score and explains match reason', async () => {
      const res = await playbookRecommendationService.recommendPlaybooks({
        organization_id: orgA.id,
        query: 'What playbook should I run for ransomware?',
        threat_type: 'ransomware',
        actor_id: analystA.id
      });
      const match = res.recommendations[0];
      assert.ok(match.confidence >= 0.90);
      assert.ok(match.reason && match.reason.length > 10);
      assert.ok(match.trigger_type);
    });

    // 8. Recommend playbooks by MITRE technique
    await testAsync('8. recommendPlaybooks with MITRE technique: ranks technique-mapped playbooks', async () => {
      const res = await playbookRecommendationService.recommendPlaybooks({
        organization_id: orgA.id,
        mitre_technique: 'T1486',
        actor_id: analystA.id
      });
      assert.ok(res.recommendations.length > 0);
      assert.ok(res.recommendations.some(r => r.playbook_id === playbookA.id));
    });

    console.log('--- Group 3: SOAR Case Creation ---');

    let createdCaseId;

    // 9. Create SOAR Case via Copilot bridge
    await testAsync('9. createSoarCase via Copilot bridge: provisions case with linked alert and findings', async () => {
      const soarCase = await copilotActionService.createSoarCase({
        organization_id: orgA.id,
        session_id: sessionA.id,
        title: 'Investigation: Ransomware Lateral Containment',
        description: 'Auto-promoted from Copilot analysis of WORKSTATION-99',
        severity: 'critical',
        priority: 'high',
        alert_id: alertA.id,
        created_by: analystA.id
      });
      assert.ok(soarCase.id);
      assert.strictEqual(soarCase.title, 'Investigation: Ransomware Lateral Containment');
      assert.strictEqual(soarCase.organization_id, orgA.id);
      createdCaseId = soarCase.id;
    });

    // 10. Escalate SOAR Case via Copilot bridge
    await testAsync('10. escalateCase via Copilot bridge: updates case priority and severity to critical', async () => {
      const updatedCase = await copilotActionService.escalateCase({
        organization_id: orgA.id,
        session_id: sessionA.id,
        case_id: createdCaseId,
        reason: 'Multiple secondary systems show signs of shadow copy tampering',
        new_priority: 'critical',
        new_severity: 'critical',
        actor_id: analystA.id
      });
      assert.strictEqual(updatedCase.priority, 'critical');
      assert.strictEqual(updatedCase.severity, 'critical');
    });

    console.log('--- Group 4: Playbook Execution ---');

    // 11. Launch Playbook via Copilot bridge
    await testAsync('11. launchPlaybook via Copilot bridge: initiates SOAR execution and records status', async () => {
      const executions = await copilotActionService.launchPlaybook({
        organization_id: orgA.id,
        session_id: sessionA.id,
        playbook_id: playbookA.id,
        alert_id: alertA.id,
        context: { host: 'WORKSTATION-99' },
        actor_id: analystA.id
      });
      assert.ok(Array.isArray(executions));
    });

    // 12. Execute low-risk action directly via Copilot execute-action API
    await testAsync('12. execute-action API: executes low-risk action directly and returns status executed', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'create_ticket',
          payload: { title: 'Ticket: Verify Backup Restoration on WORKSTATION-99', priority: 'high' },
          reason: 'Escalated ticketing for recovery validation'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'executed');
      assert.strictEqual(data.requires_approval, false);
    });

    console.log('--- Group 5: Approval Gating ---');

    let pendingApprovalId;

    // 13. Gating high-risk action: Endpoint isolation
    await testAsync('13. Gating high-risk action: isolate_endpoint returns status pending_approval with requires_approval=true', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'isolate_endpoint',
          payload: { host: 'WORKSTATION-99' },
          reason: 'Emergency isolation required due to active encryptor'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'pending_approval');
      assert.strictEqual(data.requires_approval, true);
      assert.ok(data.approval_id);
      pendingApprovalId = data.approval_id;
    });

    // 14. Gating high-risk action: Firewall IP block
    await testAsync('14. Gating high-risk action: block_ip queues SOAR approval request', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'block_ip',
          payload: { ip: '203.0.113.88' },
          reason: 'Perimeter quarantine for C2 traffic'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'pending_approval');
      assert.strictEqual(data.requires_approval, true);
    });

    // 15. Analysts cannot bypass approval
    await testAsync('15. Analysts cannot bypass approval: high-risk action requires approved status regardless of caller', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'isolate_endpoint',
          payload: { host: 'DC-PRIMARY', bypass_approval: true },
          reason: 'Attempted bypass'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      // Must still be gated as pending_approval
      assert.strictEqual(data.status, 'pending_approval');
      assert.strictEqual(data.requires_approval, true);
    });

    // 16. Execution after approval
    await testAsync('16. Execution after approval: pre-approved approval record executes high-risk action cleanly', async () => {
      // Mark the pending approval as approved in DB
      await SoarApproval.decide(pendingApprovalId, {
        status: 'approved',
        decided_by: adminA.id,
        reason: 'Authorized execution by SOC Supervisor'
      });

      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'isolate_endpoint',
          payload: { host: 'WORKSTATION-99', approval_id: pendingApprovalId },
          reason: 'Authorized execution by SOC Supervisor'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.status, 'executed');
      assert.strictEqual(data.requires_approval, false);
    });

    console.log('--- Group 6: Conversation Action Memory ---');

    // 17. recommendActions with session_id stores memory
    await testAsync('17. recommendActions with session_id: stores recommended actions into conversation action memory', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/recommend-actions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          alert_id: alertA.id
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.data.recommendations.length > 0);
    });

    // 18. executeAction with session_id stores memory
    await testAsync('18. executeAction with session_id: stores executed action into session memory', async () => {
      const actions = await CopilotSessionAction.findBySession(sessionA.id, orgA.id);
      assert.ok(actions.length > 0);
      assert.ok(actions.some(a => a.status === 'executed'));
    });

    // 19. GET /api/v1/copilot/sessions/:id/actions
    await testAsync('19. GET /api/v1/copilot/sessions/:id/actions: retrieves session actions with summary breakdown', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}/actions`, {
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.session_id, sessionA.id);
      assert.ok(data.data.actions.length > 0);
      assert.ok(data.data.summary);
      assert.ok(data.data.summary.total > 0);
    });

    // 20. Multi-turn session message integrates recorded action context
    await testAsync('20. Multi-turn session integration: postMessage incorporates recorded actions in copilot context', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          question: 'What actions did we execute during this investigation?'
        })
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(data.answer.includes('[MOCKED COPILOT RESPONSE]'));
    });

    console.log('--- Group 7: Audit Logging ---');

    // 21. Records COPILOT_ACTION_RECOMMENDED audit event
    await testAsync('21. Audit logging: records COPILOT_ACTION_RECOMMENDED audit event', async () => {
      const logs = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_ACTION_RECOMMENDED',
        limit: 5
      });
      assert.ok(logs.logs.length > 0);
    });

    // 22. Records COPILOT_PLAYBOOK_RECOMMENDED audit event
    await testAsync('22. Audit logging: records COPILOT_PLAYBOOK_RECOMMENDED audit event', async () => {
      const logs = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_PLAYBOOK_RECOMMENDED',
        limit: 5
      });
      assert.ok(logs.logs.length > 0);
    });

    // 23. Records COPILOT_ACTION_EXECUTED audit event
    await testAsync('23. Audit logging: records COPILOT_ACTION_EXECUTED audit event', async () => {
      const logs = await AuditLog.list({
        organization_id: orgA.id,
        action: 'COPILOT_ACTION_EXECUTED',
        limit: 5
      });
      assert.ok(logs.logs.length > 0);
    });

    console.log('--- Group 8: RBAC Validation ---');

    // 24. Employee access denied on recommend-actions
    await testAsync('24. RBAC validation: employee receives HTTP 403 Forbidden on recommend-actions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/recommend-actions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ alert_id: alertA.id })
      });
      assert.strictEqual(res.status, 403);
    });

    // 25. Employee access denied on execute-action
    await testAsync('25. RBAC validation: employee receives HTTP 403 Forbidden on execute-action', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ action_type: 'create_ticket' })
      });
      assert.strictEqual(res.status, 403);
    });

    // 26. Employee access denied on recommend-playbooks
    await testAsync('26. RBAC validation: employee receives HTTP 403 Forbidden on recommend-playbooks', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/recommend-playbooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({ query: 'What playbook should I run?' })
      });
      assert.strictEqual(res.status, 403);
    });

    // 27. Missing organization_id fails closed
    await testAsync('27. Missing organization_id: fails closed with HTTP 403', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/recommend-actions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenNoOrg}`
        },
        body: JSON.stringify({ alert_id: alertA.id })
      });
      assert.strictEqual(res.status, 403);
    });

    console.log('--- Group 9: Tenant Isolation ---');

    // 28. Tenant B cannot retrieve Tenant A session actions
    await testAsync('28. Tenant isolation: Tenant B cannot retrieve Tenant A session actions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/sessions/${sessionA.id}/actions`, {
        headers: { Authorization: `Bearer ${tokenAnalystB}` }
      });
      assert.strictEqual(res.status, 404);
    });

    // 29. Tenant B cannot execute actions on Tenant A cases or sessions
    await testAsync('29. Tenant isolation: Tenant B cannot execute actions on Tenant A cases or sessions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/execute-action`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystB}`
        },
        body: JSON.stringify({
          session_id: sessionA.id,
          action_type: 'escalate_case',
          payload: { case_id: createdCaseId }
        })
      });
      assert.strictEqual(res.status, 404);
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

runCopilotPhase3Suite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test Suite Fatal Error:', err);
    process.exit(1);
  });
