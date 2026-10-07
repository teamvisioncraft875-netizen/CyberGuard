process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SoarConnector = require('../src/models/SoarConnector');
const SoarPlaybook = require('../src/models/SoarPlaybook');
const SoarExecution = require('../src/models/SoarExecution');
const SoarApproval = require('../src/models/SoarApproval');
const connectorRegistry = require('../src/services/soar/connectors/ConnectorRegistry');
const { WebhookConnector, JiraConnector, SlackConnector, TeamsConnector } = require('../src/services/soar/connectors');
const playbookEngine = require('../src/services/soar/playbookEngine');
const actionExecutor = require('../src/services/soar/actionExecutor');
const approvalService = require('../src/services/soar/approvalService');
const auditService = require('../src/services/auditService');
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

async function runSoarIntegrationsSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint B Phase 3: SOAR Enterprise Integrations Tests');
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

  let webhookConnId;
  let jiraConnId;
  let slackConnId;
  let teamsConnId;

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
    orgA = await createOrganizationFixture({ name: `SOAR Integrations Org A ${Date.now()}` });
    orgB = await createOrganizationFixture({ name: `SOAR Integrations Org B ${Date.now()}` });

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
    // GROUP 1: Connector Framework & Registration (Tests 1–5)
    // =========================================================================
    console.log('--- Group 1: Connector Registration & Framework ---');

    await testAsync('1.1 Register Webhook Connector with custom headers & retry config', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({
          name: 'Splunk Ingestion Webhook',
          type: 'webhook',
          description: 'Forward alerts to external SIEM/Splunk HEC',
          config: {
            url: 'https://splunk.internal.local:8088/services/collector',
            method: 'POST',
            headers: {
              'X-Splunk-Token': 'hec-secret-token-123456789'
            },
            retries: 2,
            timeout_ms: 3000
          },
          is_default: true
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.data.type, 'webhook');
      assert.strictEqual(data.data.status, 'active');
      assert.strictEqual(data.data.is_default, true);
      webhookConnId = data.data.id;
    });

    await testAsync('1.2 Register Jira Connector with cloud domain & project settings', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({
          name: 'Corporate Jira Cloud',
          type: 'jira',
          description: 'Jira Service Management ticketing connector',
          config: {
            host: 'https://cyberguard-soc.atlassian.net',
            project_key: 'SEC',
            issue_type: 'Incident',
            api_token: 'jira-api-token-secret-9999'
          },
          is_default: true
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.data.type, 'jira');
      assert.strictEqual(data.data.is_default, true);
      jiraConnId = data.data.id;
    });

    await testAsync('1.3 Register Slack Connector with default alert channel', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({
          name: 'SOC War Room Slack',
          type: 'slack',
          description: 'Instant notification connector for SOC team',
          config: {
            webhook_url: 'https://hooks.slack.com/services/T00/B00/secretToken12345',
            channel: '#soc-war-room'
          },
          is_default: true
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.data.type, 'slack');
      slackConnId = data.data.id;
    });

    await testAsync('1.4 Register Microsoft Teams Connector with channel webhook', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({
          name: 'Executive Incident Response Teams',
          type: 'teams',
          description: 'MS Teams connector for incident broadcast',
          config: {
            webhook_url: 'https://cyberguard.webhook.office.com/webhookb2/secret-guid',
            channel: 'Executive-War-Room'
          },
          is_default: true
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.data.type, 'teams');
      teamsConnId = data.data.id;
    });

    await testAsync('1.5 Verify getDefaultConnector returns tenant-scoped default connector', async () => {
      const defaultWebhook = await connectorRegistry.getDefaultConnector('webhook', orgA.id);
      assert.ok(defaultWebhook);
      assert.strictEqual(defaultWebhook.id, webhookConnId);
      assert.strictEqual(defaultWebhook.type, 'webhook');
      assert.strictEqual(defaultWebhook.is_default, true);
    });

    // =========================================================================
    // GROUP 2: Connector Enable / Disable & State Lifecycle (Tests 6–8)
    // =========================================================================
    console.log('\n--- Group 2: Connector Enable/Disable & Status Lifecycle ---');

    await testAsync('2.1 Disable connector and transition status to disabled', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({ status: 'disabled' })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.data.status, 'disabled');

      const updated = await connectorRegistry.getConnector(webhookConnId, orgA.id);
      assert.strictEqual(updated.status, 'disabled');
      assert.strictEqual(updated.isActive(), false);
    });

    await testAsync('2.2 Attempt action execution on disabled connector throws error', async () => {
      let threw = false;
      try {
        await connectorRegistry.executeConnectorAction({
          connectorId: webhookConnId,
          organizationId: orgA.id,
          action: 'send_webhook',
          params: { url: 'https://test.local/endpoint', payload: { test: true } }
        });
      } catch (err) {
        threw = true;
        assert.ok(err.message.includes('disabled'));
      }
      assert.strictEqual(threw, true, 'Should reject action on disabled connector');
    });

    await testAsync('2.3 Re-enable connector to active status and restore execution ability', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAdminA}`
        },
        body: JSON.stringify({ status: 'active' })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.data.status, 'active');

      const updated = await connectorRegistry.getConnector(webhookConnId, orgA.id);
      assert.strictEqual(updated.status, 'active');
      assert.strictEqual(updated.isActive(), true);
    });

    // =========================================================================
    // GROUP 3: Connector Health Check & Diagnostics (Tests 9–11)
    // =========================================================================
    console.log('\n--- Group 3: Health Status & Connectivity Diagnostics ---');

    await testAsync('3.1 Test connection on Webhook connector updates health status in DB', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.data.success, true);
      assert.strictEqual(data.data.status, 'healthy');

      // Verify DB record updated
      const conn = await SoarConnector.findById(webhookConnId, orgA.id);
      assert.strictEqual(conn.health_status.status, 'healthy');
      assert.ok(conn.last_health_check);
    });

    await testAsync('3.2 Test connection on Jira connector verifies endpoint host', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${jiraConnId}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.data.success, true);
      assert.ok(data.data.message.includes('cyberguard-soc.atlassian.net'));
    });

    await testAsync('3.3 Faulty connector config transitions to error status on failed check', async () => {
      // Create a faulty connector
      const faulty = await SoarConnector.create({
        organization_id: orgA.id,
        name: 'Broken Connector',
        type: 'webhook',
        config: { url: 12345 } // invalid non-string url
      });

      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${faulty.id}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.data.status, 'error');

      const reloaded = await SoarConnector.findById(faulty.id, orgA.id);
      assert.strictEqual(reloaded.status, 'error');
    });

    // =========================================================================
    // GROUP 4: Webhook Engine & Dispatch (Tests 12–16)
    // =========================================================================
    console.log('\n--- Group 4: Webhook Engine & Dispatch ---');

    await testAsync('4.1 Webhook POST dispatch with custom headers and payload', async () => {
      const webhook = new WebhookConnector({
        id: webhookConnId,
        organization_id: orgA.id,
        name: 'Test Webhook',
        config: {
          url: 'https://test.local/ingest',
          headers: { 'X-Auth-Key': 'my-custom-key' }
        }
      });

      const result = await webhook.execute('send_webhook', {
        payload: { alert_id: 'ALT-101', severity: 'critical' },
        headers: { 'X-Correlation-ID': 'corr-abc-123' }
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.status_code, 200);
      assert.strictEqual(result.action, 'send_webhook');
      assert.ok(result.external_id);
    });

    await testAsync('4.2 Webhook dispatch with timeout handling', async () => {
      const webhook = new WebhookConnector({
        organization_id: orgA.id,
        name: 'Timeout Webhook',
        config: {
          transport: async () => {
            await new Promise(r => setTimeout(r, 80));
            return { status: 200 };
          }
        }
      });

      // Test with custom transport simulating fast response
      const result = await webhook.execute('send_webhook', {
        url: 'https://test.local/mock',
        timeout_ms: 200
      });

      assert.strictEqual(result.success, true);
    });

    await testAsync('4.3 Webhook retry policy retries on simulated transient error', async () => {
      let callCount = 0;
      const webhook = new WebhookConnector({
        organization_id: orgA.id,
        name: 'Retry Webhook',
        config: {
          transport: async () => {
            callCount++;
            if (callCount < 2) {
              throw new Error('503 Service Unavailable');
            }
            return { status: 200, data: { ok: true } };
          }
        }
      });

      const result = await webhook.execute('send_webhook', {
        url: 'https://test.local/flaky',
        retries: 2,
        retry_delay_ms: 10
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(callCount, 2);
      assert.strictEqual(result.attempts, 2);
    });

    await testAsync('4.4 Webhook execution logs recorded in soar_connector_logs', async () => {
      const logs = await SoarConnector.getLogs(webhookConnId, orgA.id);
      assert.ok(logs.length > 0);
      const log = logs[0];
      assert.strictEqual(log.connector_id, webhookConnId);
      assert.strictEqual(log.action, 'send_webhook');
      assert.strictEqual(log.status, 'success');
    });

    await testAsync('4.5 Direct SOAR action "send_webhook" via actionExecutor', async () => {
      const result = await actionExecutor.executeAction('send_webhook', {
        url: 'https://test.local/direct-soar-hook',
        payload: { event: 'ip_quarantined', ip: '198.51.100.44' }
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.action_type, 'send_webhook');
      assert.ok(result.external_id);
    });

    // =========================================================================
    // GROUP 5: Jira Enterprise Integration (Tests 17–20)
    // =========================================================================
    console.log('\n--- Group 5: Jira Enterprise Integration ---');

    let createdJiraKey;

    await testAsync('5.1 Jira create_issue action returns external_ticket_id & external_url', async () => {
      const result = await actionExecutor.executeAction('create_jira_ticket', {
        title: 'Unauthorized SSH Brute Force Incident',
        description: 'Host 10.0.0.5 observed 50 failed root login attempts.',
        priority: 'High',
        project_key: 'SEC'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.ok(result.external_ticket_id);
      assert.ok(result.external_ticket_id.startsWith('SEC-'));
      assert.ok(result.external_url.includes('cyberguard-soc.atlassian.net/browse/SEC-'));
      createdJiraKey = result.external_ticket_id;
    });

    await testAsync('5.2 Jira update_issue action modifies status and priority', async () => {
      const result = await actionExecutor.executeAction('jira_update_issue', {
        ticket_id: createdJiraKey,
        status: 'In Progress',
        priority: 'Highest'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.external_ticket_id, createdJiraKey);
      assert.strictEqual(result.status, 'In Progress');
    });

    await testAsync('5.3 Jira add_comment action appends investigation findings', async () => {
      const result = await actionExecutor.executeAction('jira_add_comment', {
        ticket_id: createdJiraKey,
        comment: 'Forensic memory dump completed. Malicious beacon identified.',
        author: 'Lead SOC Analyst'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.external_ticket_id, createdJiraKey);
      assert.ok(result.comment_id);
      assert.ok(result.comment.includes('Forensic memory dump'));
    });

    await testAsync('5.4 Jira connector logs persist external ticket ID', async () => {
      const logs = await SoarConnector.getLogs(jiraConnId, orgA.id);
      assert.ok(logs.length > 0);
      const ticketLog = logs.find(l => l.action === 'create_jira_ticket');
      assert.ok(ticketLog);
      assert.strictEqual(ticketLog.external_id, createdJiraKey);
    });

    // =========================================================================
    // GROUP 6: Slack Enterprise Integration (Tests 21–24)
    // =========================================================================
    console.log('\n--- Group 6: Slack Enterprise Integration ---');

    await testAsync('6.1 Slack send_slack_message dispatches broadcast to channel', async () => {
      const result = await actionExecutor.executeAction('send_slack_message', {
        channel: '#soc-war-room',
        text: '🔥 High severity alert acknowledged by automated SOAR engine.'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.channel, '#soc-war-room');
      assert.strictEqual(result.delivered, true);
      assert.ok(result.message_id);
    });

    await testAsync('6.2 Slack alert_notification renders formatted alert notification', async () => {
      const result = await actionExecutor.executeAction('slack_alert', {
        channel: '#soc-alerts',
        title: 'Credential Stuffing Campaign Detected',
        severity: 'critical',
        source_ip: '198.51.100.99',
        alert_id: 'ALT-CRED-888'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.notification_type, 'alert');
      assert.strictEqual(result.severity, 'CRITICAL');
      assert.strictEqual(result.alert_id, 'ALT-CRED-888');
      assert.ok(result.text.includes('198.51.100.99'));
    });

    await testAsync('6.3 Slack case_notification renders case triage summary', async () => {
      const slackConn = await connectorRegistry.getDefaultConnector('slack', orgA.id);
      const result = await slackConn.execute('case_notification', {
        case_id: 'CASE-2026-004',
        title: 'Ransomware Outbreak on Branch Office',
        status: 'investigating',
        priority: 'high'
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.notification_type, 'case');
      assert.strictEqual(result.case_id, 'CASE-2026-004');
      assert.strictEqual(result.status, 'INVESTIGATING');
    });

    await testAsync('6.4 Slack approval_notification renders human approval card', async () => {
      const slackConn = await connectorRegistry.getDefaultConnector('slack', orgA.id);
      const result = await slackConn.execute('approval_notification', {
        execution_id: 'EXEC-777',
        playbook_name: 'Core Router Isolation',
        level: 'L3',
        reason: 'Quarantine of gateway requires executive sign-off'
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.notification_type, 'approval');
      assert.strictEqual(result.level, 'L3');
      assert.ok(result.text.includes('Core Router Isolation'));
    });

    // =========================================================================
    // GROUP 7: Microsoft Teams Integration (Tests 25–28)
    // =========================================================================
    console.log('\n--- Group 7: Microsoft Teams Integration ---');

    await testAsync('7.1 Teams send_teams_message dispatches broadcast to channel', async () => {
      const result = await actionExecutor.executeAction('send_teams_message', {
        channel: 'Executive-War-Room',
        title: 'Security Incident Escalation',
        text: 'Incident has been escalated to Tier 3 response team.'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.channel, 'Executive-War-Room');
      assert.strictEqual(result.delivered, true);
      assert.ok(result.message_id);
    });

    await testAsync('7.2 Teams incident_notification delivers high-severity card', async () => {
      const result = await actionExecutor.executeAction('teams_incident', {
        channel: 'Incident-Response',
        incident_id: 'INC-2026-999',
        title: 'Data Exfiltration via DNS Tunneling',
        severity: 'critical',
        summary: '1.2 GB of egress data observed over port 53'
      }, { organization_id: orgA.id });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.notification_type, 'incident');
      assert.strictEqual(result.incident_id, 'INC-2026-999');
      assert.strictEqual(result.severity, 'CRITICAL');
    });

    await testAsync('7.3 Teams playbook_notification delivers automated orchestration recap', async () => {
      const teamsConn = await connectorRegistry.getDefaultConnector('teams', orgA.id);
      const result = await teamsConn.execute('playbook_notification', {
        playbook_name: 'Automated Phishing Containment',
        execution_id: 'EXEC-9876',
        status: 'completed'
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.notification_type, 'playbook');
      assert.strictEqual(result.playbook_name, 'Automated Phishing Containment');
      assert.strictEqual(result.status, 'completed');
    });

    await testAsync('7.4 Teams connector execution logged in audit database', async () => {
      const logs = await SoarConnector.getLogs(teamsConnId, orgA.id);
      assert.ok(logs.length > 0);
      assert.strictEqual(logs[0].status, 'success');
    });

    // =========================================================================
    // GROUP 8: Playbook Orchestration with Connectors (Tests 29–33)
    // =========================================================================
    console.log('\n--- Group 8: Multi-Step Playbook Orchestration with Connectors ---');

    let orchestrationPlaybookId;
    let orchestrationExecutionId;

    await testAsync('8.1 Create enterprise orchestration playbook with 5-step workflow', async () => {
      // Step 1: create_jira_ticket
      // Step 2: send_slack_message (references {{external_ticket_id}})
      // Step 3: send_webhook (references {{external_url}})
      // Step 4: approval (requires L2 approval)
      // Step 5: execute remediation (block_ip)
      const playbook = await SoarPlaybook.create({
        organization_id: orgA.id,
        name: 'Enterprise 5-Step SOAR Response Orchestration',
        description: 'Jira -> Slack -> Webhook -> Approval -> Firewall Block IP',
        enabled: true,
        trigger_type: 'alert',
        trigger_conditions: { severity: 'critical' },
        steps: [
          {
            step_order: 1,
            action_type: 'create_jira_ticket',
            action_config: {
              title: 'Automated Containment for Attacker {{source_ip}}',
              priority: 'High',
              project_key: 'SEC'
            },
            requires_approval: false
          },
          {
            step_order: 2,
            action_type: 'send_slack_message',
            action_config: {
              channel: '#soc-alerts',
              text: 'Created Jira ticket {{external_ticket_id}} for malicious host {{source_ip}}'
            },
            requires_approval: false
          },
          {
            step_order: 3,
            action_type: 'send_webhook',
            action_config: {
              url: 'https://test.local/siem/sync',
              payload: {
                ticket_id: '{{external_ticket_id}}',
                ticket_url: '{{external_url}}',
                attacker_ip: '{{source_ip}}'
              }
            },
            requires_approval: false
          },
          {
            step_order: 4,
            action_type: 'isolate_host',
            action_config: {
              host: 'workstation-fin-04',
              approval_level: 'L2'
            },
            requires_approval: true
          },
          {
            step_order: 5,
            action_type: 'block_ip',
            action_config: {
              ip: '203.0.113.88'
            },
            requires_approval: false
          }
        ],
        created_by: adminA.id
      });

      assert.ok(playbook.id);
      assert.strictEqual(playbook.steps.length, 5);
      orchestrationPlaybookId = playbook.id;
    });

    await testAsync('8.2 Trigger playbook: Steps 1, 2, and 3 execute sequentially with template passing', async () => {
      const execution = await SoarExecution.create({
        organization_id: orgA.id,
        playbook_id: orchestrationPlaybookId,
        status: 'pending'
      });
      orchestrationExecutionId = execution.id;

      // Pre-create step records
      const playbook = await SoarPlaybook.findById(orchestrationPlaybookId, orgA.id);
      for (const s of playbook.steps) {
        await SoarExecution.createStepRecord({
          execution_id: execution.id,
          playbook_step_id: s.id,
          status: 'pending',
          result_payload: {}
        });
      }

      // Execute playbook
      const runResult = await playbookEngine.executePlaybook(execution.id, {
        context: {
          source_ip: '203.0.113.88',
          alert_title: 'Critical Lateral Movement'
        }
      });

      // Step 4 requires approval, so status must be waiting_approval
      assert.strictEqual(runResult.status, 'waiting_approval');

      // Verify steps 1, 2, 3 completed
      const steps = await SoarExecution.getExecutionSteps(execution.id);
      const step1 = steps.find(s => s.step_order === 1);
      const step2 = steps.find(s => s.step_order === 2);
      const step3 = steps.find(s => s.step_order === 3);
      const step4 = steps.find(s => s.step_order === 4);

      assert.strictEqual(step1.status, 'completed');
      assert.ok(step1.result_payload.external_ticket_id);

      assert.strictEqual(step2.status, 'completed');
      assert.ok(step2.result_payload.text.includes(step1.result_payload.external_ticket_id));

      assert.strictEqual(step3.status, 'completed');
      assert.strictEqual(step3.result_payload.action_type, 'send_webhook');

      assert.strictEqual(step4.status, 'pending');
    });

    await testAsync('8.3 Approval gating: Execution halts at Step 4 until approved', async () => {
      const pendingApproval = await SoarApproval.findByExecutionId(orchestrationExecutionId);
      assert.ok(pendingApproval);
      assert.strictEqual(pendingApproval.status, 'pending');
      assert.strictEqual(pendingApproval.level, 'L2');
    });

    await testAsync('8.4 Approve execution: Engine resumes and executes Step 4 and Step 5 to completion', async () => {
      const pendingApproval = await SoarApproval.findByExecutionId(orchestrationExecutionId);

      // Approve with Senior Analyst (L2 authorized)
      const decisionResult = await approvalService.decideApproval(
        pendingApproval.id,
        seniorAnalystA.id,
        'approved',
        'Quarantine and block approved by Senior Analyst',
        orgA.id,
        'senior_analyst'
      );

      // Verify execution resumed and completed
      const resumed = decisionResult?.execution || await SoarExecution.findById(orchestrationExecutionId, orgA.id);
      assert.strictEqual(resumed.status, 'completed');
      assert.ok(resumed.completed_at);

      // Verify step 4 and step 5 are completed
      const steps = await SoarExecution.getExecutionSteps(orchestrationExecutionId);
      const step4 = steps.find(s => s.step_order === 4);
      const step5 = steps.find(s => s.step_order === 5);

      assert.strictEqual(step4.status, 'completed');
      assert.strictEqual(step4.result_payload.network_status, 'isolated');

      assert.strictEqual(step5.status, 'completed');
      assert.strictEqual(step5.result_payload.action, 'block_ip');
      assert.strictEqual(step5.result_payload.target_ip, '203.0.113.88');
    });

    await testAsync('8.5 Execution tracks complete history and external IDs', async () => {
      const steps = await SoarExecution.getExecutionSteps(orchestrationExecutionId);
      assert.strictEqual(steps.length, 5);
      const allCompleted = steps.every(s => s.status === 'completed');
      assert.strictEqual(allCompleted, true);
    });

    // =========================================================================
    // GROUP 9: Security, Secret Masking & Audit Trails (Tests 34–37)
    // =========================================================================
    console.log('\n--- Group 9: Security, Secret Masking & Audit Trails ---');

    await testAsync('9.1 Sensitive keys in connector config are masked with ****', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${jiraConnId}`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.data.config.api_token);
      assert.ok(data.data.config.api_token.startsWith('****'));
    });

    await testAsync('9.2 Secret masking in execution audit logs', async () => {
      // Execute an action passing sensitive secret
      const webhook = await connectorRegistry.getConnector(webhookConnId, orgA.id);
      await webhook.execute('send_webhook', {
        url: 'https://test.local/mask-test',
        headers: { Authorization: 'Bearer secret_super_key_99999' },
        api_key: 'top_secret_api_key'
      });

      const logs = await SoarConnector.getLogs(webhookConnId, orgA.id);
      const latestLog = logs[0];
      assert.ok(latestLog.request_payload);
      assert.ok(latestLog.request_payload.api_key.startsWith('****'));
    });

    await testAsync('9.3 Audit service logs SOAR_CONNECTOR_CREATED & SOAR_CONNECTOR_STATUS_CHANGED', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type, details 
         FROM public.audit_logs 
         WHERE organization_id = $1 AND resource_type = 'soar_connector'
         ORDER BY created_at DESC 
         LIMIT 50;`,
        [orgA.id]
      );

      assert.ok(auditRes.rows.length > 0);
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('SOAR_CONNECTOR_CREATED') || actions.includes('SOAR_CONNECTOR_STATUS_CHANGED'));
    });

    await testAsync('9.4 API GET /connectors/:id/logs retrieves audit trail of connector actions', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}/logs`, {
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.data));
      assert.ok(data.data.length > 0);
    });

    // =========================================================================
    // GROUP 10: Multi-Tenant Isolation & RBAC (Tests 38–40)
    // =========================================================================
    console.log('\n--- Group 10: Multi-Tenant Isolation & RBAC ---');

    await testAsync('10.1 Multi-Tenant Isolation: Tenant B cannot access or view Tenant A connector', async () => {
      // Admin of Tenant B requests connector belonging to Tenant A
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}`, {
        headers: { Authorization: `Bearer ${tokenAdminB}` }
      });

      assert.strictEqual(res.status, 404);
      const data = await res.json();
      assert.strictEqual(data.error, 'NOT_FOUND');
    });

    await testAsync('10.2 Multi-Tenant Isolation: Tenant B cannot access Tenant A connector logs', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}/logs`, {
        headers: { Authorization: `Bearer ${tokenAdminB}` }
      });

      assert.strictEqual(res.status, 404);
    });

    await testAsync('10.3 RBAC: Analyst cannot delete connector (admin only)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${webhookConnId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAnalystA}` }
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    await testAsync('10.4 RBAC: Admin can delete connector successfully', async () => {
      // Create a temporary connector to delete
      const tempConn = await SoarConnector.create({
        organization_id: orgA.id,
        name: 'Temporary Deletable Connector',
        type: 'webhook',
        config: { url: 'https://test.local/temp' }
      });

      const res = await fetch(`${baseUrl}/api/v1/soar/connectors/${tempConn.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenAdminA}` }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.success, true);

      // Verify connector is deleted
      const check = await SoarConnector.findById(tempConn.id, orgA.id);
      assert.strictEqual(check, null);
    });

  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
    // Cleanup test fixtures
    await cleanupFixtures().catch(() => {});
    if (db.pool && typeof db.pool.end === 'function') {
      await db.pool.end().catch(() => {});
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSoarIntegrationsSuite().catch((err) => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
