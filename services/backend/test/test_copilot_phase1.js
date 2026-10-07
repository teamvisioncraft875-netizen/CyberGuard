process.env.NODE_ENV = 'test';
process.env.SKIP_RATE_LIMIT = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!';

const assert = require('assert');
const jwt = require('jsonwebtoken');
const { app } = require('../src');
const db = require('../src/config/db');

const SiemAlert = require('../src/models/SiemAlert');
const Incident = require('../src/models/Incident');
const ThreatIOC = require('../src/models/ThreatIOC');
const copilotService = require('../src/services/copilot/copilotService');
const contextRetriever = require('../src/services/copilot/contextRetriever');
const promptBuilder = require('../src/services/copilot/promptBuilder');

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

async function runCopilotPhase1Suite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Sprint C Phase 1: AI Security Copilot (RAG-Based Assistant)');
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
    const orgA = await createOrganizationFixture({ name: 'Tenant Copilot Alpha' });
    const orgB = await createOrganizationFixture({ name: 'Tenant Copilot Beta' });

    const adminA = await createUserFixture({ organization_id: orgA.id, role: 'admin' });
    const analystA = await createUserFixture({ organization_id: orgA.id, role: 'analyst' });
    const employeeA = await createUserFixture({ organization_id: orgA.id, role: 'employee' });

    const analystB = await createUserFixture({ organization_id: orgB.id, role: 'analyst' });

    const tokenAdminA = createToken(adminA);
    const tokenAnalystA = createToken(analystA);
    const tokenSeniorAnalystA = createToken(analystA, 'senior_analyst');
    const tokenEmployeeA = createToken(employeeA);
    const tokenAnalystB = createToken(analystB);
    const tokenNoOrg = createToken(analystA, 'analyst', null);

    // 2. Seed Data for Tenant A
    const alertA = await SiemAlert.create({
      organization_id: orgA.id,
      title: 'Cobalt Strike C2 Beaconing Detected',
      severity: 'critical',
      status: 'open',
      source: 'zeek_network',
      mitre_technique: 'T1071.001',
      metadata: { c2_ip: '198.51.100.99', port: 443 },
      raw_event: { connection_count: 512, jitter: 15 }
    });

    const incidentA = await Incident.create({
      organization_id: orgA.id,
      threat_type: 'technical_threat',
      risk_level: 'critical',
      risk_score: 95,
      status: 'investigating',
      explanation: 'Domain Controller LockBit Ransomware Infiltration. Adversary breached perimeter via compromised credentials and attempted LockBit staging.'
    });

    const createIocFn = ThreatIOC.createIOC || ThreatIOC.create;
    const iocA = await createIocFn.call(ThreatIOC, {
      organization_id: orgA.id,
      ioc_type: 'sha256',
      ioc_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      confidence: 95,
      risk_score: 98,
      threat_actor: 'FIN7 / Carbanak',
      malware_family: 'LockBit',
      tags: ['ransomware', 'critical']
    });

    const playbookRes = await db.query(
      `INSERT INTO public.soar_playbooks (organization_id, name, description, trigger_type, enabled, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *;`,
      [
        orgA.id,
        'Ransomware Perimeter Quarantine & Host Containment',
        'Isolate affected host and block ingress/egress IP communications on firewall',
        'manual',
        true,
        adminA.id
      ]
    );
    const playbookA = playbookRes.rows[0];

    console.log('--- Copilot Functional & Security Validations ---');

    // 1. Alert explanation flow
    await testAsync('1. Alert explanation flow: returns grounded explanation, sources & tokens', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'explain_alert',
          entity_id: alertA.id,
          question: 'What is the risk and MITRE technique for this alert?'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('Cobalt Strike') || data.answer.includes('ALERT EXPLANATION'));
      assert.ok(Array.isArray(data.sources));
      assert.ok(data.sources.some(s => s.id === alertA.id));
      assert.ok(typeof data.tokens_used === 'number');
      assert.ok(data.tokens_used > 0);
    });

    // 2. Incident explanation flow
    await testAsync('2. Incident explanation flow: synthesizes incident scope and tactics', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'explain_incident',
          entity_id: incidentA.id,
          question: 'Summarize the incident scope and affected assets'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('Domain Controller') || data.answer.includes('INCIDENT EXPLANATION'));
      assert.ok(data.sources.some(s => s.id === incidentA.id));
    });

    // 3. IOC summarization
    await testAsync('3. IOC summarization: explains reputation, actor attribution and malware family', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenSeniorAnalystA}`
        },
        body: JSON.stringify({
          type: 'summarize_ioc',
          entity_id: iocA.id,
          question: 'Provide threat intel summary for this file hash'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('IOC INTELLIGENCE SUMMARY') || data.answer.includes('LockBit') || data.answer.includes('FIN7'));
      assert.ok(data.sources.some(s => s.id === iocA.id));
    });

    // 4. Playbook recommendation
    await testAsync('4. Playbook recommendation: identifies matching SOAR playbook for the threat', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'recommend_playbook',
          entity_id: alertA.id,
          question: 'Which playbook should be deployed to contain this outbreak?'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('PLAYBOOK RECOMMENDATION') || data.answer.includes('Playbook'));
      assert.ok(data.sources.some(s => s.type === 'soar_playbook'));
    });

    // 5. Investigation step generation
    await testAsync('5. Investigation step generation: returns prioritized, actionable SOC triage steps', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'investigation_steps',
          entity_id: alertA.id,
          question: 'What are the first 4 investigation steps for this host?'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('INVESTIGATION STEPS') || data.answer.includes('Triage'));
    });

    // 6. Organization isolation
    await testAsync('6. Organization isolation: Tenant B query cannot access or leak Tenant A records', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystB}`
        },
        body: JSON.stringify({
          type: 'explain_alert',
          entity_id: alertA.id,
          question: 'Explain alert from tenant A'
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      // Tenant B query must NOT list Tenant A alert as source
      assert.ok(!data.sources.some(s => s.id === alertA.id));
      assert.ok(!data.sources.some(s => s.id === iocA.id));
      assert.ok(!data.sources.some(s => s.id === playbookA.id));
    });

    // 7. Employee access denied
    await testAsync('7. Employee access denied: employee role receives HTTP 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenEmployeeA}`
        },
        body: JSON.stringify({
          type: 'explain_alert',
          entity_id: alertA.id,
          question: 'Explain alert'
        })
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    // 8. Missing organization denied
    await testAsync('8. Missing organization denied: fails closed with HTTP 403 when organization_id is null', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenNoOrg}`
        },
        body: JSON.stringify({
          type: 'explain_alert',
          entity_id: alertA.id,
          question: 'Explain alert'
        })
      });

      assert.strictEqual(res.status, 403);
      const data = await res.json();
      assert.strictEqual(data.error, 'FORBIDDEN');
    });

    // 9. Gemini timeout fallback
    await testAsync('9. Gemini timeout fallback: gracefully handles short timeout without throwing', async () => {
      const res = await fetch(`${baseUrl}/api/v1/copilot/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenAnalystA}`
        },
        body: JSON.stringify({
          type: 'generate_analyst_note',
          entity_id: incidentA.id,
          question: 'Generate handover note',
          timeoutMs: 1 // Trigger instant abort/timeout
        })
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.ok(data.answer);
      assert.ok(data.answer.includes('ANALYST SHIFT HANDOVER NOTE') || data.answer.includes('Handover'));
      assert.ok(data.tokens_used > 0);
    });

    // 10. Audit logs generated
    await testAsync('10. Audit logs generated: records COPILOT_QUERY and COPILOT_CONTEXT_RETRIEVED without raw prompt content', async () => {
      const auditRes = await db.query(
        `SELECT action, resource_type, details FROM public.audit_logs
         WHERE organization_id = $1 AND action IN ('COPILOT_QUERY', 'COPILOT_CONTEXT_RETRIEVED')
         ORDER BY created_at DESC
         LIMIT 20;`,
        [orgA.id]
      );

      assert.ok(auditRes.rows.length >= 2);
      const actions = auditRes.rows.map(r => r.action);
      assert.ok(actions.includes('COPILOT_QUERY'));
      assert.ok(actions.includes('COPILOT_CONTEXT_RETRIEVED'));

      // Validate raw prompt content is NOT stored
      for (const row of auditRes.rows) {
        const detStr = JSON.stringify(row.details || {});
        assert.ok(!detStr.includes('systemInstruction'));
        assert.ok(!detStr.includes('userPrompt'));
      }
    });

  } finally {
    if (server) {
      await new Promise(r => server.close(r));
    }
    await cleanupFixtures().catch(() => {});
    if (db.pool && typeof db.pool.end === 'function') {
      await db.pool.end().catch(() => {});
    }
  }

  console.log('\n========================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('========================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runCopilotPhase1Suite().catch(err => {
    console.error('Fatal Suite Execution Error:', err);
    process.exit(1);
  });
}

module.exports = { runCopilotPhase1Suite };
