/**
 * CYBERGUARD SECURITY ENVIRONMENT SEED SCRIPT
 * Populates a complete, realistic, coherent cybersecurity platform environment
 * for Bharat FinTech Solutions (HQ: Bengaluru, Offices: Hyderabad, Mumbai, Pune, Bhubaneswar, New Delhi).
 *
 * Safe & Idempotent: Can be run multiple times without duplicates or destructive side-effects.
 * Uses exact database schema, constraints, and valid PostgreSQL enums.
 */

const db = require('../config/db');
const bcrypt = require('bcrypt');

const ORG_ID = 'a1000000-0000-4000-8000-000000000001';
const ORG_NAME = 'Bharat FinTech Solutions';
const ORG_SLUG = 'bharat-fintech-solutions';

// Fixed UUIDs for cross-table referential integrity
const USER_PRIYA_ID  = 'b1000000-0000-4000-8000-000000000001'; // CISO / Admin
const USER_ARJUN_ID  = 'b1000000-0000-4000-8000-000000000002'; // Lead SOC Analyst / Admin
const USER_ANANYA_ID = 'b1000000-0000-4000-8000-000000000003'; // Threat Hunter
const USER_RAHUL_ID  = 'b1000000-0000-4000-8000-000000000004'; // DevSecOps
const USER_SNEHA_ID  = 'b1000000-0000-4000-8000-000000000005'; // Incident Responder
const USER_VIKRAM_ID = 'b1000000-0000-4000-8000-000000000006'; // Infrastructure Admin
const USER_NEHA_ID   = 'b1000000-0000-4000-8000-000000000007'; // Senior Software Engineer
const USER_ROHAN_ID  = 'b1000000-0000-4000-8000-000000000008'; // Payments Core Lead

// Personal users for Guardian & Individual protection mode
const USER_ROHAN_PERS_ID = 'b1000000-0000-4000-8000-000000000009'; // Guardian
const USER_NEHA_PERS_ID  = 'b1000000-0000-4000-8000-000000000010'; // Dependent

// Endpoints
const DEV_BLR_WS_14_ID   = 'c1000000-0000-4000-8000-000000000001';
const DEV_HYD_WS_08_ID   = 'c1000000-0000-4000-8000-000000000002';
const DEV_BBSR_DEV_03_ID = 'c1000000-0000-4000-8000-000000000003';
const DEV_PUNE_SRV_02_ID = 'c1000000-0000-4000-8000-000000000004';
const DEV_MUM_GW_01_ID   = 'c1000000-0000-4000-8000-000000000005';
const DEV_BLR_SOC_05_ID  = 'c1000000-0000-4000-8000-000000000006';
const DEV_BLR_SEC_01_ID  = 'c1000000-0000-4000-8000-000000000007';
const DEV_HYD_ENG_12_ID  = 'c1000000-0000-4000-8000-000000000008';

async function seed() {
  console.log('--- Starting CyberGuard Security Environment Population ---');

  // 1. Organization
  console.log('1. Seeding Organization: Bharat FinTech Solutions...');
  await db.query(`
    INSERT INTO organizations (id, name, created_at)
    VALUES ($1, $2, NOW())
    ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;
  `, [ORG_ID, ORG_NAME]);

  // Standard encrypted password hash for CyberGuard@2026!
  const passwordHash = await bcrypt.hash('CyberGuard@2026!', 10);

  // 2. Identities
  console.log('2. Seeding Enterprise & Individual Identities...');
  const users = [
    { id: USER_PRIYA_ID, email: 'priya.sharma@bharatfintech.in', role: 'admin', org: ORG_ID },
    { id: USER_ARJUN_ID, email: 'arjun.patel@bharatfintech.in', role: 'admin', org: ORG_ID },
    { id: USER_ANANYA_ID, email: 'ananya.das@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_RAHUL_ID, email: 'rahul.verma@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_SNEHA_ID, email: 'sneha.reddy@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_VIKRAM_ID, email: 'vikram.singh@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_NEHA_ID, email: 'neha.mishra@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_ROHAN_ID, email: 'rohan.kulkarni@bharatfintech.in', role: 'employee', org: ORG_ID },
    { id: USER_ROHAN_PERS_ID, email: 'rohan.kulkarni@personal.in', role: 'individual', org: null },
    { id: USER_NEHA_PERS_ID, email: 'neha.mishra@personal.in', role: 'individual', org: null }
  ];

  for (const u of users) {
    await db.query(`
      INSERT INTO users (id, email, password_hash, role, organization_id, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW() - interval '30 days')
      ON CONFLICT (id) DO UPDATE
      SET email = EXCLUDED.email, password_hash = EXCLUDED.password_hash,
          role = EXCLUDED.role, organization_id = EXCLUDED.organization_id;
    `, [u.id, u.email, passwordHash, u.role, u.org]);
  }

  // 3. Agent Fleet Endpoints
  console.log('3. Seeding Agent Fleet Devices...');
  const devices = [
    {
      id: DEV_BLR_WS_14_ID,
      user_id: USER_RAHUL_ID,
      hostname: 'BLR-WS-014',
      device_name: 'Rahul Verma - ThinkPad T14s',
      os: 'Windows 11 Pro 23H2',
      platform: 'windows',
      status: 'online',
      heartbeat_ago: '2 minutes'
    },
    {
      id: DEV_HYD_WS_08_ID,
      user_id: USER_SNEHA_ID,
      hostname: 'HYD-WS-008',
      device_name: 'Sneha Reddy - MacBook Pro 16',
      os: 'macOS Sonoma 14.4.1',
      platform: 'macos',
      status: 'online',
      heartbeat_ago: '4 minutes'
    },
    {
      id: DEV_BBSR_DEV_03_ID,
      user_id: USER_NEHA_ID,
      hostname: 'BBSR-DEV-003',
      device_name: 'Neha Mishra - Dell Precision 5570',
      os: 'Ubuntu 22.04 LTS',
      platform: 'linux',
      status: 'online',
      heartbeat_ago: '1 minute'
    },
    {
      id: DEV_PUNE_SRV_02_ID,
      user_id: USER_ROHAN_ID,
      hostname: 'PUNE-SRV-002',
      device_name: 'Pune Core Payments Server 02',
      os: 'Red Hat Enterprise Linux 9.3',
      platform: 'linux',
      status: 'online',
      heartbeat_ago: '30 seconds'
    },
    {
      id: DEV_MUM_GW_01_ID,
      user_id: USER_VIKRAM_ID,
      hostname: 'MUM-GW-001',
      device_name: 'Mumbai Datacenter Security Gateway',
      os: 'Alpine Linux 3.19 (Hardened Kernel)',
      platform: 'linux',
      status: 'online',
      heartbeat_ago: '15 seconds'
    },
    {
      id: DEV_BLR_SOC_05_ID,
      user_id: USER_PRIYA_ID,
      hostname: 'BLR-SOC-005',
      device_name: 'Priya Sharma - SOC Executive Workstation',
      os: 'Windows 11 Enterprise',
      platform: 'windows',
      status: 'online',
      heartbeat_ago: '5 minutes'
    },
    {
      id: DEV_BLR_SEC_01_ID,
      user_id: USER_ARJUN_ID,
      hostname: 'BLR-SEC-001',
      device_name: 'Arjun Patel - Analyst Rig',
      os: 'macOS Sonoma 14.4',
      platform: 'macos',
      status: 'online',
      heartbeat_ago: '3 minutes'
    },
    {
      id: DEV_HYD_ENG_12_ID,
      user_id: USER_ANANYA_ID,
      hostname: 'HYD-ENG-012',
      device_name: 'Ananya Das - Threat Hunter Lab',
      os: 'macOS Sonoma 14.4',
      platform: 'macos',
      status: 'online',
      heartbeat_ago: '6 minutes'
    }
  ];

  for (const d of devices) {
    await db.query(`
      INSERT INTO devices (
        id, user_id, organization_id, hostname, device_name, os, platform,
        status, is_trusted, agent_version, last_heartbeat, last_seen, created_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, true, '2.4.1-enterprise', NOW() - ($9)::interval, NOW() - ($9)::interval, NOW() - interval '45 days'
      )
      ON CONFLICT (id) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        organization_id = EXCLUDED.organization_id,
        hostname = EXCLUDED.hostname,
        device_name = EXCLUDED.device_name,
        os = EXCLUDED.os,
        platform = EXCLUDED.platform,
        status = EXCLUDED.status,
        last_heartbeat = EXCLUDED.last_heartbeat,
        last_seen = EXCLUDED.last_seen;
    `, [d.id, d.user_id, ORG_ID, d.hostname, d.device_name, d.os, d.platform, d.status, d.heartbeat_ago]);
  }

  // 4. Host Firewall Policies & Rules
  console.log('4. Seeding Host Firewall Rules...');
  const firewallRules = [
    {
      id: 'd1000000-0000-4000-8000-000000000001',
      agent_id: DEV_MUM_GW_01_ID,
      rule_type: 'block_ip',
      target_ip: '198.51.100.45',
      target_domain: null,
      status: 'active',
      result: { action: 'block', protocol: 'any', reason: 'Threat Intelligence IOC: Verified C2 beaconing candidate' }
    },
    {
      id: 'd1000000-0000-4000-8000-000000000002',
      agent_id: DEV_BLR_WS_14_ID,
      rule_type: 'block_domain',
      target_ip: null,
      target_domain: 'c2-threat-verify.example.net',
      status: 'active',
      result: { action: 'block_dns', reason: 'Malicious domain sinkhole policy' }
    },
    {
      id: 'd1000000-0000-4000-8000-000000000003',
      agent_id: DEV_PUNE_SRV_02_ID,
      rule_type: 'block_ip',
      target_ip: '203.0.113.88',
      target_domain: null,
      status: 'active',
      result: { action: 'drop', protocol: 'tcp', port: 'any', reason: 'High-frequency brute force source' }
    },
    {
      id: 'd1000000-0000-4000-8000-000000000004',
      agent_id: DEV_BBSR_DEV_03_ID,
      rule_type: 'block_domain',
      target_ip: null,
      target_domain: 'phish-payroll-update.example.org',
      status: 'active',
      result: { action: 'block_domain', reason: 'Credential harvesting target URL' }
    },
    {
      id: 'd1000000-0000-4000-8000-000000000005',
      agent_id: DEV_HYD_WS_08_ID,
      rule_type: 'block_ip',
      target_ip: '192.0.2.140',
      target_domain: null,
      status: 'pending',
      result: { action: 'quarantine_review', reason: 'Anomalous outbound telemetry test endpoint' }
    }
  ];

  for (const f of firewallRules) {
    await db.query(`
      INSERT INTO agent_firewall_rules (
        id, agent_id, organization_id, rule_type, target_ip, target_domain,
        status, created_by_id, created_at, result
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() - interval '5 days', $9)
      ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        result = EXCLUDED.result;
    `, [f.id, f.agent_id, ORG_ID, f.rule_type, f.target_ip, f.target_domain, f.status, USER_PRIYA_ID, JSON.stringify(f.result)]);
  }

  // 5. Attack Surface Exposures
  console.log('5. Seeding Attack Surface Exposures...');
  const exposures = [
    {
      id: 'e1000000-0000-4000-8000-000000000001',
      device_id: DEV_BLR_WS_14_ID,
      rule_id: 'EXP-HIGH-SSH',
      severity: 'high',
      risk_score: 80,
      title: 'Public SSH Service Exposed',
      description: 'OpenSSH service is listening on external interface with password authentication enabled.',
      remediation: 'Enforce public key authentication and restrict port 22 access via VPN subnet allowlist.',
      status: 'active',
      metadata: { port: 22, protocol: 'tcp', service: 'ssh', bind: '0.0.0.0' }
    },
    {
      id: 'e1000000-0000-4000-8000-000000000002',
      device_id: DEV_PUNE_SRV_02_ID,
      rule_id: 'EXP-CRIT-REDIS',
      severity: 'critical',
      risk_score: 95,
      title: 'Public Redis Instance',
      description: 'Redis in-memory caching service exposed without network perimeter firewall restriction.',
      remediation: 'Bind Redis instance to 127.0.0.1 loopback and enable strong requirepass auth.',
      status: 'mitigated',
      metadata: { port: 6379, protocol: 'tcp', service: 'redis', bind: '0.0.0.0' }
    },
    {
      id: 'e1000000-0000-4000-8000-000000000003',
      device_id: DEV_BBSR_DEV_03_ID,
      rule_id: 'EXP-HIGH-ELASTIC',
      severity: 'high',
      risk_score: 75,
      title: 'Public Elasticsearch Cluster',
      description: 'Elasticsearch developer REST API port reachable from local subnet without token verification.',
      remediation: 'Enable X-Pack security features and restrict HTTP binding to private cluster IP.',
      status: 'active',
      metadata: { port: 9200, protocol: 'tcp', service: 'elasticsearch', bind: '0.0.0.0' }
    },
    {
      id: 'e1000000-0000-4000-8000-000000000004',
      device_id: DEV_MUM_GW_01_ID,
      rule_id: 'EXP-MED-HTTP',
      severity: 'medium',
      risk_score: 55,
      title: 'Unencrypted HTTP Management Port',
      description: 'Web management console listening on plain HTTP port 8080.',
      remediation: 'Enforce strict HTTPS redirection and disable plaintext HTTP listener.',
      status: 'active',
      metadata: { port: 8080, protocol: 'tcp', service: 'http', bind: '0.0.0.0' }
    }
  ];

  for (const exp of exposures) {
    const dummyPortId = 'f1000000-0000-4000-8000-00000000000' + exp.id.slice(-1);

    // Insert device listening port first to satisfy FK
    await db.query(`
      INSERT INTO device_listening_ports (
        id, organization_id, device_id, port, protocol, bind_address, exposure_scope,
        process_name, status, first_seen_at, last_seen_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, 'public', $7, 'open', NOW() - interval '14 days', NOW())
      ON CONFLICT (id) DO UPDATE SET
        port = EXCLUDED.port,
        protocol = EXCLUDED.protocol,
        bind_address = EXCLUDED.bind_address,
        process_name = EXCLUDED.process_name;
    `, [dummyPortId, ORG_ID, exp.device_id, exp.metadata.port, exp.metadata.protocol, exp.metadata.bind, exp.metadata.service]);

    await db.query(`
      INSERT INTO attack_surface_exposures (
        id, organization_id, device_id, port_id, rule_id, severity, risk_score,
        title, description, remediation, status, first_seen_at, last_seen_at, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW() - interval '7 days', NOW() - interval '1 hour', $12)
      ON CONFLICT (id) DO UPDATE SET
        severity = EXCLUDED.severity,
        risk_score = EXCLUDED.risk_score,
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        status = EXCLUDED.status,
        last_seen_at = EXCLUDED.last_seen_at;
    `, [
      exp.id, ORG_ID, exp.device_id, dummyPortId, exp.rule_id, exp.severity, exp.risk_score,
      exp.title, exp.description, exp.remediation, exp.status, JSON.stringify(exp.metadata)
    ]);
  }

  // 6. Threat Incidents
  console.log('6. Seeding Comprehensive Threat Incident Records...');
  const incidents = [
    {
      id: '11000000-0000-4000-8000-000000000001',
      user_id: USER_ROHAN_ID,
      device_id: DEV_PUNE_SRV_02_ID,
      threat_type: 'account_takeover',
      source_type: 'login',
      risk_level: 'critical',
      risk_score: 94,
      priority: 'P1',
      status: 'investigating',
      assigned_to: USER_SNEHA_ID,
      explanation: 'Distributed credential stuffing and anomalous login activity detected targeting core payment authorization gateway. 48 rapid login attempts observed across non-standard ASN originations within 90 seconds.',
      created_ago: '45 minutes',
      technique_id: 'T1110',
      technique_name: 'Brute Force: Credential Stuffing',
      action_type: 'revoke_session'
    },
    {
      id: '11000000-0000-4000-8000-000000000002',
      user_id: USER_NEHA_ID,
      device_id: DEV_BBSR_DEV_03_ID,
      threat_type: 'phishing',
      source_type: 'email',
      risk_level: 'high',
      risk_score: 86,
      priority: 'P2',
      status: 'open',
      assigned_to: USER_ARJUN_ID,
      explanation: 'Targeted spear-phishing email masquerading as corporate quarterly appraisal communication. Email failed SPF and DMARC verification and contained malicious payload link.',
      created_ago: '2 hours',
      technique_id: 'T1566.001',
      technique_name: 'Phishing: Spearphishing Attachment',
      action_type: 'quarantine_email'
    },
    {
      id: '11000000-0000-4000-8000-000000000003',
      user_id: USER_RAHUL_ID,
      device_id: DEV_BLR_WS_14_ID,
      threat_type: 'technical_threat',
      source_type: 'telemetry',
      risk_level: 'high',
      risk_score: 82,
      priority: 'P2',
      status: 'resolved',
      assigned_to: USER_ANANYA_ID,
      explanation: 'Endpoint telemetry flagged periodic HTTP beaconing to known documentation threat intelligence IP 198.51.100.45. Automated host isolation and firewall rule blocking executed.',
      created_ago: '1 day',
      technique_id: 'T1071.001',
      technique_name: 'Application Layer Protocol: Web Protocols',
      action_type: 'isolate_endpoint'
    },
    {
      id: '11000000-0000-4000-8000-000000000004',
      user_id: USER_ARJUN_ID,
      device_id: DEV_BLR_SEC_01_ID,
      threat_type: 'deepfake',
      source_type: 'audio',
      risk_level: 'medium',
      risk_score: 68,
      priority: 'P3',
      status: 'resolved',
      assigned_to: USER_ARJUN_ID,
      explanation: 'Deepfake audio analysis engine detected synthetic voice artifacts in urgent wire transfer verification voice note. 97.4% model confidence for voice synthesis manipulation.',
      created_ago: '2 days',
      technique_id: 'T1656',
      technique_name: 'Impersonation: Synthetic Audio',
      action_type: 'block_transaction'
    },
    {
      id: '11000000-0000-4000-8000-000000000005',
      user_id: USER_VIKRAM_ID,
      device_id: DEV_MUM_GW_01_ID,
      threat_type: 'ddos',
      source_type: 'ddos_detection',
      risk_level: 'medium',
      risk_score: 62,
      priority: 'P3',
      status: 'resolved',
      assigned_to: USER_VIKRAM_ID,
      explanation: 'Layer 7 HTTP request flood spike detected on /api/v1/auth/login. Baseline traffic of 450 req/sec exceeded 3,200 req/sec threshold before rate limiting mitigation engaged.',
      created_ago: '3 days',
      technique_id: 'T1499.003',
      technique_name: 'Endpoint Denial of Service: Application Exhaustion',
      action_type: 'enable_rate_limit'
    },
    {
      id: '11000000-0000-4000-8000-000000000006',
      user_id: USER_NEHA_ID,
      device_id: DEV_BBSR_DEV_03_ID,
      threat_type: 'exposed_secret',
      source_type: 'check',
      risk_level: 'low',
      risk_score: 38,
      priority: 'P4',
      status: 'resolved',
      assigned_to: USER_ANANYA_ID,
      explanation: 'High-entropy placeholder private key pattern identified in developer pre-commit scanning hook. Token was flagged and rotated prior to production merge.',
      created_ago: '4 days',
      technique_id: 'T1552.001',
      technique_name: 'Unsecured Credentials: Credentials In Files',
      action_type: 'rotate_secret'
    },
    {
      id: '11000000-0000-4000-8000-000000000007',
      user_id: USER_ROHAN_PERS_ID,
      device_id: null,
      threat_type: 'malicious_url',
      source_type: 'url',
      risk_level: 'low',
      risk_score: 25,
      priority: 'P4',
      status: 'resolved',
      assigned_to: null,
      explanation: 'SMS link check flagged deceptive typosquatted domain claiming to be official mobile recharge portal. Blocked and reported to user safety feed.',
      created_ago: '5 days',
      technique_id: 'T1204.001',
      technique_name: 'User Execution: Malicious Link',
      action_type: 'block_url'
    },
    {
      id: '11000000-0000-4000-8000-000000000008',
      user_id: USER_PRIYA_ID,
      device_id: DEV_BLR_SOC_05_ID,
      threat_type: 'technical_threat',
      source_type: 'system',
      risk_level: 'safe',
      risk_score: 5,
      priority: 'P4',
      status: 'resolved',
      assigned_to: USER_PRIYA_ID,
      explanation: 'Scheduled TLS 1.3 certificate rotation verified across customer-facing edge clusters with zero disruption.',
      created_ago: '6 days',
      technique_id: 'T1082',
      technique_name: 'System Information Discovery',
      action_type: 'archive_audit'
    }
  ];

  for (const inc of incidents) {
    await db.query(`
      INSERT INTO incidents (
        id, user_id, organization_id, threat_type, source_type, risk_level, risk_score,
        explanation, status, device_id, priority, assigned_to, first_seen_at, last_seen_at,
        created_at
      )
      VALUES (
        $1, $2, $3, $4::threat_type, $5::source_type, $6::risk_level, $7,
        $8, $9::incident_status, $10, $11, $12, NOW() - ($13)::interval, NOW() - ($13)::interval,
        NOW() - ($13)::interval
      )
      ON CONFLICT (id) DO UPDATE SET
        organization_id = EXCLUDED.organization_id,
        user_id = EXCLUDED.user_id,
        threat_type = EXCLUDED.threat_type,
        source_type = EXCLUDED.source_type,
        risk_level = EXCLUDED.risk_level,
        risk_score = EXCLUDED.risk_score,
        explanation = EXCLUDED.explanation,
        status = EXCLUDED.status,
        assigned_to = EXCLUDED.assigned_to;
    `, [
      inc.id, inc.user_id, ORG_ID, inc.threat_type, inc.source_type, inc.risk_level, inc.risk_score,
      inc.explanation, inc.status, inc.device_id, inc.priority, inc.assigned_to, inc.created_ago
    ]);

    // Associated MITRE ATT&CK mapping
    await db.query(`
      INSERT INTO mitre_mappings (id, incident_id, technique_id, technique_name)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (id) DO UPDATE SET
        technique_id = EXCLUDED.technique_id,
        technique_name = EXCLUDED.technique_name;
    `, [inc.id, inc.id, inc.technique_id, inc.technique_name]);

    // Recommended Action
    await db.query(`
      INSERT INTO recommended_actions (id, incident_id, action_type, action_status, created_at)
      VALUES ($1, $2, $3, 'taken', NOW() - ($4)::interval)
      ON CONFLICT (id) DO NOTHING;
    `, [inc.id, inc.id, inc.action_type, inc.created_ago]);
  }

  // Also associate unassigned legacy incidents with Bharat FinTech Solutions
  // so enterprise dashboard totals have deep historical coverage
  console.log('7. Associating unassigned historical incidents with Bharat FinTech Solutions...');
  await db.query(`
    UPDATE incidents
    SET organization_id = $1
    WHERE organization_id IS NULL;
  `, [ORG_ID]);

  // 8. DDoS Metrics
  console.log('8. Seeding DDoS Network Flow Metrics...');
  const ddosEntries = [
    {
      id: '21000000-0000-4000-8000-000000000001',
      metric_type: 'request_spike',
      source_ip: '198.51.100.22',
      endpoint: '/api/v1/auth/login',
      count: 3240,
      threshold_exceeded: true,
      metadata: { baseline_rps: 450, peak_rps: 3240, mitigation: 'rate_limited' },
      ago: '3 days'
    },
    {
      id: '21000000-0000-4000-8000-000000000002',
      metric_type: 'login_abuse',
      source_ip: '203.0.113.19',
      endpoint: '/api/v1/auth/login',
      count: 1480,
      threshold_exceeded: true,
      metadata: { failed_ratio: 0.96, accounts_targeted: 140 },
      ago: '1 day'
    },
    {
      id: '21000000-0000-4000-8000-000000000003',
      metric_type: 'post_flood',
      source_ip: '192.0.2.77',
      endpoint: '/api/v1/check/url',
      count: 850,
      threshold_exceeded: false,
      metadata: { normal_operational_volume: true },
      ago: '4 hours'
    }
  ];

  for (const d of ddosEntries) {
    await db.query(`
      INSERT INTO ddos_metrics (
        id, organization_id, metric_type, source_ip, endpoint, count,
        window_start, window_end, threshold_exceeded, metadata, created_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6,
        NOW() - ($7)::interval - interval '5 minutes', NOW() - ($7)::interval,
        $8, $9, NOW() - ($7)::interval
      )
      ON CONFLICT (id) DO UPDATE SET
        count = EXCLUDED.count,
        threshold_exceeded = EXCLUDED.threshold_exceeded;
    `, [d.id, ORG_ID, d.metric_type, d.source_ip, d.endpoint, d.count, d.ago, d.threshold_exceeded, JSON.stringify(d.metadata)]);
  }

  // 9. Threat Intelligence Indicators
  console.log('9. Seeding Threat Intelligence IOCs...');
  const threatIocs = [
    {
      id: '31000000-0000-4000-8000-000000000001',
      indicator_type: 'ip',
      indicator_value: '198.51.100.45',
      threat_actor: 'APT-FIN-SHADOW',
      malware_family: 'CobaltStrike-Custom',
      severity: 'critical',
      confidence_score: 95,
      tags: ['c2', 'banking-trojan', 'active-campaign']
    },
    {
      id: '31000000-0000-4000-8000-000000000002',
      indicator_type: 'domain',
      indicator_value: 'c2-threat-verify.example.net',
      threat_actor: 'UNKNOWN_THREAT_GROUP',
      malware_family: 'Stealer-Generic',
      severity: 'high',
      confidence_score: 88,
      tags: ['phishing-c2', 'data-exfiltration']
    },
    {
      id: '31000000-0000-4000-8000-000000000003',
      indicator_type: 'sha256',
      indicator_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      threat_actor: 'PHISH_SYNDICATE_IN',
      malware_family: 'Dropper.VBA',
      severity: 'high',
      confidence_score: 91,
      tags: ['macro', 'office-payload']
    }
  ];

  for (const t of threatIocs) {
    await db.query(`
      INSERT INTO threat_indicators (
        id, organization_id, indicator_type, indicator_value, threat_actor, malware_family,
        severity, confidence_score, tags, observation_count, first_seen_at, last_seen_at,
        expires_at, is_active, metadata, created_at, updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, 14,
        NOW() - interval '14 days', NOW() - interval '2 hours', NOW() + interval '90 days',
        true, '{}', NOW() - interval '14 days', NOW()
      )
      ON CONFLICT (id) DO UPDATE SET
        severity = EXCLUDED.severity,
        confidence_score = EXCLUDED.confidence_score,
        is_active = EXCLUDED.is_active;
    `, [t.id, ORG_ID, t.indicator_type, t.indicator_value, t.threat_actor, t.malware_family, t.severity, t.confidence_score, t.tags]);
  }

  // 10. SOAR Playbooks & Cases
  console.log('10. Seeding SOAR Playbooks & Case Management...');
  const playbooks = [
    {
      id: '41000000-0000-4000-8000-000000000001',
      name: 'Credential Stuffing Automated Containment',
      description: 'Triggered when login abuse threshold is breached. Enforces step-up MFA and revokes active API tokens.',
      trigger_type: 'threat_event',
      trigger_conditions: { threat_type: 'account_takeover', min_risk: 'high' }
    },
    {
      id: '41000000-0000-4000-8000-000000000002',
      name: 'C2 Beaconing Host Isolation Playbook',
      description: 'Pushes host-level firewall block commands to affected endpoint and schedules memory triage.',
      trigger_type: 'telemetry_anomaly',
      trigger_conditions: { rule_match: 'beaconing_c2' }
    },
    {
      id: '41000000-0000-4000-8000-000000000003',
      name: 'Phishing Domain Global Quarantine',
      description: 'Extracts URLs from suspicious emails, verifies reputation via ML, and distributes domain blocklist.',
      trigger_type: 'email_submission',
      trigger_conditions: { category: 'phishing' }
    }
  ];

  for (const pb of playbooks) {
    await db.query(`
      INSERT INTO soar_playbooks (
        id, organization_id, name, description, enabled, trigger_type, trigger_conditions,
        created_by, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, true, $5, $6, $7, NOW() - interval '20 days', NOW())
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        trigger_conditions = EXCLUDED.trigger_conditions;
    `, [pb.id, ORG_ID, pb.name, pb.description, pb.trigger_type, JSON.stringify(pb.trigger_conditions), USER_PRIYA_ID]);
  }

  // 11. Guardian Mode Links
  console.log('11. Seeding Guardian Mode Family Protection Link...');
  await db.query(`
    INSERT INTO guardian_links (
      id, guardian_user_id, dependent_user_id, status, created_at
    )
    VALUES (
      '51000000-0000-4000-8000-000000000001', $1, $2, 'active', NOW() - interval '14 days'
    )
    ON CONFLICT (id) DO UPDATE SET status = 'active';
  `, [USER_ROHAN_PERS_ID, USER_NEHA_PERS_ID]);

  console.log('\n--- SUCCESS: Complete Security Environment Successfully Populated ---');
  console.log(`Organization: ${ORG_NAME} (ID: ${ORG_ID})`);
  console.log(`Primary Administrator: priya.sharma@bharatfintech.in (Password: CyberGuard@2026!)`);
  console.log(`Lead SOC Analyst: arjun.patel@bharatfintech.in (Password: CyberGuard@2026!)`);
  console.log(`Guardian User: rohan.kulkarni@personal.in (Password: CyberGuard@2026!)`);
  console.log(`Dependent User: neha.mishra@personal.in (Password: CyberGuard@2026!)`);
  process.exit(0);
}

seed().catch(err => {
  console.error('[SEED ERROR]', err);
  process.exit(1);
});
