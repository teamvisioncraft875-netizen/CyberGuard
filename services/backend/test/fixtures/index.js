const db = require('../../src/config/db');
const SecurityEvent = require('../../src/models/SecurityEvent');
const Incident = require('../../src/models/Incident');
const SiemAlert = require('../../src/models/SiemAlert');

/**
 * Shared Test Fixtures — Reusable, high-performance fixture factories for CyberGuard tests
 * Eliminates duplicate boilerplate, enforces database consistency, and simplifies teardown.
 */

async function createOrganizationFixture({ name = `Fixture Org ${Date.now()}` } = {}, client = null) {
  const dbClient = client || db;
  const res = await dbClient.query(
    `INSERT INTO public.organizations (name) VALUES ($1) RETURNING *;`,
    [name]
  );
  return res.rows[0];
}

async function createUserFixture({
  organization_id,
  email = `analyst_${Date.now()}_${Math.random().toString(36).slice(2, 7)}@cyberguard.test`,
  role = 'admin',
  password_hash = 'fixture_password_hash'
} = {}, client = null) {
  if (!organization_id) throw new Error('createUserFixture requires organization_id');
  const dbClient = client || db;
  // DB enum user_role allows ('individual', 'employee', 'admin')
  const dbRole = role === 'analyst' ? 'admin' : role;
  const res = await dbClient.query(
    `INSERT INTO public.users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *;`,
    [organization_id, email, password_hash, dbRole]
  );
  const user = res.rows[0];
  user.jwt_role = role; // Store intended JWT role (e.g., analyst)
  return user;
}

async function createIncidentFixture({
  organization_id,
  user_id = null,
  device_id = null,
  threat_type = 'account_takeover',
  source_type = 'siem',
  risk_level = 'high',
  risk_score = 75,
  status = 'open',
  explanation = 'Fixture Generated Incident'
} = {}, client = null) {
  if (!organization_id) throw new Error('createIncidentFixture requires organization_id');
  return Incident.create({
    organization_id,
    user_id,
    device_id,
    threat_type,
    source_type,
    risk_level,
    risk_score,
    status,
    explanation
  }, client);
}

async function createAlertFixture({
  organization_id,
  title = `Fixture Alert ${Date.now()}`,
  severity = 'high',
  status = 'new',
  rule_code = 'FIXTURE-RULE',
  mitre_technique = 'T1110',
  source_type = 'windows'
} = {}, client = null) {
  if (!organization_id) throw new Error('createAlertFixture requires organization_id');
  return SiemAlert.create({
    organization_id,
    title,
    severity,
    status,
    rule_code,
    mitre_technique,
    source_type
  }, client);
}

async function createEventFixture({
  organization_id,
  event_type = 'windows_logon_failed',
  severity = 'medium',
  source_type = 'windows',
  device_id = null,
  user_id = null,
  raw_event = { message: 'Fixture security event' },
  normalized_event = { summary: 'Fixture event summary' }
} = {}, client = null) {
  if (!organization_id) throw new Error('createEventFixture requires organization_id');
  return SecurityEvent.create({
    organization_id,
    event_type,
    severity,
    source_type,
    device_id,
    user_id,
    raw_event,
    normalized_event,
    event_timestamp: new Date()
  }, client);
}

/**
 * Cleanup helper for test teardown
 */
async function cleanupFixtures({
  orgIds = [],
  userIds = [],
  incidentIds = [],
  alertIds = [],
  eventIds = []
} = {}, client = null) {
  const dbClient = client || db;
  try {
    if (alertIds.length > 0) {
      await dbClient.query(`DELETE FROM public.siem_alerts WHERE id = ANY($1::uuid[]);`, [alertIds]);
    }
    if (incidentIds.length > 0) {
      await dbClient.query(`DELETE FROM public.incidents WHERE id = ANY($1::uuid[]);`, [incidentIds]);
    }
    if (eventIds.length > 0) {
      await dbClient.query(`DELETE FROM public.security_events WHERE id = ANY($1::uuid[]);`, [eventIds]);
    }
    if (userIds.length > 0) {
      await dbClient.query(`DELETE FROM public.users WHERE id = ANY($1::uuid[]);`, [userIds]);
    }
    if (orgIds.length > 0) {
      await dbClient.query(`DELETE FROM public.siem_alerts WHERE organization_id = ANY($1::uuid[]);`, [orgIds]);
      await dbClient.query(`DELETE FROM public.siem_detection_hits WHERE organization_id = ANY($1::uuid[]);`, [orgIds]);
      await dbClient.query(`DELETE FROM public.audit_logs WHERE organization_id = ANY($1::uuid[]);`, [orgIds]);
      await dbClient.query(`DELETE FROM public.organizations WHERE id = ANY($1::uuid[]);`, [orgIds]);
    }
  } catch (err) {
    console.warn('[cleanupFixtures Warning]:', err.message);
  }
}

module.exports = {
  createOrganizationFixture,
  createUserFixture,
  createIncidentFixture,
  createAlertFixture,
  createEventFixture,
  cleanupFixtures
};
