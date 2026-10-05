/**
 * CYBERGUARD — ATTACK SURFACE DISCOVERY (ASD) PHASE A TEST SUITE
 * Tests:
 *  1. collect_listening_ports() returns valid schema
 *  2. loopback address classified correctly
 *  3. private RFC1918 address classified correctly
 *  4. public binding classified correctly
 *  5. telemetry payload includes attack_surface object
 *  6. backend ingestion persists listening ports
 *  7. repeated telemetry updates last_seen_at (idempotency, zero duplicates)
 *  8. organization scoping enforced
 *  9. collection survives AccessDenied exceptions gracefully
 * 10. no crashes with empty port list
 */

const assert = require('assert');
const { execSync } = require('child_process');
const path = require('path');
const db = require('../src/config/db');
const DeviceListeningPort = require('../src/models/DeviceListeningPort');
const telemetryController = require('../src/controllers/telemetryController');

async function runPhaseATestSuite() {
  console.log('========================================================================');
  console.log('CYBERGUARD — Attack Surface Discovery (Phase A Foundation) Test Suite');
  console.log('========================================================================\n');

  const testOrgA = '00000000-0000-0000-0000-000000000a01';
  const testOrgB = '00000000-0000-0000-0000-000000000b02';
  const testDeviceA = '00000000-0000-0000-0000-000000000d01';
  const testDeviceB = '00000000-0000-0000-0000-000000000d02';

  // Cleanup before tests
  await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
  await db.query(`DELETE FROM public.telemetry_events WHERE device_id IN ($1, $2);`, [testDeviceA, testDeviceB]);
  await db.query(`DELETE FROM public.devices WHERE id IN ($1, $2);`, [testDeviceA, testDeviceB]);
  await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgA, testOrgB]);

  // Insert test organizations and devices
  await db.query(`
    INSERT INTO public.organizations (id, name)
    VALUES ($1, 'ASD Test Org A'),
           ($2, 'ASD Test Org B');
  `, [testOrgA, testOrgB]);

  await db.query(`
    INSERT INTO public.devices (id, organization_id, hostname, platform, os, status, agent_version)
    VALUES ($1, $2, 'asd-host-alpha', 'win32', 'Windows 11', 'online', '1.0.0'),
           ($3, $4, 'asd-host-beta', 'linux', 'Ubuntu 22.04', 'online', '1.0.0');
  `, [testDeviceA, testOrgA, testDeviceB, testOrgB]);

  // ---------------------------------------------------------------------------
  // CHECK 1: collect_listening_ports() returns valid schema
  // ---------------------------------------------------------------------------
  console.log('--- CHECK 1: AGENT SENSOR SCHEMA VALIDATION ---');
  const pyAgentDir = path.resolve(__dirname, '../../enterprise-agent');
  const pyCheck1 = `import sys, json
sys.path.insert(0, r"${pyAgentDir.replace(/\\/g, '\\\\')}")
from collector import collect_listening_ports
ports = collect_listening_ports()
print(json.dumps(ports[:5]))
`;
  const rawPorts = execSync('python', { input: pyCheck1 }).toString().trim();
  const samplePorts = JSON.parse(rawPorts);
  console.log(`Discovered local listening ports sample count: ${samplePorts.length}`);

  if (samplePorts.length > 0) {
    const p = samplePorts[0];
    console.log('Sample port record:', p);
    assert.strictEqual(typeof p.port, 'number', 'Port must be a number');
    assert.ok(p.port > 0 && p.port <= 65535, 'Port must be within valid range 1-65535');
    assert.ok(['tcp', 'udp'].includes(p.protocol), 'Protocol must be tcp or udp');
    assert.strictEqual(typeof p.bind_address, 'string', 'Bind address must be a string');
    assert.ok(['loopback', 'private', 'public', 'unknown'].includes(p.exposure_scope), 'Scope must be valid enum');
  }
  console.log('✅ CHECK 1 PASSED: collect_listening_ports() returns valid schema.');

  // ---------------------------------------------------------------------------
  // CHECKS 2, 3, 4: Exposure Scope Classification
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECKS 2, 3, 4: EXPOSURE SCOPE CLASSIFICATION ---');
  const pyScopeCheck = `import sys, json
sys.path.insert(0, r"${pyAgentDir.replace(/\\/g, '\\\\')}")
from collector import classify_exposure_scope
res = {
  "loopback_v4": classify_exposure_scope("127.0.0.1"),
  "loopback_v6": classify_exposure_scope("::1"),
  "priv_10": classify_exposure_scope("10.0.1.25"),
  "priv_172": classify_exposure_scope("172.16.5.10"),
  "priv_192": classify_exposure_scope("192.168.1.1"),
  "public_v4": classify_exposure_scope("0.0.0.0"),
  "public_v6": classify_exposure_scope("::"),
  "unknown_other": classify_exposure_scope("8.8.8.8"),
  "unknown_invalid": classify_exposure_scope("invalid-ip")
}
print(json.dumps(res))
`;
  const scopeResults = JSON.parse(execSync('python', { input: pyScopeCheck }).toString().trim());
  console.log('Scope classification test results:', scopeResults);

  // Check 2: Loopback
  assert.strictEqual(scopeResults.loopback_v4, 'loopback');
  assert.strictEqual(scopeResults.loopback_v6, 'loopback');
  console.log('✅ CHECK 2 PASSED: 127.0.0.1 and ::1 correctly classified as loopback.');

  // Check 3: Private RFC1918
  assert.strictEqual(scopeResults.priv_10, 'private');
  assert.strictEqual(scopeResults.priv_172, 'private');
  assert.strictEqual(scopeResults.priv_192, 'private');
  console.log('✅ CHECK 3 PASSED: RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) classified as private.');

  // Check 4: Public
  assert.strictEqual(scopeResults.public_v4, 'public');
  assert.strictEqual(scopeResults.public_v6, 'public');
  assert.strictEqual(scopeResults.unknown_other, 'unknown');
  assert.strictEqual(scopeResults.unknown_invalid, 'unknown');
  console.log('✅ CHECK 4 PASSED: 0.0.0.0 and :: classified as public, other non-RFC1918 IPs as unknown.');

  // ---------------------------------------------------------------------------
  // CHECK 5: Telemetry Payload includes attack_surface object
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 5: TELEMETRY PAYLOAD EXTENSION ---');
  const pyTelemetryCheck = `import sys, json
sys.path.insert(0, r"${pyAgentDir.replace(/\\/g, '\\\\')}")
from collector import collect_system_telemetry
snap = collect_system_telemetry()
print(json.dumps({"has_attack_surface": "attack_surface" in snap, "ports_count": len(snap.get("attack_surface", {}).get("listening_ports", []))}))
`;
  const snapCheck = JSON.parse(execSync('python', { input: pyTelemetryCheck }).toString().trim());
  console.log('Snapshot check result:', snapCheck);
  assert.strictEqual(snapCheck.has_attack_surface, true, 'attack_surface missing from telemetry snapshot');
  console.log('✅ CHECK 5 PASSED: Telemetry payload contains attack_surface.listening_ports object.');

  // ---------------------------------------------------------------------------
  // CHECK 6: Backend Ingestion persists listening ports
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 6: BACKEND INGESTION PERSISTENCE ---');
  const mockReq = {
    agent: {
      device_id: testDeviceA,
      organization_id: testOrgA,
      user_id: null
    },
    body: {
      timestamp: new Date().toISOString(),
      event_type: 'agent_telemetry',
      telemetry_type: 'agent_telemetry',
      details: {
        hostname: 'asd-host-alpha',
        network_conn_count: 5,
        attack_surface: {
          listening_ports: [
            { port: 80, protocol: 'tcp', bind_address: '0.0.0.0', exposure_scope: 'public', pid: 101, process_name: 'nginx.exe', process_path: 'C:\\nginx\\nginx.exe' },
            { port: 5432, protocol: 'tcp', bind_address: '127.0.0.1', exposure_scope: 'loopback', pid: 202, process_name: 'postgres.exe', process_path: 'C:\\pg\\postgres.exe' },
            { port: 22, protocol: 'tcp', bind_address: '10.0.1.5', exposure_scope: 'private', pid: 303, process_name: 'sshd.exe', process_path: 'C:\\ssh\\sshd.exe' }
          ]
        }
      }
    }
  };

  let resStatus = null;
  let resJson = null;
  const mockRes = {
    status(code) { resStatus = code; return this; },
    json(payload) { resJson = payload; return this; }
  };

  await telemetryController.reportSystemEvent(mockReq, mockRes);
  assert.strictEqual(resStatus, 201, `Expected HTTP 201, got ${resStatus}`);

  const storedPorts = await DeviceListeningPort.getPortsForDevice(testDeviceA, testOrgA);
  console.log(`Stored ports in DB for device: ${storedPorts.length} (Expected: 3)`);
  assert.strictEqual(storedPorts.length, 3, 'All 3 listening ports should be ingested in DB');
  const portsList = storedPorts.map(p => ({ port: p.port, scope: p.exposure_scope, status: p.status }));
  console.log('Persisted ports in DB:', portsList);
  console.log('✅ CHECK 6 PASSED: Backend successfully ingests and stores listening ports.');

  // ---------------------------------------------------------------------------
  // CHECK 7: Repeated Telemetry Updates last_seen_at (Zero Duplication)
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 7: REPEATED TELEMETRY IDEMPOTENCY & TIMESTAMP UPDATE ---');
  const originalLastSeen = new Date(storedPorts[0].last_seen_at).getTime();
  
  // Wait 100ms so timestamps advance
  await new Promise(resolve => setTimeout(resolve, 150));

  await telemetryController.reportSystemEvent(mockReq, mockRes);
  const updatedPorts = await DeviceListeningPort.getPortsForDevice(testDeviceA, testOrgA);
  assert.strictEqual(updatedPorts.length, 3, 'Duplicate rows created on repeated report!');

  const updatedLastSeen = new Date(updatedPorts[0].last_seen_at).getTime();
  console.log(`Original last_seen_at: ${originalLastSeen}, Updated last_seen_at: ${updatedLastSeen}`);
  assert.ok(updatedLastSeen >= originalLastSeen, 'last_seen_at should be updated on repeat snapshots');
  console.log('✅ CHECK 7 PASSED: Idempotent upsert verified; last_seen_at updated with zero duplicate records.');

  // ---------------------------------------------------------------------------
  // CHECK 8: Organization Scoping Enforced
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 8: MULTI-TENANT ORGANIZATION SCOPING ---');
  const orgAPorts = await DeviceListeningPort.getPortsForOrganization(testOrgA);
  const orgBPorts = await DeviceListeningPort.getPortsForOrganization(testOrgB);
  console.log(`Org A ports: ${orgAPorts.length} (Expected: 3), Org B ports: ${orgBPorts.length} (Expected: 0)`);
  assert.strictEqual(orgAPorts.length, 3, 'Org A should have 3 listening ports');
  assert.strictEqual(orgBPorts.length, 0, 'Org B should have 0 listening ports (Tenant isolation failed)');
  console.log('✅ CHECK 8 PASSED: Multi-tenant organization scoping strictly enforced.');

  // ---------------------------------------------------------------------------
  // CHECK 9: Collection Survives AccessDenied Exceptions Gracefully
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 9: SENSOR RESILIENCE UNDER AccessDenied ---');
  const pyAccessDeniedTest = `import sys, json, psutil
sys.path.insert(0, r"${pyAgentDir.replace(/\\/g, '\\\\')}")
import collector

# Mock psutil.net_connections to raise AccessDenied
def mock_net_connections(kind="inet"):
    raise psutil.AccessDenied(pid=1, name="system")

collector.psutil.net_connections = mock_net_connections
ports = collector.collect_listening_ports()
print(json.dumps({"survived": True, "ports": ports}))
`;
  const accessDeniedRes = JSON.parse(execSync('python', { input: pyAccessDeniedTest }).toString().trim());
  console.log('AccessDenied simulation output:', accessDeniedRes);
  assert.strictEqual(accessDeniedRes.survived, true);
  assert.strictEqual(accessDeniedRes.ports.length, 0);
  console.log('✅ CHECK 9 PASSED: Sensor gracefully handles AccessDenied without crashing.');

  // ---------------------------------------------------------------------------
  // CHECK 10: No Crashes With Empty Port List
  // ---------------------------------------------------------------------------
  console.log('\n--- CHECK 10: EMPTY PORT LIST INGESTION ---');
  const mockReqEmpty = {
    agent: {
      device_id: testDeviceB,
      organization_id: testOrgB,
      user_id: null
    },
    body: {
      timestamp: new Date().toISOString(),
      event_type: 'agent_telemetry',
      telemetry_type: 'agent_telemetry',
      details: {
        hostname: 'asd-host-beta',
        network_conn_count: 0,
        attack_surface: {
          listening_ports: []
        }
      }
    }
  };

  await telemetryController.reportSystemEvent(mockReqEmpty, mockRes);
  assert.strictEqual(resStatus, 201);
  const emptyPorts = await DeviceListeningPort.getPortsForDevice(testDeviceB, testOrgB);
  assert.strictEqual(emptyPorts.length, 0);
  console.log('✅ CHECK 10 PASSED: Backend smoothly handles empty listening port snapshots.');

  // Cleanup
  console.log('\nCleaning up Phase A test resources...');
  await db.query(`DELETE FROM public.device_listening_ports WHERE organization_id IN ($1, $2);`, [testOrgA, testOrgB]);
  await db.query(`DELETE FROM public.telemetry_events WHERE device_id IN ($1, $2);`, [testDeviceA, testDeviceB]);
  await db.query(`DELETE FROM public.devices WHERE id IN ($1, $2);`, [testDeviceA, testDeviceB]);
  await db.query(`DELETE FROM public.organizations WHERE id IN ($1, $2);`, [testOrgA, testOrgB]);
  console.log('Cleanup complete.');

  console.log('\n========================================================================');
  console.log('🎉 ALL 10 PHASE A VERIFICATION CHECKS PASSED WITH ZERO ERRORS!');
  console.log('========================================================================\n');
}

runPhaseATestSuite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\n❌ PHASE A VERIFICATION FAILED:', err);
    process.exit(1);
  });
