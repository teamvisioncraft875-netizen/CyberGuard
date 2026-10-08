const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore } = require('./setup');

describe('Incident Service Tests', () => {
  let originalFetch;
  let incidentService;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/incidentService')];
    delete require.cache[require.resolve('../src/services/apiClient')];

    incidentService = require('../src/services/incidentService').incidentService;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('E1: getIncidents formats query parameters and parses list', async () => {
    let capturedUrl = null;
    global.fetch = async (url) => {
      capturedUrl = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          incidents: [
            { id: 'inc-1', threat_type: 'phishing', risk_level: 'critical' },
            { id: 'inc-2', threat_type: 'malicious_url', risk_level: 'high' }
          ],
          total: 2,
          limit: 10,
          offset: 0
        })
      };
    };

    const res = await incidentService.getIncidents({
      limit: 10,
      offset: 0,
      risk_level: 'high',
      status: 'open',
      threat_type: 'phishing'
    });

    assert.ok(capturedUrl.includes('limit=10'));
    assert.ok(capturedUrl.includes('offset=0'));
    assert.ok(capturedUrl.includes('risk_level=high'));
    assert.ok(capturedUrl.includes('status=open'));
    assert.ok(capturedUrl.includes('threat_type=phishing'));

    assert.strictEqual(res.incidents.length, 2);
    assert.strictEqual(res.total, 2);
  });

  it('E2: getIncidents handles backend responses returning data array instead of incidents', async () => {
    global.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: [{ id: 'inc-alt', risk_level: 'medium' }]
      })
    });

    const res = await incidentService.getIncidents();
    assert.strictEqual(res.incidents.length, 1);
    assert.strictEqual(res.incidents[0].id, 'inc-alt');
  });

  it('E3: getIncidentById retrieves single incident forensic record', async () => {
    let capturedUrl = null;
    global.fetch = async (url) => {
      capturedUrl = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          id: 'inc-42',
          risk_level: 'critical',
          explanation: 'Targeted spear-phishing attack with credential harvesting',
          mitre_mappings: [{ technique_id: 'T1566' }],
          signals: { urgency: true }
        })
      };
    };

    const res = await incidentService.getIncidentById('inc-42');
    assert.ok(capturedUrl.endsWith('/incidents/inc-42'));
    assert.strictEqual(res.id, 'inc-42');
    assert.strictEqual(res.mitre_mappings[0].technique_id, 'T1566');
  });

  it('E4: getIncidentById rejects empty incident id', async () => {
    await assert.rejects(
      async () => {
        await incidentService.getIncidentById('');
      },
      /Incident ID is required/
    );
  });
});
