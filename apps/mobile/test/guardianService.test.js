const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore } = require('./setup');

describe('Guardian Mode Service Tests', () => {
  let originalFetch;
  let guardianService;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/guardianService')];
    delete require.cache[require.resolve('../src/services/apiClient')];

    guardianService = require('../src/services/guardianService').guardianService;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('F1: listLinks sends status filter query', async () => {
    let capturedUrl = null;
    global.fetch = async (url) => {
      capturedUrl = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          links: [{ id: 'link-1', status: 'active', dependent_user_id: 'dep-1' }]
        })
      };
    };

    const res = await guardianService.listLinks({ status: 'active' });
    assert.ok(capturedUrl.includes('status=active'));
    assert.strictEqual(res.length, 1);
    assert.strictEqual(res[0].id, 'link-1');
  });

  it('F2: searchUserByEmail encodes email in query string', async () => {
    let capturedUrl = null;
    global.fetch = async (url) => {
      capturedUrl = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          users: [{ id: 'u-55', email: 'child+test@example.com' }]
        })
      };
    };

    const res = await guardianService.searchUserByEmail('child+test@example.com');
    assert.ok(capturedUrl.includes('email=child%2Btest%40example.com'));
    assert.strictEqual(res.users[0].id, 'u-55');
  });

  it('F3: searchUserByEmail rejects empty search queries', async () => {
    await assert.rejects(
      async () => {
        await guardianService.searchUserByEmail('   ');
      },
      /valid email address to search/
    );
  });

  it('F4: createLink disallows self-linking and sends guardian/dependent ids', async () => {
    await assert.rejects(
      async () => {
        await guardianService.createLink({
          guardian_user_id: 'user-same',
          dependent_user_id: 'user-same'
        });
      },
      /cannot establish a guardian link with your own account/
    );

    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 201,
        json: async () => ({ id: 'link-new', status: 'pending' })
      };
    };

    const res = await guardianService.createLink({
      guardian_user_id: 'g-1',
      dependent_user_id: 'd-2'
    });

    assert.strictEqual(capturedBody.guardian_user_id, 'g-1');
    assert.strictEqual(capturedBody.dependent_user_id, 'd-2');
    assert.strictEqual(res.id, 'link-new');
  });

  it('F5: acceptLink, declineLink, and revokeLink hit appropriate lifecycle routes', async () => {
    const calledUrls = [];
    global.fetch = async (url) => {
      calledUrls.push(url);
      return {
        ok: true,
        status: 200,
        json: async () => ({ status: 'success' })
      };
    };

    await guardianService.acceptLink('lnk-1');
    await guardianService.declineLink('lnk-2');
    await guardianService.revokeLink('lnk-3');

    assert.ok(calledUrls[0].endsWith('/guardian/link/lnk-1/accept'));
    assert.ok(calledUrls[1].endsWith('/guardian/link/lnk-2/decline'));
    assert.ok(calledUrls[2].endsWith('/guardian/link/lnk-3/revoke'));
  });

  it('F6: getAlerts retrieves dependent threat notifications', async () => {
    global.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => [
        {
          alert_id: 'alt-1',
          dependent_name: 'Alex',
          risk_level: 'critical',
          threat_type: 'phishing'
        }
      ]
    });

    const alerts = await guardianService.getAlerts();
    assert.strictEqual(alerts.length, 1);
    assert.strictEqual(alerts[0].dependent_name, 'Alex');
  });
});
