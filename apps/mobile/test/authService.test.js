const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore, secureStoreMock } = require('./setup');

describe('Auth Service Tests', () => {
  let originalFetch;
  let authService;
  let CONFIG;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/authService')];
    delete require.cache[require.resolve('../src/services/apiClient')];
    delete require.cache[require.resolve('../src/services/storageService')];
    delete require.cache[require.resolve('../src/constants/config')];

    authService = require('../src/services/authService').authService;
    CONFIG = require('../src/constants/config').CONFIG;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('B1: login sends correct credentials and persists tokens + user', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          token: 'jwt_access_token_abc',
          refreshToken: 'refresh_token_xyz',
          user: { id: 'u-1', email: 'analyst@cyberguard.io', role: 'individual' }
        })
      };
    };

    const res = await authService.login('analyst@cyberguard.io', 'SecurePass123!');
    assert.strictEqual(capturedBody.email, 'analyst@cyberguard.io');
    assert.strictEqual(capturedBody.password, 'SecurePass123!');
    assert.strictEqual(res.user.id, 'u-1');

    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), 'jwt_access_token_abc');
    assert.strictEqual(secureStoreMock.get(CONFIG.REFRESH_TOKEN_KEY), 'refresh_token_xyz');
    assert.ok(secureStoreMock.get(CONFIG.USER_KEY).includes('analyst@cyberguard.io'));
  });

  it('B2: signup sends correct role and organization_name payload', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 201,
        json: async () => ({
          token: 'jwt_employee_token',
          refreshToken: 'refresh_emp_token',
          user: { id: 'u-2', email: 'emp@corp.com', role: 'employee' }
        })
      };
    };

    await authService.signup('emp@corp.com', 'Pass123!', 'employee', 'CyberDefenseCorp');
    assert.strictEqual(capturedBody.email, 'emp@corp.com');
    assert.strictEqual(capturedBody.role, 'employee');
    assert.strictEqual(capturedBody.organization_name, 'CyberDefenseCorp');
  });

  it('B3: logout purges all tokens from secure storage and notifies backend', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'active_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'active_refresh');
    secureStoreMock.set(CONFIG.USER_KEY, JSON.stringify({ id: 'u-1' }));

    let logoutCalled = false;
    global.fetch = async (url) => {
      if (url.includes('/auth/logout')) {
        logoutCalled = true;
      }
      return { ok: true, status: 200, json: async () => ({}) };
    };

    await authService.logout();
    assert.strictEqual(logoutCalled, true);
    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), undefined);
    assert.strictEqual(secureStoreMock.get(CONFIG.REFRESH_TOKEN_KEY), undefined);
    assert.strictEqual(secureStoreMock.get(CONFIG.USER_KEY), undefined);
  });

  it('B4: getMe retrieves current user and updates local user cache', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'valid_token');

    global.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ id: 'u-99', email: 'updated@cyberguard.io', role: 'admin' })
    });

    const user = await authService.getMe();
    assert.strictEqual(user.id, 'u-99');
    assert.ok(secureStoreMock.get(CONFIG.USER_KEY).includes('updated@cyberguard.io'));
  });

  it('B5: getStoredSession parses cached user profile safely', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'saved_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'saved_refresh');
    secureStoreMock.set(CONFIG.USER_KEY, JSON.stringify({ id: 'u-1', email: 'cached@test.com' }));

    const session = await authService.getStoredSession();
    assert.strictEqual(session.token, 'saved_token');
    assert.strictEqual(session.refreshToken, 'saved_refresh');
    assert.strictEqual(session.user.email, 'cached@test.com');
  });
});
