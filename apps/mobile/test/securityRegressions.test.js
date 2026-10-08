const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore, secureStoreMock } = require('./setup');

describe('Security Regression & Privacy Tests', () => {
  let originalFetch;
  let apiClient;
  let secretService;
  let authService;
  let CONFIG;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/apiClient')];
    delete require.cache[require.resolve('../src/services/secretService')];
    delete require.cache[require.resolve('../src/services/authService')];
    delete require.cache[require.resolve('../src/services/storageService')];
    delete require.cache[require.resolve('../src/constants/config')];

    apiClient = require('../src/services/apiClient').apiClient;
    secretService = require('../src/services/secretService').secretService;
    authService = require('../src/services/authService').authService;
    CONFIG = require('../src/constants/config').CONFIG;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('SEC-1: refresh token is never attached as Authorization Bearer header', async () => {
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'secret_refresh_token_789');

    let capturedHeaders = null;
    global.fetch = async (url, options) => {
      capturedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        json: async () => ({ status: 'ok' })
      };
    };

    await apiClient.get('/test/no-token');
    // If no access token is stored, Authorization header must NOT be populated with refresh token
    assert.strictEqual(capturedHeaders.Authorization, undefined);
  });

  it('SEC-2: secret scanner errors never leak raw candidate secret input', async () => {
    const rawSecret = 'SUPER_CONFIDENTIAL_KEY_AKIAIOSFODNN7EXAMPLE';

    global.fetch = async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: 'INVALID_INPUT', message: 'Payload validation failed on server' })
    });

    try {
      await secretService.scanSecret(rawSecret);
      assert.fail('Should have thrown error');
    } catch (err) {
      assert.ok(!err.message.includes(rawSecret), 'Error message must not include the raw secret');
    }
  });

  it('SEC-3: expired sessions are completely cleared upon invalid refresh', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'expired_access_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'revoked_refresh_token');
    secureStoreMock.set(CONFIG.USER_KEY, JSON.stringify({ id: 'u-1', email: 'compromised@user.com' }));

    global.fetch = async (url) => {
      if (url.includes('/auth/refresh')) {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'REVOKED_TOKEN' })
        };
      }
      return {
        ok: false,
        status: 401,
        json: async () => ({ error: 'TOKEN_EXPIRED' })
      };
    };

    await assert.rejects(
      async () => {
        await apiClient.get('/sensitive-dashboard');
      },
      /Session expired, please login again/
    );

    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), undefined);
    assert.strictEqual(secureStoreMock.get(CONFIG.REFRESH_TOKEN_KEY), undefined);
  });

  it('SEC-4: non-token-expired 401 (e.g. USER_SUSPENDED) immediately triggers logout without refresh loop', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'user_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'valid_refresh');

    let refreshAttempted = false;
    global.fetch = async (url) => {
      if (url.includes('/auth/refresh')) {
        refreshAttempted = true;
      }
      return {
        ok: false,
        status: 401,
        json: async () => ({ error: 'USER_SUSPENDED', message: 'Your account has been suspended by SOC' })
      };
    };

    await assert.rejects(
      async () => {
        await apiClient.get('/account-status');
      },
      /Your account has been suspended/
    );

    // Refresh must NOT be attempted when error is not TOKEN_EXPIRED
    assert.strictEqual(refreshAttempted, false);
  });

  it('SEC-5: secrets scanned are not written to persistent storage', async () => {
    const candidateSecret = 'ghp_secretCandidateTokenToInspect12345';

    global.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ risk_level: 'safe', detected_secrets: [] })
    });

    await secretService.scanSecret(candidateSecret);

    // Ensure mock storage does not contain the secret anywhere
    for (const [key, value] of secureStoreMock.entries()) {
      assert.ok(!String(value).includes(candidateSecret), `Storage key ${key} should not contain scanned secret`);
    }
  });
});
