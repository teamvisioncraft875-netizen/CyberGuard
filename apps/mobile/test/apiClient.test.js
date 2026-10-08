const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore, secureStoreMock } = require('./setup');

describe('API Client Unit & Integration Tests', () => {
  let originalFetch;
  let apiClient;
  let apiRequest;
  let setUnauthorizedHandler;
  let CONFIG;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    // Load fresh modules
    delete require.cache[require.resolve('../src/services/apiClient')];
    delete require.cache[require.resolve('../src/services/storageService')];
    delete require.cache[require.resolve('../src/constants/config')];

    const clientMod = require('../src/services/apiClient');
    apiClient = clientMod.apiClient;
    apiRequest = clientMod.apiRequest;
    setUnauthorizedHandler = clientMod.setUnauthorizedHandler;
    CONFIG = require('../src/constants/config').CONFIG;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('A1: attaches Authorization Bearer header when token is present', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'valid_test_token_123');

    let capturedHeaders = null;
    global.fetch = async (url, options) => {
      capturedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        json: async () => ({ status: 'ok' })
      };
    };

    const res = await apiClient.get('/test/endpoint');
    assert.strictEqual(res.status, 'ok');
    assert.strictEqual(capturedHeaders.Authorization, 'Bearer valid_test_token_123');
  });

  it('A2: performs successful GET, POST, PATCH, DELETE requests', async () => {
    const calledMethods = [];
    global.fetch = async (url, options) => {
      calledMethods.push(options.method);
      return {
        ok: true,
        status: 200,
        json: async () => ({ method: options.method })
      };
    };

    await apiClient.get('/resource');
    await apiClient.post('/resource', { name: 'test' });
    await apiClient.patch('/resource', { name: 'updated' });
    await apiClient.delete('/resource');

    assert.deepStrictEqual(calledMethods, ['GET', 'POST', 'PATCH', 'DELETE']);
  });

  it('A3: throws formatted error on non-401 HTTP failures', async () => {
    global.fetch = async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: 'BAD_REQUEST', message: 'Invalid payload provided' })
    });

    await assert.rejects(
      async () => {
        await apiClient.get('/bad-request');
      },
      (err) => {
        assert.strictEqual(err.status, 400);
        assert.strictEqual(err.code, 'BAD_REQUEST');
        assert.strictEqual(err.message, 'Invalid payload provided');
        return true;
      }
    );
  });

  it('A4: automatically refreshes token on TOKEN_EXPIRED and replays request', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'expired_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'valid_refresh_token');

    let requestCount = 0;
    global.fetch = async (url, options) => {
      requestCount++;
      if (url.includes('/auth/refresh')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'new_fresh_token_456' })
        };
      }
      if (options.headers.Authorization === 'Bearer expired_token') {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'TOKEN_EXPIRED', message: 'Token has expired' })
        };
      }
      if (options.headers.Authorization === 'Bearer new_fresh_token_456') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ secret_data: 'success' })
        };
      }
      throw new Error(`Unexpected call to ${url}`);
    };

    const res = await apiClient.get('/protected-resource');
    assert.strictEqual(res.secret_data, 'success');
    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), 'new_fresh_token_456');
    assert.strictEqual(requestCount, 3); // 1: initial 401, 2: /auth/refresh, 3: replayed request
  });

  it('A5: prevents infinite retry loops with _retry flag', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'loop_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'loop_refresh_token');

    let unauthorizedTriggered = false;
    setUnauthorizedHandler(() => {
      unauthorizedTriggered = true;
    });

    global.fetch = async (url) => {
      if (url.includes('/auth/refresh')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'still_expired_token' })
        };
      }
      return {
        ok: false,
        status: 401,
        json: async () => ({ error: 'TOKEN_EXPIRED', message: 'Token has expired' })
      };
    };

    await assert.rejects(
      async () => {
        await apiClient.get('/resource-loop');
      },
      (err) => {
        assert.strictEqual(err.status, 401);
        return true;
      }
    );

    assert.strictEqual(unauthorizedTriggered, true);
  });

  it('A6: queues concurrent 401s during single refresh cycle', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'old_token');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'good_refresh_token');

    let refreshCallCount = 0;
    global.fetch = async (url, options) => {
      if (url.includes('/auth/refresh')) {
        refreshCallCount++;
        // Small delay to simulate real network trip
        await new Promise((r) => setTimeout(r, 20));
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'shared_new_token' })
        };
      }
      if (options.headers.Authorization === 'Bearer old_token') {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'TOKEN_EXPIRED' })
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ url, success: true })
      };
    };

    // Fire 3 simultaneous requests
    const [res1, res2, res3] = await Promise.all([
      apiClient.get('/req-1'),
      apiClient.get('/req-2'),
      apiClient.get('/req-3')
    ]);

    assert.strictEqual(res1.success, true);
    assert.strictEqual(res2.success, true);
    assert.strictEqual(res3.success, true);
    // Refresh was only invoked ONCE despite 3 concurrent 401s
    assert.strictEqual(refreshCallCount, 1);
    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), 'shared_new_token');
  });

  it('A7: clears tokens and triggers logout handler when refresh fails', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'token_a');
    secureStoreMock.set(CONFIG.REFRESH_TOKEN_KEY, 'bad_refresh');

    let logoutCalled = false;
    setUnauthorizedHandler(() => {
      logoutCalled = true;
    });

    global.fetch = async (url) => {
      if (url.includes('/auth/refresh')) {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'INVALID_REFRESH_TOKEN' })
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
        await apiClient.get('/test');
      },
      (err) => {
        assert.strictEqual(err.code, 'REFRESH_TOKEN_INVALID');
        return true;
      }
    );

    assert.strictEqual(logoutCalled, true);
    assert.strictEqual(secureStoreMock.get(CONFIG.TOKEN_KEY), undefined);
    assert.strictEqual(secureStoreMock.get(CONFIG.REFRESH_TOKEN_KEY), undefined);
  });
});
