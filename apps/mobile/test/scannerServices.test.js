const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore, secureStoreMock } = require('./setup');

describe('Threat Scanner Services Tests', () => {
  let originalFetch;
  let scannerService;
  let secretService;

  beforeEach(() => {
    resetSecureStore();
    originalFetch = global.fetch;

    delete require.cache[require.resolve('../src/services/scannerService')];
    delete require.cache[require.resolve('../src/services/secretService')];
    delete require.cache[require.resolve('../src/services/apiClient')];

    scannerService = require('../src/services/scannerService').scannerService;
    secretService = require('../src/services/secretService').secretService;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // URL SCANNER
  it('C1: scanUrl normalizes missing protocol scheme and sends URL payload', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          risk_level: 'safe',
          explanation: 'Legitimate domain'
        })
      };
    };

    const res = await scannerService.scanUrl('google.com');
    assert.strictEqual(capturedBody.url, 'https://google.com');
    assert.strictEqual(res.risk_level, 'safe');
  });

  it('C2: scanUrl rejects empty or invalid inputs before network trip', async () => {
    await assert.rejects(
      async () => {
        await scannerService.scanUrl('');
      },
      /valid URL/
    );

    await assert.rejects(
      async () => {
        await scannerService.scanUrl('   ');
      },
      /valid URL/
    );
  });

  // MESSAGE SCANNER
  it('C3: scanMessage sends text and validates channel source type', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          risk_level: 'critical',
          explanation: 'Urgent phishing threat detected'
        })
      };
    };

    const res = await scannerService.scanMessage('Your account is locked, click now', 'email');
    assert.strictEqual(capturedBody.text, 'Your account is locked, click now');
    assert.strictEqual(capturedBody.source_type, 'email');
    assert.strictEqual(res.risk_level, 'critical');
  });

  it('C4: scanMessage falls back to sms for unknown source channel', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({ risk_level: 'safe' })
      };
    };

    await scannerService.scanMessage('Test alert message', 'unknown_channel');
    assert.strictEqual(capturedBody.source_type, 'sms');
  });

  // SECRET SCANNER
  it('C5: scanSecret sends input and optional context payload', async () => {
    let capturedBody = null;
    global.fetch = async (url, options) => {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          risk_level: 'high',
          risk_score: 85,
          detected_secrets: [{ secret_type: 'AWS_ACCESS_KEY', severity: 'high', location: 'line 1' }]
        })
      };
    };

    const res = await secretService.scanSecret('AKIAIOSFODNN7EXAMPLE', { context: 'ci-pipeline' });
    assert.strictEqual(capturedBody.input, 'AKIAIOSFODNN7EXAMPLE');
    assert.strictEqual(capturedBody.context, 'ci-pipeline');
    assert.strictEqual(res.detected_secrets.length, 1);
  });

  it('C6: scanSecret maps rate limits (429) to clean human readable errors', async () => {
    global.fetch = async () => ({
      ok: false,
      status: 429,
      json: async () => ({ error: 'RATE_LIMIT_EXCEEDED' })
    });

    await assert.rejects(
      async () => {
        await secretService.scanSecret('secret_content');
      },
      /Rate limit exceeded/
    );
  });

  it('C7: scanSecret maps 502 bad gateway to friendly retry message', async () => {
    global.fetch = async () => ({
      ok: false,
      status: 502,
      json: async () => ({ error: 'BAD_GATEWAY' })
    });

    await assert.rejects(
      async () => {
        await secretService.scanSecret('secret_content');
      },
      /Threat inspection service temporarily unavailable/
    );
  });
});
