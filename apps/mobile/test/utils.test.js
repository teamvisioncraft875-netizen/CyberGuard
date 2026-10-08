const { describe, it } = require('node:test');
const assert = require('node:assert');
require('./setup');

const {
  getRiskColor,
  getRiskMutedBg,
  formatThreatType
} = require('../src/utils/riskHelpers');

const {
  formatDate,
  truncate
} = require('../src/utils/formatters');

describe('Security Utilities & Pure Logic Tests', () => {
  it('UTIL-1: getRiskColor returns appropriate color token for all risk tiers', () => {
    assert.strictEqual(getRiskColor('critical'), '#ef4444');
    assert.strictEqual(getRiskColor('high'), '#f97316');
    assert.strictEqual(getRiskColor('medium'), '#f59e0b');
    assert.strictEqual(getRiskColor('low'), '#38bdf8');
    assert.strictEqual(getRiskColor('safe'), '#10b981');
    assert.strictEqual(getRiskColor('unknown'), '#64748b');
  });

  it('UTIL-2: getRiskMutedBg returns translucent background color token', () => {
    assert.strictEqual(getRiskMutedBg('critical'), 'rgba(239, 68, 68, 0.16)');
    assert.strictEqual(getRiskMutedBg('safe'), 'rgba(16, 185, 129, 0.14)');
  });

  it('UTIL-3: formatThreatType produces canonical human readable threat labels', () => {
    assert.strictEqual(formatThreatType('phishing'), 'Phishing Message');
    assert.strictEqual(formatThreatType('malicious_url'), 'Malicious URL');
    assert.strictEqual(formatThreatType('deepfake'), 'Synthetic / Deepfake Media');
    assert.strictEqual(formatThreatType('account_takeover'), 'Suspicious Authentication');
    assert.strictEqual(formatThreatType('exposed_secret'), 'Exposed Credential / Secret');
    assert.strictEqual(formatThreatType(null), 'Unclassified Threat');
  });

  it('UTIL-4: formatters handle null and invalid date timestamps gracefully', () => {
    assert.strictEqual(formatDate(null), 'Just now');
    assert.strictEqual(formatDate('invalid-date-string'), 'Recently');
    assert.strictEqual(truncate('Hello World', 5), 'Hello...');
    assert.strictEqual(truncate('Short', 10), 'Short');
    assert.strictEqual(truncate(null), '');
  });
});
