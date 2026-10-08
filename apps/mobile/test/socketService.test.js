const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const { resetSecureStore, secureStoreMock } = require('./setup');

describe('Socket.IO Realtime Service Tests', () => {
  let socketService;
  let CONFIG;

  beforeEach(() => {
    resetSecureStore();

    delete require.cache[require.resolve('../src/services/socketService')];
    delete require.cache[require.resolve('../src/services/storageService')];
    delete require.cache[require.resolve('../src/constants/config')];

    socketService = require('../src/services/socketService').socketService;
    CONFIG = require('../src/constants/config').CONFIG;
  });

  afterEach(() => {
    socketService.disconnect();
  });

  it('SOC-1: connect returns null if user is not authenticated', async () => {
    const socket = await socketService.connect();
    assert.strictEqual(socket, null);
    assert.strictEqual(socketService.isConnected(), false);
  });

  it('SOC-2: connects with Bearer token when token is present in storage', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'socket_test_bearer_token');

    const socket = await socketService.connect();
    assert.ok(socket);
    assert.strictEqual(socket.connected, true);
    assert.strictEqual(socketService.isConnected(), true);
  });

  it('SOC-3: notifies incident subscribers when incident:new event fires', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'socket_token');
    const socket = await socketService.connect();

    let receivedIncident = null;
    const unsubscribe = socketService.subscribeToIncidents((incident) => {
      receivedIncident = incident;
    });

    // Simulate socket event
    socket._trigger('incident:new', { id: 'inc-live-1', risk_level: 'critical' });
    assert.strictEqual(receivedIncident.id, 'inc-live-1');

    // Test unsubscribe
    unsubscribe();
    socket._trigger('incident:new', { id: 'inc-live-2' });
    assert.strictEqual(receivedIncident.id, 'inc-live-1'); // Unchanged
  });

  it('SOC-4: notifies status listeners when connection state transitions', async () => {
    secureStoreMock.set(CONFIG.TOKEN_KEY, 'socket_token');

    const statusHistory = [];
    const unsubscribe = socketService.onStatusChange((connected) => {
      statusHistory.push(connected);
    });

    await socketService.connect();
    socketService.disconnect();

    unsubscribe();
    assert.ok(statusHistory.length >= 2);
  });
});
