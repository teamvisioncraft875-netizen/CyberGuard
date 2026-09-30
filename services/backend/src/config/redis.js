const { createClient } = require('redis');

let client = null;
let isConnectedState = false;
let mockStorage = null; // In-memory cache store for tests or fallback emulation

/**
 * Initializes the Redis client if REDIS_URL is provided in environment variables.
 */
function initRedis() {
  const redisUrl = process.env.REDIS_URL;

  if (!redisUrl) {
    client = null;
    isConnectedState = false;
    return null;
  }

  try {
    client = createClient({
      url: redisUrl,
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 3) {
            return false; // Stop trying if Redis server is unavailable
          }
          return Math.min(retries * 200, 1000);
        }
      }
    });

    client.on('connect', () => {
      isConnectedState = true;
    });

    client.on('ready', () => {
      isConnectedState = true;
    });

    client.on('error', (err) => {
      isConnectedState = false;
      console.warn('[Redis Error]', err.message);
    });

    client.on('end', () => {
      isConnectedState = false;
    });

    return client;
  } catch (err) {
    console.warn('[Redis Initialization Warning]', err.message);
    client = null;
    isConnectedState = false;
    return null;
  }
}

/**
 * Attempts to connect to Redis at application startup.
 * Fails gracefully without throwing an error if Redis is unreachable.
 */
async function connectRedis() {
  if (mockStorage) {
    isConnectedState = true;
    return true;
  }

  if (!client) {
    initRedis();
  }

  if (!client) {
    isConnectedState = false;
    return false;
  }

  try {
    if (!client.isOpen) {
      await client.connect();
    }
    isConnectedState = true;
    return true;
  } catch (err) {
    isConnectedState = false;
    console.warn('[Redis Connection Warning] Could not connect to Redis at startup:', err.message);
    return false;
  }
}

/**
 * Health check: returns true if Redis is connected and ready to accept commands.
 * @returns {boolean}
 */
function isConnected() {
  if (mockStorage) {
    return isConnectedState;
  }
  return isConnectedState && client?.isOpen === true;
}

/**
 * Retrieves a string value from Redis cache. Returns null on cache miss or error.
 *
 * @param {string} key
 * @returns {Promise<string|null>}
 */
async function get(key) {
  if (mockStorage && isConnectedState) {
    const item = mockStorage.get(key);
    if (!item) return null;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      mockStorage.delete(key);
      return null;
    }
    return item.value;
  }

  if (!isConnected() || !client) {
    return null;
  }

  try {
    return await client.get(key);
  } catch (err) {
    console.warn(`[Redis GET Warning] Failed for key ${key}:`, err.message);
    return null;
  }
}

/**
 * Stores a value in Redis with optional TTL in seconds.
 *
 * @param {string} key
 * @param {string} value
 * @param {Object} [options]
 * @param {number} [options.EX] - TTL in seconds
 * @returns {Promise<string|null>}
 */
async function set(key, value, options = {}) {
  const ttlSeconds = options.EX || options.ex || (options.ttl ? Math.floor(options.ttl) : null);

  if (mockStorage && isConnectedState) {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
    mockStorage.set(key, { value: String(value), expiresAt });
    return 'OK';
  }

  if (!isConnected() || !client) {
    return null;
  }

  try {
    const redisOpts = {};
    if (ttlSeconds) {
      redisOpts.EX = ttlSeconds;
    }
    return await client.set(key, String(value), redisOpts);
  } catch (err) {
    console.warn(`[Redis SET Warning] Failed for key ${key}:`, err.message);
    return null;
  }
}

/**
 * Deletes a key from Redis.
 *
 * @param {string} key
 * @returns {Promise<number>} Number of keys removed
 */
async function del(key) {
  if (mockStorage) {
    const existed = mockStorage.delete(key);
    return existed ? 1 : 0;
  }

  if (!isConnected() || !client) {
    return 0;
  }

  try {
    return await client.del(key);
  } catch (err) {
    console.warn(`[Redis DEL Warning] Failed for key ${key}:`, err.message);
    return 0;
  }
}

/**
 * Test & environment helpers for isolated tests
 */
function enableMockRedis() {
  mockStorage = new Map();
  isConnectedState = true;
}

function disableMockRedis() {
  isConnectedState = false;
}

function clearMockRedis() {
  if (mockStorage) {
    mockStorage.clear();
  }
}

function getMockStorage() {
  return mockStorage;
}

module.exports = {
  client,
  connectRedis,
  isConnected,
  get,
  set,
  del,
  enableMockRedis,
  disableMockRedis,
  clearMockRedis,
  getMockStorage
};
