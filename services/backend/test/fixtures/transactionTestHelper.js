const db = require('../../src/config/db');
const { createOrganizationFixture, createUserFixture, cleanupFixtures } = require('./index');
const jwt = require('jsonwebtoken');

/**
 * Transaction-Based Test Isolation Helper
 * Executes operations inside a database transaction and rolls back automatically.
 */
async function withTransaction(testFn) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN;');
    await testFn(client);
  } finally {
    try {
      await client.query('ROLLBACK;');
    } catch (rbErr) {
      console.warn('[withTransaction Rollback Warning]:', rbErr.message);
    }
    client.release();
  }
}

/**
 * Executes a test with an ephemeral organization and user, then performs targeted cleanup
 */
async function withIsolatedTenant(testFn) {
  const org = await createOrganizationFixture();
  const user = await createUserFixture({ organization_id: org.id, role: 'admin' });
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: 'analyst',
      organization_id: org.id
    },
    process.env.JWT_SECRET || 'cyberguard-super-secure-secret-key-32chars!',
    { expiresIn: '1h' }
  );

  try {
    await testFn({ org, user, token });
  } finally {
    await cleanupFixtures({ orgIds: [org.id], userIds: [user.id] });
  }
}

module.exports = {
  withTransaction,
  withIsolatedTenant
};
