const cron = require('node-cron');
const db = require('../config/db');
const executionService = require('./executionService');

let cronTask = null;
let isRunning = false;
let lastRunTimestamp = null;
let actionsExecutedThisHour = {};
let isProcessing = false;

const MAX_EXECUTIONS_PER_HOUR = 10;

/**
 * Counts how many actions were executed in the past hour for a given organization.
 *
 * @param {string|null} orgId
 * @returns {Promise<number>}
 */
async function countOrgExecutionsLastHour(orgId) {
  try {
    let queryText;
    let params;
    if (!orgId || orgId === 'unassigned') {
      queryText = `
        SELECT COUNT(*)::int AS count
        FROM public.response_actions
        WHERE organization_id IS NULL
          AND executed_at > NOW() - INTERVAL '1 hour'
          AND status = 'executed';
      `;
      params = [];
    } else {
      queryText = `
        SELECT COUNT(*)::int AS count
        FROM public.response_actions
        WHERE organization_id = $1
          AND executed_at > NOW() - INTERVAL '1 hour'
          AND status = 'executed';
      `;
      params = [orgId];
    }
    const res = await db.query(queryText, params);
    return res.rows[0]?.count || 0;
  } catch (err) {
    console.error(`[schedulerService] Error counting executions for org ${orgId}:`, err.message);
    return 0;
  }
}

/**
 * Refreshes the in-memory map of actions executed this hour across all organizations.
 */
async function refreshHourlyCounts() {
  try {
    const res = await db.query(`
      SELECT COALESCE(organization_id::text, 'unassigned') AS org_id, COUNT(*)::int AS count
      FROM public.response_actions
      WHERE executed_at > NOW() - INTERVAL '1 hour'
        AND status = 'executed'
      GROUP BY organization_id;
    `);
    const counts = {};
    for (const row of res.rows) {
      counts[row.org_id] = row.count;
    }
    actionsExecutedThisHour = counts;
  } catch (err) {
    console.warn('[schedulerService] Error refreshing hourly counts:', err.message);
  }
}

/**
 * Main job logic: checks for due actions and executes them with circuit breaker guardrails.
 * Never throws an unhandled error.
 */
async function processDueActions() {
  if (!isRunning) return;

  if (isProcessing) {
    console.log('[schedulerService] Previous cycle is still running. Skipping overlapping run.');
    return;
  }

  isProcessing = true;
  lastRunTimestamp = new Date();
  let lockClient = null;
  let lockAcquired = false;

  try {
    try {
      lockClient = await db.pool.connect();
      const lockRes = await lockClient.query(
        'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired;',
        ['cyberguard_scheduler_lock']
      );
      lockAcquired = Boolean(lockRes.rows[0]?.acquired);
      if (!lockAcquired) {
        console.log('[schedulerService] Advisory lock already held by another scheduler worker. Skipping cycle.');
        if (lockClient) lockClient.release();
        isProcessing = false;
        return;
      }
    } catch (lErr) {
      if (lockClient) lockClient.release();
      isProcessing = false;
      return;
    }

    // 1. Sync recent execution stats
    await refreshHourlyCounts();
    if (!isRunning) {
      if (lockClient && lockAcquired) {
        await lockClient.query('SELECT pg_advisory_unlock(hashtext($1));', ['cyberguard_scheduler_lock']);
        lockClient.release();
      }
        isProcessing = false;
        return;
      }

      // 2. Query response_actions WHERE status IN ('scheduled', 'approved') AND scheduled_at <= NOW()
      const dueQuery = `
        SELECT *
        FROM public.response_actions
        WHERE status IN ('scheduled', 'approved')
          AND scheduled_at IS NOT NULL
          AND scheduled_at <= NOW()
        ORDER BY scheduled_at ASC;
      `;
      const { rows: dueActions } = await db.query(dueQuery);

      if (!dueActions || dueActions.length === 0 || !isRunning) {
        if (lockClient && lockAcquired) {
          await lockClient.query('SELECT pg_advisory_unlock(hashtext($1));', ['cyberguard_scheduler_lock']);
          lockClient.release();
        }
        isProcessing = false;
        return;
      }

    console.log(`[schedulerService] Found ${dueActions.length} due response action(s) to process`);

    // 3. Group by organization_id
    const actionsByOrg = {};
    for (const action of dueActions) {
      const orgId = action.organization_id ? String(action.organization_id) : 'unassigned';
      if (!actionsByOrg[orgId]) {
        actionsByOrg[orgId] = [];
      }
      actionsByOrg[orgId].push(action);
    }

    // 4. Process each organization batch with circuit breaker (max 10 executions/hour)
    for (const [orgId, orgActions] of Object.entries(actionsByOrg)) {
      if (!isRunning) break;

      let executedLastHour = await countOrgExecutionsLastHour(orgId === 'unassigned' ? null : orgId);
      actionsExecutedThisHour[orgId] = executedLastHour;

      if (executedLastHour >= MAX_EXECUTIONS_PER_HOUR) {
        console.warn(
          `[schedulerService] [CIRCUIT BREAKER] Org ${orgId} has reached the limit of ${MAX_EXECUTIONS_PER_HOUR} executions in the past hour (${executedLastHour} executed). Skipping batch of ${orgActions.length} action(s).`
        );
        continue;
      }

      for (const action of orgActions) {
        if (!isRunning) {
          console.log('[schedulerService] Scheduler stopped during processing. Aborting execution loop.');
          break;
        }

        if (executedLastHour >= MAX_EXECUTIONS_PER_HOUR) {
          console.warn(
            `[schedulerService] [CIRCUIT BREAKER] Org ${orgId} reached execution limit of ${MAX_EXECUTIONS_PER_HOUR}/hour during batch. Skipping remaining action(s).`
          );
          break;
        }

        try {
          console.log(`[schedulerService] Auto-executing scheduled action ${action.id} (${action.action_type}) for org ${orgId}`);
          const execRes = await executionService.execute(action, {
            actor_type: 'background_scheduler'
          });

          if (execRes && execRes.success) {
            executedLastHour++;
            actionsExecutedThisHour[orgId] = executedLastHour;
          }
        } catch (actionErr) {
          // Never throw; log error and continue to next action
          console.error(`[schedulerService] Error executing action ${action.id}:`, actionErr.message);
        }
      }
    }
  } catch (cycleErr) {
    console.error('[schedulerService] Uncaught error in scheduler cycle:', cycleErr.message);
  } finally {
    if (lockClient && lockAcquired) {
      try {
        await lockClient.query('SELECT pg_advisory_unlock(hashtext($1));', ['cyberguard_scheduler_lock']);
      } catch (uErr) {}
      lockClient.release();
    }
    isProcessing = false;
  }
}

/**
 * Starts the background node-cron scheduler.
 * Runs every 60 seconds (every minute).
 *
 * @param {string} [cronPattern='* * * * *']
 * @returns {Object}
 */
function startScheduler(cronPattern = '* * * * *') {
  if (isRunning && cronTask) {
    console.log('[schedulerService] Background scheduler is already running');
    return cronTask;
  }

  isRunning = true;

  // Refresh hourly counts at startup
  refreshHourlyCounts().catch(() => {});

  cronTask = cron.schedule(cronPattern, async () => {
    if (!isRunning) return;
    await processDueActions();
  });

  console.log(`[schedulerService] Background scheduler started (runs every 60 seconds with pattern "${cronPattern}")`);
  return cronTask;
}

/**
 * Stops the background scheduler for graceful shutdown.
 *
 * @param {boolean} [waitForDrain=true]
 */
async function stopScheduler(waitForDrain = true) {
  isRunning = false;
  if (cronTask) {
    cronTask.stop();
    cronTask = null;
  }
  console.log('[schedulerService] Background scheduler stopped');

  if (waitForDrain && isProcessing) {
    const start = Date.now();
    while (isProcessing && Date.now() - start < 4000) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
}

/**
 * Returns the current runtime status and hourly execution counts.
 *
 * @returns {{ running: boolean, last_run: Date|null, actions_executed_this_hour: Object }}
 */
function getSchedulerStatus() {
  return {
    running: isRunning,
    last_run: lastRunTimestamp,
    actions_executed_this_hour: { ...actionsExecutedThisHour }
  };
}

module.exports = {
  startScheduler,
  stopScheduler,
  getSchedulerStatus,
  processDueActions,
  refreshHourlyCounts
};
