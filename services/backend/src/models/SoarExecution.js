const db = require('../config/db');

/**
 * SoarExecution Model — Tenant-scoped execution tracking for security playbooks
 * Supports execution resiliency, retries, backoff metadata, and recovery.
 */
const SoarExecution = {
  VALID_STATUSES: ['pending', 'running', 'waiting_approval', 'retrying', 'completed', 'failed', 'cancelled'],

  /**
   * Creates a new execution record for a playbook.
   */
  async create({
    organization_id,
    playbook_id,
    trigger_alert_id = null,
    status = 'pending',
    retry_count = 0,
    max_retries = 3,
    backoff_metadata = {}
  }, client = null) {
    if (!organization_id) throw new Error('SoarExecution Error: organization_id is required');
    if (!playbook_id) throw new Error('SoarExecution Error: playbook_id is required');

    const cleanStatus = (status || 'pending').toLowerCase();
    const dbClient = client || db;

    const query = `
      INSERT INTO public.soar_executions (
        organization_id,
        playbook_id,
        trigger_alert_id,
        status,
        retry_count,
        max_retries,
        backoff_metadata,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      organization_id,
      playbook_id,
      trigger_alert_id,
      cleanStatus,
      retry_count,
      max_retries,
      JSON.stringify(backoff_metadata || {})
    ]);

    return res.rows[0];
  },

  /**
   * Retrieves an execution by ID with playbook details and execution steps.
   */
  async findById(id, organization_id, client = null) {
    if (!organization_id) throw new Error('SoarExecution Error: organization_id is required');
    if (!id) return null;

    const dbClient = client || db;
    const query = `
      SELECT 
        e.*,
        p.name AS playbook_name,
        p.description AS playbook_description,
        p.trigger_type AS playbook_trigger_type
      FROM public.soar_executions e
      LEFT JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE e.id = $1 AND e.organization_id = $2;
    `;

    const res = await dbClient.query(query, [id, organization_id]);
    if (res.rows.length === 0) return null;

    const execution = res.rows[0];
    execution.steps = await this.getExecutionSteps(id, dbClient);
    return execution;
  },

  /**
   * Queries executions with optional tenant filtering and pagination.
   */
  async findMany({
    organization_id,
    playbook_id,
    status,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('SoarExecution Error: organization_id is required');

    const dbClient = client || db;
    const params = [organization_id];
    let idx = 2;
    const whereClauses = ['e.organization_id = $1'];

    if (playbook_id) {
      whereClauses.push(`e.playbook_id = $${idx++}`);
      params.push(playbook_id);
    }

    if (status) {
      whereClauses.push(`e.status = $${idx++}`);
      params.push(status.toLowerCase());
    }

    const whereStr = whereClauses.join(' AND ');

    const countQuery = `
      SELECT COUNT(*)::int AS total 
      FROM public.soar_executions e 
      WHERE ${whereStr};
    `;
    const countRes = await dbClient.query(countQuery, params);
    const total = countRes.rows[0]?.total || 0;

    const dataQuery = `
      SELECT 
        e.*,
        p.name AS playbook_name,
        p.trigger_type AS playbook_trigger_type
      FROM public.soar_executions e
      LEFT JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE ${whereStr}
      ORDER BY e.created_at DESC
      LIMIT $${idx++} OFFSET $${idx++};
    `;
    params.push(Math.max(1, limit), Math.max(0, offset));

    const res = await dbClient.query(dataQuery, params);
    return { data: res.rows, total };
  },

  /**
   * Updates an execution's status and optional lifecycle timestamps.
   */
  async updateStatus(id, organization_id, status, extraFields = {}, client = null) {
    if (!organization_id) throw new Error('SoarExecution Error: organization_id is required');
    if (!id) throw new Error('SoarExecution Error: id is required');

    const cleanStatus = status.toLowerCase();
    const dbClient = client || db;
    const params = [id, organization_id, cleanStatus];
    const setClauses = ['status = $3'];
    let idx = 4;

    if (extraFields.started_at !== undefined) {
      setClauses.push(`started_at = $${idx++}`);
      params.push(extraFields.started_at);
    }
    if (extraFields.completed_at !== undefined) {
      setClauses.push(`completed_at = $${idx++}`);
      params.push(extraFields.completed_at);
    }
    if (extraFields.retry_count !== undefined) {
      setClauses.push(`retry_count = $${idx++}`);
      params.push(extraFields.retry_count);
    }
    if (extraFields.backoff_metadata !== undefined) {
      setClauses.push(`backoff_metadata = $${idx++}`);
      params.push(JSON.stringify(extraFields.backoff_metadata || {}));
    }

    const query = `
      UPDATE public.soar_executions
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Records a retry attempt and backoff metadata for an execution.
   */
  async recordRetry(id, organization_id, retryCount, backoffMetadata = {}, client = null) {
    return await this.updateStatus(id, organization_id, 'retrying', {
      retry_count: retryCount,
      backoff_metadata: backoffMetadata
    }, client);
  },

  /**
   * Creates an execution step record.
   */
  async createStepRecord({
    execution_id,
    playbook_step_id,
    status = 'pending',
    result_payload = {},
    retry_count = 0
  }, client = null) {
    if (!execution_id) throw new Error('SoarExecution Error: execution_id is required');
    if (!playbook_step_id) throw new Error('SoarExecution Error: playbook_step_id is required');

    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_execution_steps (
        execution_id,
        playbook_step_id,
        status,
        result_payload,
        retry_count
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      execution_id,
      playbook_step_id,
      (status || 'pending').toLowerCase(),
      JSON.stringify(result_payload || {}),
      retry_count
    ]);

    return res.rows[0];
  },

  /**
   * Bulk creates execution step records in a single query.
   */
  async createStepRecordsBatch(records = [], client = null) {
    if (!Array.isArray(records) || records.length === 0) return [];

    const dbClient = client || db;
    const valueClauses = [];
    const values = [];
    let paramIndex = 1;

    for (const rec of records) {
      if (!rec.execution_id || !rec.playbook_step_id) continue;
      valueClauses.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
      values.push(
        rec.execution_id,
        rec.playbook_step_id,
        (rec.status || 'pending').toLowerCase(),
        JSON.stringify(rec.result_payload || {}),
        rec.retry_count || 0
      );
    }

    if (valueClauses.length === 0) return [];

    const query = `
      INSERT INTO public.soar_execution_steps (
        execution_id,
        playbook_step_id,
        status,
        result_payload,
        retry_count
      )
      VALUES ${valueClauses.join(', ')}
      RETURNING *;
    `;

    const res = await dbClient.query(query, values);
    return res.rows;
  },

  /**
   * Updates an execution step record with completion status and result payload.
   */
  async updateStepRecord(id, {
    status,
    result_payload,
    retry_count,
    executed_at = new Date()
  }, client = null) {
    if (!id) throw new Error('SoarExecution Error: step record id is required');

    const dbClient = client || db;
    const params = [id, status.toLowerCase(), JSON.stringify(result_payload || {}), executed_at];
    let retryClause = '';
    if (typeof retry_count === 'number') {
      params.push(retry_count);
      retryClause = ', retry_count = $5';
    }

    const query = `
      UPDATE public.soar_execution_steps
      SET status = $2,
          result_payload = $3,
          executed_at = $4
          ${retryClause}
      WHERE id = $1
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Retrieves all execution steps for an execution, joined with playbook step info.
   */
  async getExecutionSteps(execution_id, client = null) {
    if (!execution_id) return [];

    const dbClient = client || db;
    const query = `
      SELECT 
        es.*,
        ps.step_order,
        ps.action_type,
        ps.action_config,
        ps.requires_approval,
        ps.retry_policy
      FROM public.soar_execution_steps es
      JOIN public.soar_playbook_steps ps ON es.playbook_step_id = ps.id
      WHERE es.execution_id = $1
      ORDER BY ps.step_order ASC, es.id ASC;
    `;

    const res = await dbClient.query(query, [execution_id]);
    return res.rows;
  },

  /**
   * Finds running or retrying executions that may need recovery.
   */
  async findStaleRunningExecutions(organization_id = null, client = null) {
    const dbClient = client || db;
    const params = [];
    let query = `
      SELECT e.*, p.name AS playbook_name
      FROM public.soar_executions e
      JOIN public.soar_playbooks p ON e.playbook_id = p.id
      WHERE e.status IN ('running', 'retrying')
    `;

    if (organization_id) {
      query += ` AND e.organization_id = $1`;
      params.push(organization_id);
    }

    query += ` ORDER BY e.created_at ASC;`;

    const res = await dbClient.query(query, params);
    return res.rows;
  }
};

module.exports = SoarExecution;
