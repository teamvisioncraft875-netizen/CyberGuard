const db = require('../config/db');

/**
 * SoarPlaybook Model — Tenant-scoped security automation playbooks & steps
 */
const SoarPlaybook = {
  VALID_TRIGGER_TYPES: ['alert', 'incident', 'manual', 'schedule'],

  /**
   * Creates a new Playbook with optional initial steps.
   */
  async create({
    organization_id,
    name,
    description = null,
    enabled = true,
    trigger_type = 'alert',
    trigger_conditions = {},
    created_by = null,
    steps = []
  }, client = null) {
    if (!organization_id) throw new Error('SoarPlaybook Error: organization_id is required');
    if (!name || typeof name !== 'string' || !name.trim()) {
      throw new Error('SoarPlaybook Error: name is required');
    }

    const cleanTriggerType = (trigger_type || 'alert').toLowerCase();
    const dbClient = client || db;

    const insertPlaybookQuery = `
      INSERT INTO public.soar_playbooks (
        organization_id,
        name,
        description,
        enabled,
        trigger_type,
        trigger_conditions,
        created_by,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(insertPlaybookQuery, [
      organization_id,
      name.trim(),
      description,
      Boolean(enabled),
      cleanTriggerType,
      JSON.stringify(trigger_conditions || {}),
      created_by || null
    ]);

    const playbook = res.rows[0];

    // If steps are provided, insert them sequentially
    playbook.steps = [];
    if (Array.isArray(steps) && steps.length > 0) {
      for (let i = 0; i < steps.length; i++) {
        const s = steps[i];
        const stepOrder = typeof s.step_order === 'number' ? s.step_order : i + 1;
        const insertedStep = await this.addStep(playbook.id, {
          step_order: stepOrder,
          action_type: s.action_type,
          action_config: s.action_config || {},
          requires_approval: Boolean(s.requires_approval)
        }, dbClient);
        playbook.steps.push(insertedStep);
      }
    }

    return playbook;
  },

  /**
   * Retrieves a single playbook by ID with its ordered steps.
   */
  async findById(id, organization_id, client = null) {
    if (!organization_id) throw new Error('SoarPlaybook Error: organization_id is required');
    if (!id) return null;

    const dbClient = client || db;
    const query = `
      SELECT *
      FROM public.soar_playbooks
      WHERE id = $1 AND organization_id = $2;
    `;
    const res = await dbClient.query(query, [id, organization_id]);
    if (res.rows.length === 0) return null;

    const playbook = res.rows[0];
    playbook.steps = await this.getSteps(id, dbClient);
    return playbook;
  },

  /**
   * Searches and filters playbooks within tenant boundary.
   */
  async findMany({
    organization_id,
    enabled,
    trigger_type,
    search,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('SoarPlaybook Error: organization_id is required');

    const dbClient = client || db;
    const params = [organization_id];
    let idx = 2;
    const whereClauses = ['organization_id = $1'];

    if (enabled !== undefined && enabled !== null) {
      whereClauses.push(`enabled = $${idx++}`);
      params.push(Boolean(enabled));
    }

    if (trigger_type) {
      whereClauses.push(`trigger_type = $${idx++}`);
      params.push(trigger_type.toLowerCase());
    }

    if (search && typeof search === 'string' && search.trim()) {
      whereClauses.push(`(name ILIKE $${idx} OR description ILIKE $${idx})`);
      params.push(`%${search.trim()}%`);
      idx++;
    }

    const whereStr = whereClauses.join(' AND ');

    const countQuery = `SELECT COUNT(*)::int AS total FROM public.soar_playbooks WHERE ${whereStr};`;
    const countRes = await dbClient.query(countQuery, params);
    const total = countRes.rows[0]?.total || 0;

    const dataQuery = `
      SELECT *
      FROM public.soar_playbooks
      WHERE ${whereStr}
      ORDER BY created_at DESC
      LIMIT $${idx++} OFFSET $${idx++};
    `;
    params.push(Math.max(1, limit), Math.max(0, offset));

    const res = await dbClient.query(dataQuery, params);
    const playbooks = res.rows;

    // Attach step counts or steps
    for (const pb of playbooks) {
      pb.steps = await this.getSteps(pb.id, dbClient);
    }

    return { data: playbooks, total };
  },

  /**
   * Updates an existing playbook's properties and optionally replaces steps.
   */
  async update(id, organization_id, updates = {}, client = null) {
    if (!organization_id) throw new Error('SoarPlaybook Error: organization_id is required');
    if (!id) throw new Error('SoarPlaybook Error: id is required');

    const dbClient = client || db;
    const allowedFields = ['name', 'description', 'enabled', 'trigger_type', 'trigger_conditions'];
    const setClauses = [];
    const params = [id, organization_id];
    let idx = 3;

    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        if (field === 'trigger_conditions') {
          setClauses.push(`trigger_conditions = $${idx++}`);
          params.push(JSON.stringify(updates[field]));
        } else if (field === 'enabled') {
          setClauses.push(`enabled = $${idx++}`);
          params.push(Boolean(updates[field]));
        } else if (field === 'trigger_type') {
          setClauses.push(`trigger_type = $${idx++}`);
          params.push(updates[field].toLowerCase());
        } else {
          setClauses.push(`${field} = $${idx++}`);
          params.push(updates[field]);
        }
      }
    }

    setClauses.push(`updated_at = NOW()`);

    const updateQuery = `
      UPDATE public.soar_playbooks
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(updateQuery, params);
    if (res.rows.length === 0) return null;

    const playbook = res.rows[0];

    // If new steps are supplied in update, replace existing steps
    if (Array.isArray(updates.steps)) {
      await dbClient.query('DELETE FROM public.soar_playbook_steps WHERE playbook_id = $1;', [id]);
      playbook.steps = [];
      for (let i = 0; i < updates.steps.length; i++) {
        const s = updates.steps[i];
        const stepOrder = typeof s.step_order === 'number' ? s.step_order : i + 1;
        const insertedStep = await this.addStep(playbook.id, {
          step_order: stepOrder,
          action_type: s.action_type,
          action_config: s.action_config || {},
          requires_approval: Boolean(s.requires_approval)
        }, dbClient);
        playbook.steps.push(insertedStep);
      }
    } else {
      playbook.steps = await this.getSteps(id, dbClient);
    }

    return playbook;
  },

  /**
   * Deletes a playbook and all dependent steps/executions via CASCADE.
   */
  async delete(id, organization_id, client = null) {
    if (!organization_id) throw new Error('SoarPlaybook Error: organization_id is required');
    if (!id) return false;

    const dbClient = client || db;
    const query = `
      DELETE FROM public.soar_playbooks
      WHERE id = $1 AND organization_id = $2
      RETURNING id;
    `;
    const res = await dbClient.query(query, [id, organization_id]);
    return res.rows.length > 0;
  },

  /**
   * Retrieves ordered steps for a playbook.
   */
  async getSteps(playbook_id, client = null) {
    if (!playbook_id) return [];
    const dbClient = client || db;
    const query = `
      SELECT *
      FROM public.soar_playbook_steps
      WHERE playbook_id = $1
      ORDER BY step_order ASC, created_at ASC;
    `;
    const res = await dbClient.query(query, [playbook_id]);
    return res.rows;
  },

  /**
   * Adds a single step to a playbook.
   */
  async addStep(playbook_id, {
    step_order,
    action_type,
    action_config = {},
    requires_approval = false
  }, client = null) {
    if (!playbook_id) throw new Error('SoarPlaybook Error: playbook_id is required');
    if (!action_type || typeof action_type !== 'string') {
      throw new Error('SoarPlaybook Error: action_type is required');
    }

    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_playbook_steps (
        playbook_id,
        step_order,
        action_type,
        action_config,
        requires_approval,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      playbook_id,
      typeof step_order === 'number' ? step_order : 1,
      action_type.trim(),
      JSON.stringify(action_config || {}),
      Boolean(requires_approval)
    ]);
    return res.rows[0];
  },

  /**
   * Finds all enabled playbooks matching an alert's attributes.
   */
  async findMatchingPlaybooks({ organization_id, trigger_type = 'alert', alert = {} }, client = null) {
    if (!organization_id) return [];
    const dbClient = client || db;

    const query = `
      SELECT *
      FROM public.soar_playbooks
      WHERE organization_id = $1 AND enabled = true AND trigger_type = $2
      ORDER BY created_at ASC;
    `;

    const res = await dbClient.query(query, [organization_id, trigger_type.toLowerCase()]);
    const playbooks = res.rows;
    const matched = [];

    for (const pb of playbooks) {
      const cond = pb.trigger_conditions || {};

      // Match severity if specified in conditions
      if (cond.severity) {
        const allowedSeverities = Array.isArray(cond.severity) ? cond.severity : [cond.severity];
        const alertSev = (alert.severity || '').toLowerCase();
        const matchesSev = allowedSeverities.some(s => String(s).toLowerCase() === alertSev);
        if (!matchesSev) continue;
      }

      // Match MITRE technique if specified in conditions
      if (cond.mitre_technique) {
        const allowedMitre = Array.isArray(cond.mitre_technique) ? cond.mitre_technique : [cond.mitre_technique];
        const alertMitre = alert.mitre_technique || alert.metadata?.mitre_technique;
        if (!allowedMitre.includes(alertMitre)) continue;
      }

      // Match rule_id / rule_code if specified
      if (cond.rule_code || cond.rule_id) {
        const target = cond.rule_code || cond.rule_id;
        const alertRule = alert.rule_code || alert.rule_id || alert.metadata?.rule_id;
        if (alertRule !== target) continue;
      }

      pb.steps = await this.getSteps(pb.id, dbClient);
      matched.push(pb);
    }

    return matched;
  }
};

module.exports = SoarPlaybook;
