const db = require('../config/db');

/**
 * SoarKnowledgeBase Model — Repository for enterprise security response procedures,
 * investigation notes, lessons learned, and MITRE mappings.
 */
class SoarKnowledgeBase {
  static async create({
    organization_id,
    title,
    summary = null,
    procedures = [],
    investigation_notes = null,
    resolution_summary = null,
    lessons_learned = null,
    mitre_mappings = [],
    tags = [],
    linked_case_ids = [],
    linked_playbook_ids = [],
    created_by = null
  }, client = null) {
    const dbClient = client || db;

    if (!organization_id) throw new Error('SoarKnowledgeBase.create requires organization_id');
    if (!title || typeof title !== 'string' || !title.trim()) {
      throw new Error('SoarKnowledgeBase.create requires non-empty title');
    }

    const query = `
      INSERT INTO public.soar_knowledge_base (
        organization_id, title, summary, procedures,
        investigation_notes, resolution_summary, lessons_learned,
        mitre_mappings, tags, linked_case_ids, linked_playbook_ids,
        created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `;
    const values = [
      organization_id,
      title.trim(),
      summary,
      JSON.stringify(procedures || []),
      investigation_notes,
      resolution_summary,
      lessons_learned,
      JSON.stringify(mitre_mappings || []),
      JSON.stringify(tags || []),
      JSON.stringify(linked_case_ids || []),
      JSON.stringify(linked_playbook_ids || []),
      created_by
    ];

    const { rows } = await dbClient.query(query, values);
    return rows[0];
  }

  static async findById(id, organization_id, client = null) {
    const dbClient = client || db;
    let query = 'SELECT * FROM public.soar_knowledge_base WHERE id = $1';
    const params = [id];

    if (organization_id) {
      query += ' AND organization_id = $2';
      params.push(organization_id);
    }

    const { rows } = await dbClient.query(query, params);
    return rows[0] || null;
  }

  static async findMany(filters = {}, client = null) {
    const dbClient = client || db;
    const {
      organization_id,
      search,
      tag,
      mitre,
      case_id,
      playbook_id,
      limit = 50,
      offset = 0
    } = filters;

    let query = 'SELECT * FROM public.soar_knowledge_base WHERE 1=1';
    const params = [];
    let pIdx = 1;

    if (organization_id) {
      query += ` AND organization_id = $${pIdx++}`;
      params.push(organization_id);
    }

    if (search) {
      query += ` AND (title ILIKE $${pIdx} OR summary ILIKE $${pIdx} OR investigation_notes ILIKE $${pIdx} OR resolution_summary ILIKE $${pIdx})`;
      params.push(`%${search}%`);
      pIdx++;
    }

    if (tag) {
      query += ` AND tags @> $${pIdx++}::jsonb`;
      params.push(JSON.stringify([tag]));
    }

    if (mitre) {
      query += ` AND mitre_mappings @> $${pIdx++}::jsonb`;
      params.push(JSON.stringify([mitre]));
    }

    if (case_id) {
      query += ` AND linked_case_ids @> $${pIdx++}::jsonb`;
      params.push(JSON.stringify([case_id]));
    }

    if (playbook_id) {
      query += ` AND linked_playbook_ids @> $${pIdx++}::jsonb`;
      params.push(JSON.stringify([playbook_id]));
    }

    query += ' ORDER BY created_at DESC';

    if (limit) {
      query += ` LIMIT $${pIdx++}`;
      params.push(limit);
    }
    if (offset) {
      query += ` OFFSET $${pIdx++}`;
      params.push(offset);
    }

    const { rows } = await dbClient.query(query, params);
    return rows;
  }

  static async update(id, organization_id, updates = {}, client = null) {
    const dbClient = client || db;
    const allowed = [
      'title', 'summary', 'procedures', 'investigation_notes',
      'resolution_summary', 'lessons_learned', 'mitre_mappings',
      'tags', 'linked_case_ids', 'linked_playbook_ids'
    ];

    const sets = [];
    const params = [id, organization_id];
    let pIdx = 3;

    for (const key of allowed) {
      if (updates[key] !== undefined) {
        if (['procedures', 'mitre_mappings', 'tags', 'linked_case_ids', 'linked_playbook_ids'].includes(key)) {
          sets.push(`${key} = $${pIdx++}`);
          params.push(JSON.stringify(updates[key]));
        } else {
          sets.push(`${key} = $${pIdx++}`);
          params.push(updates[key]);
        }
      }
    }

    if (sets.length === 0) {
      return await this.findById(id, organization_id, dbClient);
    }

    const query = `
      UPDATE public.soar_knowledge_base
      SET ${sets.join(', ')}, updated_at = NOW()
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const { rows } = await dbClient.query(query, params);
    return rows[0] || null;
  }

  static async delete(id, organization_id, client = null) {
    const dbClient = client || db;
    const query = `
      DELETE FROM public.soar_knowledge_base
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;
    const { rows } = await dbClient.query(query, [id, organization_id]);
    return rows[0] || null;
  }

  static async linkCase(id, organization_id, caseId, client = null) {
    const record = await this.findById(id, organization_id, client);
    if (!record) return null;
    const existing = Array.isArray(record.linked_case_ids) ? record.linked_case_ids : [];
    if (!existing.includes(caseId)) {
      existing.push(caseId);
      return await this.update(id, organization_id, { linked_case_ids: existing }, client);
    }
    return record;
  }

  static async unlinkCase(id, organization_id, caseId, client = null) {
    const record = await this.findById(id, organization_id, client);
    if (!record) return null;
    const existing = Array.isArray(record.linked_case_ids) ? record.linked_case_ids : [];
    const filtered = existing.filter(cid => cid !== caseId);
    return await this.update(id, organization_id, { linked_case_ids: filtered }, client);
  }

  static async linkPlaybook(id, organization_id, playbookId, client = null) {
    const record = await this.findById(id, organization_id, client);
    if (!record) return null;
    const existing = Array.isArray(record.linked_playbook_ids) ? record.linked_playbook_ids : [];
    if (!existing.includes(playbookId)) {
      existing.push(playbookId);
      return await this.update(id, organization_id, { linked_playbook_ids: existing }, client);
    }
    return record;
  }

  static async unlinkPlaybook(id, organization_id, playbookId, client = null) {
    const record = await this.findById(id, organization_id, client);
    if (!record) return null;
    const existing = Array.isArray(record.linked_playbook_ids) ? record.linked_playbook_ids : [];
    const filtered = existing.filter(pid => pid !== playbookId);
    return await this.update(id, organization_id, { linked_playbook_ids: filtered }, client);
  }
}

module.exports = SoarKnowledgeBase;
