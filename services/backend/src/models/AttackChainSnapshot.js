const db = require('../config/db');

/**
 * AttackChainSnapshot Model — CRUD operations on public.attack_chain_snapshots
 */
const AttackChainSnapshot = {
  /**
   * Creates an attack chain snapshot record.
   */
  async create({
    organization_id,
    root_incident_id,
    attack_chain_group_id = null,
    confidence_score = 0.800,
    chain_length = 1,
    timeline = [],
    metadata = {}
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.attack_chain_snapshots (
        organization_id,
        root_incident_id,
        attack_chain_group_id,
        confidence_score,
        chain_length,
        timeline,
        metadata,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(text, [
      organization_id,
      root_incident_id,
      attack_chain_group_id,
      confidence_score,
      chain_length,
      JSON.stringify(timeline || []),
      JSON.stringify(metadata || {})
    ]);

    return res.rows[0];
  },

  /**
   * Finds the latest attack chain snapshot for a root incident.
   */
  async findByIncident(incidentId, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT *
      FROM public.attack_chain_snapshots
      WHERE root_incident_id = $1
      ORDER BY updated_at DESC
      LIMIT 1;
    `;
    const res = await dbClient.query(text, [incidentId]);
    return res.rows[0] || null;
  },

  /**
   * Updates an attack chain snapshot by ID.
   */
  async update(id, updates = {}, client = null) {
    const dbClient = client || db;
    const allowed = ['attack_chain_group_id', 'confidence_score', 'chain_length', 'timeline', 'metadata'];
    const setClauses = [];
    const values = [];

    for (const [key, val] of Object.entries(updates)) {
      if (allowed.includes(key)) {
        if (key === 'timeline' || key === 'metadata') {
          values.push(JSON.stringify(val || (key === 'timeline' ? [] : {})));
        } else {
          values.push(val);
        }
        setClauses.push(`${key} = $${values.length}`);
      }
    }

    if (setClauses.length === 0) return this.findById(id, dbClient);

    setClauses.push(`updated_at = NOW()`);
    values.push(id);
    const idIdx = values.length;

    const text = `
      UPDATE public.attack_chain_snapshots
      SET ${setClauses.join(', ')}
      WHERE id = $${idIdx}
      RETURNING *;
    `;

    const res = await dbClient.query(text, values);
    return res.rows[0] || null;
  },

  /**
   * Finds snapshot by ID.
   */
  async findById(id, client = null) {
    const dbClient = client || db;
    const text = `SELECT * FROM public.attack_chain_snapshots WHERE id = $1;`;
    const res = await dbClient.query(text, [id]);
    return res.rows[0] || null;
  },

  /**
   * Deletes an attack chain snapshot by ID.
   */
  async delete(id, client = null) {
    const dbClient = client || db;
    const text = `DELETE FROM public.attack_chain_snapshots WHERE id = $1 RETURNING *;`;
    const res = await dbClient.query(text, [id]);
    return res.rows[0] || null;
  }
};

module.exports = AttackChainSnapshot;
