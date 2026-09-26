const db = require('../config/db');

/**
 * RecommendedAction Model — CRUD operations on the 'recommended_actions' table
 */
const RecommendedAction = {
  async create({ incident_id, action_type, action_text, action_status = 'pending', execution_status }, client = null) {
    const dbClient = client || db;
    const resolvedActionType = action_type || action_text;
    const resolvedStatus = (action_status || execution_status || 'pending').toLowerCase();

    const text = `
      INSERT INTO recommended_actions (incident_id, action_type, action_status, created_at)
      VALUES ($1, $2, $3::action_status, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [incident_id, resolvedActionType, resolvedStatus]);
    return res.rows[0];
  },

  async createMany(actions = [], client = null) {
    if (!actions || actions.length === 0) return [];
    const dbClient = client || db;
    const inserted = [];
    for (const action of actions) {
      const payload = typeof action === 'string'
        ? { action_type: action, action_status: 'pending' }
        : action;
      const res = await RecommendedAction.create(payload, dbClient);
      inserted.push(res);
    }
    return inserted;
  },

  async findByIncidentId(incident_id) {
    const text = `
      SELECT * FROM recommended_actions
      WHERE incident_id = $1
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [incident_id]);
    return res.rows;
  },

  async findByIncidentIds(incident_ids) {
    if (!incident_ids || incident_ids.length === 0) return [];
    const text = `
      SELECT * FROM recommended_actions
      WHERE incident_id = ANY($1::uuid[])
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [incident_ids]);
    return res.rows;
  },

  async updateStatus(id, action_status) {
    const text = `
      UPDATE recommended_actions
      SET action_status = $2::action_status
      WHERE id = $1
      RETURNING *;
    `;
    const res = await db.query(text, [id, action_status.toLowerCase()]);
    return res.rows[0] || null;
  }
};

module.exports = RecommendedAction;
