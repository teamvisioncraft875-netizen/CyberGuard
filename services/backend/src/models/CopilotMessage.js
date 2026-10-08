const db = require('../config/db');

/**
 * CopilotMessage Model — Manages conversation messages within an investigation session.
 */
const CopilotMessage = {
  async create({
    session_id,
    role,
    content,
    metadata = {}
  }, client = null) {
    if (!session_id) throw new Error('CopilotMessage Error: session_id is required');
    if (!role || !['user', 'assistant', 'system'].includes(role)) {
      throw new Error(`CopilotMessage Error: invalid role "${role}". Must be user, assistant, or system`);
    }
    if (!content) throw new Error('CopilotMessage Error: content is required');

    const dbClient = client || db;
    const query = `
      INSERT INTO public.copilot_messages (
        session_id, role, content, metadata, timestamp
      )
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(query, [
      session_id,
      role,
      content,
      JSON.stringify(metadata || {})
    ]);
    return res.rows[0];
  },

  async findBySessionId(session_id, limit = 50, client = null) {
    if (!session_id) return [];
    const dbClient = client || db;
    const query = `
      SELECT *
      FROM public.copilot_messages
      WHERE session_id = $1
      ORDER BY timestamp ASC
      LIMIT $2;
    `;
    const res = await dbClient.query(query, [session_id, limit]);
    return res.rows;
  },

  async findRecent(session_id, limit = 10, client = null) {
    if (!session_id) return [];
    const dbClient = client || db;
    const query = `
      SELECT *
      FROM (
        SELECT *
        FROM public.copilot_messages
        WHERE session_id = $1
        ORDER BY timestamp DESC
        LIMIT $2
      ) sub
      ORDER BY timestamp ASC;
    `;
    const res = await dbClient.query(query, [session_id, limit]);
    return res.rows;
  }
};

module.exports = CopilotMessage;
