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

  /**
   * Retrieves messages for a session in chronological order.
   * Enforces tenant isolation by joining copilot_sessions when organization_id is supplied.
   */
  async findBySessionId(session_id, arg2 = 50, arg3 = null, client = null) {
    if (!session_id) return [];

    let limit = 50;
    let organization_id = null;
    let dbClient = client;

    if (typeof arg2 === 'number') {
      limit = arg2;
      if (typeof arg3 === 'string') organization_id = arg3;
      else if (arg3 && typeof arg3.query === 'function') dbClient = arg3;
    } else if (typeof arg2 === 'string') {
      organization_id = arg2;
      if (typeof arg3 === 'number') limit = arg3;
      else if (arg3 && typeof arg3.query === 'function') dbClient = arg3;
    } else if (arg2 && typeof arg2.query === 'function') {
      dbClient = arg2;
    }

    const effectiveClient = dbClient || db;
    let query;
    let params;

    if (organization_id) {
      query = `
        SELECT m.*
        FROM public.copilot_messages m
        JOIN public.copilot_sessions s ON m.session_id = s.id
        WHERE m.session_id = $1
          AND s.organization_id = $2
        ORDER BY m.timestamp ASC
        LIMIT $3;
      `;
      params = [session_id, organization_id, limit];
    } else {
      query = `
        SELECT m.*
        FROM public.copilot_messages m
        JOIN public.copilot_sessions s ON m.session_id = s.id
        WHERE m.session_id = $1
        ORDER BY m.timestamp ASC
        LIMIT $2;
      `;
      params = [session_id, limit];
    }

    const res = await effectiveClient.query(query, params);
    return res.rows;
  },

  /**
   * Retrieves the most recent messages for a session (ordered chronologically).
   * Enforces tenant isolation by joining copilot_sessions when organization_id is supplied.
   */
  async findRecent(session_id, arg2 = 10, arg3 = null, client = null) {
    if (!session_id) return [];

    let limit = 10;
    let organization_id = null;
    let dbClient = client;

    if (typeof arg2 === 'number') {
      limit = arg2;
      if (typeof arg3 === 'string') organization_id = arg3;
      else if (arg3 && typeof arg3.query === 'function') dbClient = arg3;
    } else if (typeof arg2 === 'string') {
      organization_id = arg2;
      if (typeof arg3 === 'number') limit = arg3;
      else if (arg3 && typeof arg3.query === 'function') dbClient = arg3;
    } else if (arg2 && typeof arg2.query === 'function') {
      dbClient = arg2;
    }

    const effectiveClient = dbClient || db;
    let query;
    let params;

    if (organization_id) {
      query = `
        SELECT *
        FROM (
          SELECT m.*
          FROM public.copilot_messages m
          JOIN public.copilot_sessions s ON m.session_id = s.id
          WHERE m.session_id = $1
            AND s.organization_id = $2
          ORDER BY m.timestamp DESC
          LIMIT $3
        ) sub
        ORDER BY timestamp ASC;
      `;
      params = [session_id, organization_id, limit];
    } else {
      query = `
        SELECT *
        FROM (
          SELECT m.*
          FROM public.copilot_messages m
          JOIN public.copilot_sessions s ON m.session_id = s.id
          WHERE m.session_id = $1
          ORDER BY m.timestamp DESC
          LIMIT $2
        ) sub
        ORDER BY timestamp ASC;
      `;
      params = [session_id, limit];
    }

    const res = await effectiveClient.query(query, params);
    return res.rows;
  }
};

module.exports = CopilotMessage;
