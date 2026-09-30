const db = require('../config/db');

/**
 * GuardianLink Model — CRUD operations on the 'guardian_links' table
 */
const GuardianLink = {
  async create({ guardian_user_id, dependent_user_id, status = 'pending' }) {
    const text = `
      INSERT INTO guardian_links (guardian_user_id, dependent_user_id, status, created_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (guardian_user_id, dependent_user_id) DO UPDATE
      SET status = EXCLUDED.status
      RETURNING id as link_id, id, guardian_user_id, dependent_user_id, status, created_at;
    `;
    const res = await db.query(text, [guardian_user_id, dependent_user_id, status]);
    return res.rows[0];
  },

  async findById(id) {
    const text = `
      SELECT id as link_id, id, guardian_user_id, dependent_user_id, status, created_at
      FROM guardian_links
      WHERE id = $1;
    `;
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  async findByGuardianId(guardian_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.dependent_user_id,
             u.email as dependent_email, split_part(u.email, '@', 1) as dependent_name, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.dependent_user_id
      WHERE gl.guardian_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [guardian_user_id]);
    return res.rows;
  },

  async findByDependentId(dependent_user_id) {
    const text = `
      SELECT gl.id as link_id, gl.guardian_user_id, gl.dependent_user_id,
             u.email as guardian_email, split_part(u.email, '@', 1) as guardian_name, gl.status, gl.created_at
      FROM guardian_links gl
      JOIN users u ON u.id = gl.guardian_user_id
      WHERE gl.dependent_user_id = $1 AND gl.status = 'active';
    `;
    const res = await db.query(text, [dependent_user_id]);
    return res.rows;
  },

  async updateStatus(link_id, status) {
    const text = `
      UPDATE guardian_links
      SET status = $2
      WHERE id = $1
      RETURNING id as link_id, id, guardian_user_id, dependent_user_id, status, created_at;
    `;
    const res = await db.query(text, [link_id, status]);
    return res.rows[0] || null;
  },

  async listLinks({ userId, organizationId, isAdmin, status }) {
    let query = `
      SELECT gl.id,
             gl.id as link_id,
             gl.guardian_user_id,
             gl.dependent_user_id,
             gl.status,
             gl.created_at,
             ug.email AS guardian_email,
             ud.email AS dependent_email
      FROM guardian_links gl
      JOIN users ug ON ug.id = gl.guardian_user_id
      JOIN users ud ON ud.id = gl.dependent_user_id
    `;
    const params = [];
    const whereClauses = [];

    if (isAdmin && organizationId) {
      params.push(organizationId);
      whereClauses.push(`(ug.organization_id = $${params.length} OR ud.organization_id = $${params.length})`);
    } else {
      params.push(userId);
      whereClauses.push(`(gl.guardian_user_id = $${params.length} OR gl.dependent_user_id = $${params.length})`);
    }

    if (status) {
      if (status !== 'all') {
        params.push(status);
        whereClauses.push(`gl.status = $${params.length}`);
      }
    } else {
      // By default, exclude revoked links unless explicitly requested via ?status=revoked or ?status=all
      whereClauses.push(`gl.status != 'revoked'`);
    }

    query += ` WHERE ${whereClauses.join(' AND ')} ORDER BY gl.created_at DESC;`;

    const res = await db.query(query, params);
    return res.rows;
  }
};

module.exports = GuardianLink;
