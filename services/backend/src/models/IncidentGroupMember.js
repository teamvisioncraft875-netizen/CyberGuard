const db = require('../config/db');

/**
 * IncidentGroupMember Model — Many-to-many relationship linking incidents into groups
 */
const IncidentGroupMember = {
  /**
   * Adds an incident to a group. Uses ON CONFLICT DO NOTHING to prevent duplicate memberships.
   */
  async add({
    group_id,
    incident_id,
    added_by = 'rule_engine',
    confidence = 1.000
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.incident_group_members (
        group_id,
        incident_id,
        added_by,
        confidence,
        joined_at
      )
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (group_id, incident_id)
      DO NOTHING
      RETURNING *;
    `;

    const res = await dbClient.query(text, [group_id, incident_id, added_by, confidence]);
    return res.rows[0] || null;
  },

  /**
   * Checks if an incident is already a member of a group.
   */
  async exists(group_id, incident_id, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT 1 FROM public.incident_group_members
      WHERE group_id = $1 AND incident_id = $2
      LIMIT 1;
    `;
    const res = await dbClient.query(text, [group_id, incident_id]);
    return res.rowCount > 0;
  },

  /**
   * Retrieves all member incidents of a group with basic incident details.
   */
  async findByGroup(group_id, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT
        m.id AS membership_id,
        m.group_id,
        m.incident_id,
        m.added_by,
        m.confidence::float AS confidence,
        m.joined_at,
        i.threat_type,
        i.source_type,
        i.risk_level,
        i.risk_score,
        i.status,
        i.explanation,
        i.created_at AS incident_created_at
      FROM public.incident_group_members m
      JOIN public.incidents i ON i.id = m.incident_id
      WHERE m.group_id = $1
      ORDER BY m.joined_at ASC;
    `;
    const res = await dbClient.query(text, [group_id]);
    return res.rows;
  },

  /**
   * Finds the group that an incident currently belongs to (returns the group record if open/active).
   */
  async findGroupByIncident(incident_id, client = null) {
    const dbClient = client || db;
    const text = `
      SELECT g.*
      FROM public.incident_groups g
      JOIN public.incident_group_members m ON m.group_id = g.id
      WHERE m.incident_id = $1
      ORDER BY (CASE WHEN g.status != 'resolved' THEN 0 ELSE 1 END), g.created_at DESC
      LIMIT 1;
    `;
    const res = await dbClient.query(text, [incident_id]);
    return res.rows[0] || null;
  },

  /**
   * Moves all memberships from one group to another, skipping existing mappings to avoid conflict.
   */
  async moveMembers(sourceGroupId, targetGroupId, client = null) {
    const dbClient = client || db;
    // 1. Insert missing members into targetGroup
    await dbClient.query(`
      INSERT INTO public.incident_group_members (group_id, incident_id, added_by, confidence, joined_at)
      SELECT $1, incident_id, added_by, confidence, joined_at
      FROM public.incident_group_members
      WHERE group_id = $2
      ON CONFLICT (group_id, incident_id) DO NOTHING;
    `, [targetGroupId, sourceGroupId]);

    // 2. Delete all members from sourceGroup
    const deleted = await dbClient.query(`
      DELETE FROM public.incident_group_members
      WHERE group_id = $1
      RETURNING incident_id;
    `, [sourceGroupId]);

    return deleted.rows.map(r => r.incident_id);
  }
};

module.exports = IncidentGroupMember;
