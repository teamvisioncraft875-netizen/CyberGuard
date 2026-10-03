const db = require('../config/db');

/**
 * ResponsePolicy Model — Phase 1B Automated Response Layer.
 * Defines automated response rules configured by organization admins.
 */
const ResponsePolicy = {
  /**
   * Creates a response policy record.
   *
   * @param {Object} params
   * @param {string} params.organization_id
   * @param {string} params.name
   * @param {boolean} [params.enabled=true]
   * @param {string|null} [params.created_by_id=null]
   * @param {Array<Object>} params.rules
   * @param {import('pg').PoolClient} [client=null] - Optional transaction client
   * @returns {Promise<Object>} The inserted response policy record
   */
  async create({
    organization_id,
    name,
    enabled = true,
    created_by_id = null,
    rules = []
  }, client = null) {
    const dbClient = client || db;
    const text = `
      INSERT INTO public.response_policies (
        organization_id,
        name,
        enabled,
        created_by_id,
        rules,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
      RETURNING *;
    `;
    const res = await dbClient.query(text, [
      organization_id,
      name,
      enabled,
      created_by_id,
      typeof rules === 'string' ? rules : JSON.stringify(rules)
    ]);
    return res.rows[0];
  },

  /**
   * Finds a response policy by ID.
   *
   * @param {string} id
   * @returns {Promise<Object|null>}
   */
  async findById(id) {
    const text = 'SELECT * FROM public.response_policies WHERE id = $1;';
    const res = await db.query(text, [id]);
    return res.rows[0] || null;
  },

  /**
   * Finds all enabled response policies for an organization.
   *
   * @param {string} organization_id
   * @returns {Promise<Array<Object>>}
   */
  async findEnabledByOrg(organization_id) {
    if (!organization_id) return [];
    const text = `
      SELECT *
      FROM public.response_policies
      WHERE organization_id = $1 AND enabled = true
      ORDER BY created_at ASC;
    `;
    const res = await db.query(text, [organization_id]);
    return res.rows;
  },

  /**
   * Lists all response policies for an organization.
   *
   * @param {string} organization_id
   * @returns {Promise<Array<Object>>}
   */
  async listByOrg(organization_id) {
    if (!organization_id) return [];
    const text = `
      SELECT *
      FROM public.response_policies
      WHERE organization_id = $1
      ORDER BY created_at DESC;
    `;
    const res = await db.query(text, [organization_id]);
    return res.rows;
  }
};

module.exports = ResponsePolicy;
