const db = require('../config/db');
const auditService = require('../services/auditService');

/**
 * SoarCaseEvidence Model — Immutable response evidence collection for security cases
 */
const SoarCaseEvidence = {
  VALID_EVIDENCE_TYPES: [
    'action_result',
    'remediation_output',
    'execution_log',
    'analyst_note',
    'ioc_match',
    'alert_snapshot',
    'network_trace',
    'edr_telemetry'
  ],

  /**
   * Records a new piece of evidence linked to a case.
   */
  async create({
    case_id,
    organization_id,
    evidence_type,
    data = {},
    execution_id = null,
    created_by = null
  }, client = null) {
    if (!case_id) throw new Error('SoarCaseEvidence Error: case_id is required');
    if (!organization_id) throw new Error('SoarCaseEvidence Error: organization_id is required');
    if (!evidence_type || typeof evidence_type !== 'string') {
      throw new Error('SoarCaseEvidence Error: evidence_type is required');
    }

    const cleanType = evidence_type.toLowerCase().trim();
    const dbClient = client || db;

    // Verify case exists in organization
    const caseCheck = await dbClient.query(
      'SELECT id FROM public.soar_cases WHERE id = $1 AND organization_id = $2;',
      [case_id, organization_id]
    );
    if (caseCheck.rows.length === 0) {
      throw new Error(`SoarCaseEvidence Error: Case "${case_id}" not found in organization`);
    }

    const query = `
      INSERT INTO public.soar_case_evidence (
        case_id,
        organization_id,
        evidence_type,
        data,
        execution_id,
        created_by,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      case_id,
      organization_id,
      cleanType,
      JSON.stringify(data || {}),
      execution_id,
      created_by
    ]);

    const createdEvidence = res.rows[0];

    await auditService.log({
      organization_id,
      actor_id: created_by,
      action: 'SOAR_EVIDENCE_ATTACHED',
      resource_type: 'soar_case_evidence',
      resource_id: createdEvidence.id,
      details: { case_id, evidence_type: cleanType, execution_id }
    }).catch(err => console.error('[SoarCaseEvidence] Audit log error:', err.message));

    return createdEvidence;
  },

  /**
   * Retrieves evidence items for a case with filtering and pagination.
   */
  async findByCaseId(case_id, organization_id, options = {}, client = null) {
    if (!case_id) throw new Error('SoarCaseEvidence Error: case_id is required');
    if (!organization_id) throw new Error('SoarCaseEvidence Error: organization_id is required');

    const dbClient = client || db;
    const params = [case_id, organization_id];
    let idx = 3;
    const whereClauses = ['e.case_id = $1', 'e.organization_id = $2'];

    if (options.evidence_type) {
      whereClauses.push(`e.evidence_type = $${idx++}`);
      params.push(options.evidence_type.toLowerCase().trim());
    }

    if (options.execution_id) {
      whereClauses.push(`e.execution_id = $${idx++}`);
      params.push(options.execution_id);
    }

    const whereStr = whereClauses.join(' AND ');

    const countRes = await dbClient.query(
      `SELECT COUNT(*)::int AS total FROM public.soar_case_evidence e WHERE ${whereStr};`,
      params
    );
    const total = countRes.rows[0]?.total || 0;

    const limit = Math.max(1, options.limit || 50);
    const offset = Math.max(0, options.offset || 0);

    const dataQuery = `
      SELECT 
        e.*,
        u.email AS created_by_email
      FROM public.soar_case_evidence e
      LEFT JOIN public.users u ON e.created_by = u.id
      WHERE ${whereStr}
      ORDER BY e.created_at DESC
      LIMIT $${idx++} OFFSET $${idx++};
    `;
    params.push(limit, offset);

    const res = await dbClient.query(dataQuery, params);
    return { data: res.rows, total };
  },

  /**
   * Retrieves a single evidence record by ID.
   */
  async findById(id, organization_id, client = null) {
    if (!id || !organization_id) throw new Error('SoarCaseEvidence Error: id and organization_id required');
    const dbClient = client || db;

    const res = await dbClient.query(
      `SELECT e.*, u.email AS created_by_email 
       FROM public.soar_case_evidence e 
       LEFT JOIN public.users u ON e.created_by = u.id 
       WHERE e.id = $1 AND e.organization_id = $2;`,
      [id, organization_id]
    );

    return res.rows[0] || null;
  }
};

module.exports = SoarCaseEvidence;
