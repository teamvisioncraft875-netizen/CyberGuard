const db = require('../config/db');
const auditService = require('../services/auditService');

/**
 * SoarCase Model — Tenant-isolated security incident and investigation case management
 */
const SoarCase = {
  VALID_STATUSES: ['open', 'investigating', 'contained', 'resolved', 'closed'],
  VALID_SEVERITIES: ['critical', 'high', 'medium', 'low'],
  VALID_PRIORITIES: ['critical', 'high', 'medium', 'low'],

  /**
   * Creates a new SOAR case.
   */
  async create({
    organization_id,
    title,
    description = '',
    severity = 'medium',
    status = 'open',
    priority = 'medium',
    assigned_to = null,
    created_by = null,
    alert_id = null,
    incident_ids = [],
    ioc_ids = [],
    threat_intel_findings = {},
    tags = []
  }, client = null) {
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');
    if (!title || typeof title !== 'string' || !title.trim()) {
      throw new Error('SoarCase Error: title is required');
    }

    const cleanSeverity = (severity || 'medium').toLowerCase();
    const cleanStatus = (status || 'open').toLowerCase();
    const cleanPriority = (priority || 'medium').toLowerCase();

    if (!this.VALID_STATUSES.includes(cleanStatus)) {
      throw new Error(`SoarCase Error: Invalid status "${status}". Allowed: ${this.VALID_STATUSES.join(', ')}`);
    }

    const dbClient = client || db;
    const query = `
      INSERT INTO public.soar_cases (
        organization_id,
        title,
        description,
        severity,
        status,
        priority,
        assigned_to,
        created_by,
        alert_id,
        incident_ids,
        ioc_ids,
        threat_intel_findings,
        tags,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      organization_id,
      title.trim(),
      description,
      cleanSeverity,
      cleanStatus,
      cleanPriority,
      assigned_to,
      created_by,
      alert_id,
      JSON.stringify(Array.isArray(incident_ids) ? incident_ids : [incident_ids]),
      JSON.stringify(Array.isArray(ioc_ids) ? ioc_ids : [ioc_ids]),
      JSON.stringify(threat_intel_findings || {}),
      JSON.stringify(Array.isArray(tags) ? tags : [tags])
    ]);

    const createdCase = res.rows[0];

    await auditService.log({
      organization_id,
      actor_id: created_by,
      action: 'SOAR_CASE_CREATED',
      resource_type: 'soar_case',
      resource_id: createdCase.id,
      details: { title: createdCase.title, severity: createdCase.severity, alert_id }
    }).catch(err => console.error('[SoarCase] Audit log error:', err.message));

    return createdCase;
  },

  /**
   * Creates a new case initialized from a SIEM alert.
   */
  async createFromAlert(alert_id, organization_id, options = {}, client = null) {
    if (!alert_id) throw new Error('SoarCase Error: alert_id is required');
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');

    const dbClient = client || db;
    const alertRes = await dbClient.query(
      'SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;',
      [alert_id, organization_id]
    );

    const alert = alertRes.rows[0];
    if (!alert) {
      throw new Error(`SoarCase Error: Alert "${alert_id}" not found in organization`);
    }

    const title = options.title || `Case: ${alert.title}`;
    const description = options.description || `Investigating SIEM alert ${alert.id} (${alert.rule_code || 'N/A'}) - Severity: ${alert.severity}`;
    const severity = options.severity || alert.severity || 'medium';
    const incidentIds = alert.incident_id ? [alert.incident_id] : (options.incident_ids || []);
    const threatIntel = alert.metadata?.threat_intel || options.threat_intel_findings || {};

    return await this.create({
      organization_id,
      title,
      description,
      severity,
      status: 'open',
      priority: options.priority || (severity === 'critical' ? 'critical' : 'high'),
      assigned_to: options.assigned_to || alert.assigned_analyst,
      created_by: options.created_by || null,
      alert_id: alert.id,
      incident_ids: incidentIds,
      ioc_ids: options.ioc_ids || [],
      threat_intel_findings: threatIntel,
      tags: options.tags || ['from_siem_alert']
    }, dbClient);
  },

  /**
   * Retrieves a case by ID scoped to organization.
   */
  async findById(id, organization_id, client = null) {
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');
    if (!id) return null;

    const dbClient = client || db;
    const query = `
      SELECT 
        c.*,
        u.email AS assigned_to_email,
        cb.email AS created_by_email,
        sa.title AS alert_title,
        sa.severity AS alert_severity
      FROM public.soar_cases c
      LEFT JOIN public.users u ON c.assigned_to = u.id
      LEFT JOIN public.users cb ON c.created_by = cb.id
      LEFT JOIN public.siem_alerts sa ON c.alert_id = sa.id
      WHERE c.id = $1 AND c.organization_id = $2;
    `;

    const res = await dbClient.query(query, [id, organization_id]);
    return res.rows[0] || null;
  },

  /**
   * Lists cases with filtering, search, and pagination.
   */
  async findMany({
    organization_id,
    status,
    severity,
    priority,
    assigned_to,
    search,
    limit = 50,
    offset = 0
  }, client = null) {
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');

    const dbClient = client || db;
    const params = [organization_id];
    let idx = 2;
    const whereClauses = ['c.organization_id = $1'];

    if (status) {
      whereClauses.push(`c.status = $${idx++}`);
      params.push(status.toLowerCase());
    }

    if (severity) {
      whereClauses.push(`c.severity = $${idx++}`);
      params.push(severity.toLowerCase());
    }

    if (priority) {
      whereClauses.push(`c.priority = $${idx++}`);
      params.push(priority.toLowerCase());
    }

    if (assigned_to) {
      whereClauses.push(`c.assigned_to = $${idx++}`);
      params.push(assigned_to);
    }

    if (search && typeof search === 'string' && search.trim()) {
      whereClauses.push(`(c.title ILIKE $${idx} OR c.description ILIKE $${idx})`);
      params.push(`%${search.trim()}%`);
      idx++;
    }

    const whereStr = whereClauses.join(' AND ');

    const countRes = await dbClient.query(
      `SELECT COUNT(*)::int AS total FROM public.soar_cases c WHERE ${whereStr};`,
      params
    );
    const total = countRes.rows[0]?.total || 0;

    const dataQuery = `
      SELECT 
        c.*,
        u.email AS assigned_to_email
      FROM public.soar_cases c
      LEFT JOIN public.users u ON c.assigned_to = u.id
      WHERE ${whereStr}
      ORDER BY c.created_at DESC
      LIMIT $${idx++} OFFSET $${idx++};
    `;
    params.push(Math.max(1, limit), Math.max(0, offset));

    const res = await dbClient.query(dataQuery, params);
    return { data: res.rows, total };
  },

  /**
   * Updates case attributes.
   */
  async update(id, organization_id, updates = {}, client = null) {
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');
    if (!id) throw new Error('SoarCase Error: id is required');

    const dbClient = client || db;
    const allowedFields = ['title', 'description', 'severity', 'priority', 'assigned_to', 'tags'];
    const setClauses = [];
    const params = [id, organization_id];
    let idx = 3;

    for (const [key, val] of Object.entries(updates)) {
      if (!allowedFields.includes(key)) continue;

      if (key === 'tags') {
        setClauses.push(`tags = $${idx++}`);
        params.push(JSON.stringify(Array.isArray(val) ? val : [val]));
      } else {
        setClauses.push(`${key} = $${idx++}`);
        params.push(val);
      }
    }

    if (setClauses.length === 0) {
      return await this.findById(id, organization_id, dbClient);
    }

    setClauses.push('updated_at = NOW()');
    const query = `
      UPDATE public.soar_cases
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    const updated = res.rows[0];

    if (updated) {
      await auditService.log({
        organization_id,
        actor_id: updates.actor_id || null,
        action: 'SOAR_CASE_UPDATED',
        resource_type: 'soar_case',
        resource_id: id,
        details: { updated_fields: Object.keys(updates) }
      }).catch(err => console.error('[SoarCase] Audit log error:', err.message));
    }

    return updated;
  },

  /**
   * Transitions case status with validation and closed_at timestamping.
   */
  async updateStatus(id, organization_id, status, details = {}, client = null) {
    if (!organization_id) throw new Error('SoarCase Error: organization_id is required');
    if (!id) throw new Error('SoarCase Error: id is required');

    const cleanStatus = (status || '').toLowerCase().trim();
    if (!this.VALID_STATUSES.includes(cleanStatus)) {
      throw new Error(`SoarCase Error: Invalid status "${status}". Allowed: ${this.VALID_STATUSES.join(', ')}`);
    }

    const dbClient = client || db;
    const isClosing = ['resolved', 'closed'].includes(cleanStatus);
    const closedClause = isClosing ? ', closed_at = NOW()' : (cleanStatus === 'open' ? ', closed_at = NULL' : '');

    const query = `
      UPDATE public.soar_cases
      SET status = $3, updated_at = NOW() ${closedClause}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, [id, organization_id, cleanStatus]);
    const updated = res.rows[0];
    if (!updated) return null;

    await auditService.log({
      organization_id,
      actor_id: details.actor_id || null,
      action: 'SOAR_CASE_STATUS_CHANGED',
      resource_type: 'soar_case',
      resource_id: id,
      details: { new_status: cleanStatus, reason: details.reason || null }
    }).catch(err => console.error('[SoarCase] Audit log error:', err.message));

    return updated;
  },

  /**
   * Attaches incidents to a case (without duplicates).
   */
  async attachIncidents(id, organization_id, incident_ids, client = null) {
    if (!id || !organization_id) throw new Error('SoarCase Error: id and organization_id required');
    const dbClient = client || db;

    const current = await this.findById(id, organization_id, dbClient);
    if (!current) throw new Error(`Case ${id} not found`);

    const existingIds = new Set(Array.isArray(current.incident_ids) ? current.incident_ids : []);
    const toAdd = Array.isArray(incident_ids) ? incident_ids : [incident_ids];
    for (const incId of toAdd) {
      if (incId) existingIds.add(incId);
    }

    const merged = Array.from(existingIds);
    const res = await dbClient.query(
      `UPDATE public.soar_cases SET incident_ids = $3, updated_at = NOW() WHERE id = $1 AND organization_id = $2 RETURNING *;`,
      [id, organization_id, JSON.stringify(merged)]
    );

    return res.rows[0];
  },

  /**
   * Attaches IOCs to a case (without duplicates).
   */
  async attachIOCs(id, organization_id, ioc_ids, client = null) {
    if (!id || !organization_id) throw new Error('SoarCase Error: id and organization_id required');
    const dbClient = client || db;

    const current = await this.findById(id, organization_id, dbClient);
    if (!current) throw new Error(`Case ${id} not found`);

    const existingIocs = new Set(Array.isArray(current.ioc_ids) ? current.ioc_ids : []);
    const toAdd = Array.isArray(ioc_ids) ? ioc_ids : [ioc_ids];
    for (const ioc of toAdd) {
      if (ioc) existingIocs.add(ioc);
    }

    const merged = Array.from(existingIocs);
    const res = await dbClient.query(
      `UPDATE public.soar_cases SET ioc_ids = $3, updated_at = NOW() WHERE id = $1 AND organization_id = $2 RETURNING *;`,
      [id, organization_id, JSON.stringify(merged)]
    );

    return res.rows[0];
  },

  /**
   * Attaches or updates threat intel findings.
   */
  async attachThreatIntelFindings(id, organization_id, findings = {}, client = null) {
    if (!id || !organization_id) throw new Error('SoarCase Error: id and organization_id required');
    const dbClient = client || db;

    const current = await this.findById(id, organization_id, dbClient);
    if (!current) throw new Error(`Case ${id} not found`);

    const merged = { ...(current.threat_intel_findings || {}), ...findings };
    const res = await dbClient.query(
      `UPDATE public.soar_cases SET threat_intel_findings = $3, updated_at = NOW() WHERE id = $1 AND organization_id = $2 RETURNING *;`,
      [id, organization_id, JSON.stringify(merged)]
    );

    return res.rows[0];
  },

  /**
   * Deletes a case.
   */
  async delete(id, organization_id, client = null) {
    if (!id || !organization_id) throw new Error('SoarCase Error: id and organization_id required');
    const dbClient = client || db;
    const res = await dbClient.query(
      'DELETE FROM public.soar_cases WHERE id = $1 AND organization_id = $2 RETURNING id;',
      [id, organization_id]
    );
    return res.rowCount > 0;
  }
};

module.exports = SoarCase;
