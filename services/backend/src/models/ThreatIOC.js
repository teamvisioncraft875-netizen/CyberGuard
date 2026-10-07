const db = require('../config/db');

/**
 * ThreatIOC Model — Tenant-scoped Indicators of Compromise & Sighting management
 */
const ThreatIOC = {
  VALID_TYPES: ['ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'hostname'],

  /**
   * Creates a new Indicator of Compromise (IOC) record
   */
  async createIOC({
    organization_id,
    ioc_type,
    ioc_value,
    confidence = 50,
    risk_score = 50,
    threat_actor = null,
    malware_family = null,
    campaign_name = null,
    source_name = 'manual',
    expiration_date = null,
    tags = []
  }, client = null) {
    if (!organization_id) throw new Error('ThreatIOC Error: organization_id is required');
    if (!ioc_type || !this.VALID_TYPES.includes(ioc_type.toLowerCase())) {
      throw new Error(`ThreatIOC Error: Invalid ioc_type "${ioc_type}". Must be one of: ${this.VALID_TYPES.join(', ')}`);
    }
    if (!ioc_value || typeof ioc_value !== 'string') {
      throw new Error('ThreatIOC Error: ioc_value is required');
    }

    const dbClient = client || db;
    const cleanType = ioc_type.toLowerCase();
    const cleanValue = ioc_value.trim();

    const query = `
      INSERT INTO public.threat_iocs (
        organization_id,
        ioc_type,
        ioc_value,
        confidence,
        risk_score,
        threat_actor,
        malware_family,
        campaign_name,
        source_name,
        expiration_date,
        tags,
        first_seen,
        last_seen,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), NOW(), NOW())
      ON CONFLICT (organization_id, ioc_type, ioc_value)
      DO UPDATE SET
        confidence = EXCLUDED.confidence,
        risk_score = EXCLUDED.risk_score,
        threat_actor = COALESCE(EXCLUDED.threat_actor, public.threat_iocs.threat_actor),
        malware_family = COALESCE(EXCLUDED.malware_family, public.threat_iocs.malware_family),
        campaign_name = COALESCE(EXCLUDED.campaign_name, public.threat_iocs.campaign_name),
        source_name = COALESCE(EXCLUDED.source_name, public.threat_iocs.source_name),
        expiration_date = EXCLUDED.expiration_date,
        tags = EXCLUDED.tags,
        last_seen = NOW(),
        updated_at = NOW()
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      organization_id,
      cleanType,
      cleanValue,
      Math.min(100, Math.max(0, parseInt(confidence, 10) || 50)),
      Math.min(100, Math.max(0, parseInt(risk_score, 10) || 50)),
      threat_actor,
      malware_family,
      campaign_name,
      source_name,
      expiration_date ? new Date(expiration_date) : null,
      JSON.stringify(tags || [])
    ]);

    return res.rows[0];
  },

  /**
   * Retrieves an IOC by ID within tenant
   */
  async getIOC(id, organizationId, client = null) {
    const dbClient = client || db;
    const query = `
      SELECT *
      FROM public.threat_iocs
      WHERE id = $1 AND organization_id = $2;
    `;
    const res = await dbClient.query(query, [id, organizationId]);
    return res.rows[0] || null;
  },

  /**
   * Updates an existing IOC
   */
  async updateIOC(id, organizationId, fields = {}, client = null) {
    const dbClient = client || db;
    const setClauses = [];
    const params = [id, organizationId];

    if (fields.confidence !== undefined) {
      params.push(Math.min(100, Math.max(0, parseInt(fields.confidence, 10) || 0)));
      setClauses.push(`confidence = $${params.length}`);
    }

    if (fields.risk_score !== undefined) {
      params.push(Math.min(100, Math.max(0, parseInt(fields.risk_score, 10) || 0)));
      setClauses.push(`risk_score = $${params.length}`);
    }

    if (fields.threat_actor !== undefined) {
      params.push(fields.threat_actor);
      setClauses.push(`threat_actor = $${params.length}`);
    }

    if (fields.malware_family !== undefined) {
      params.push(fields.malware_family);
      setClauses.push(`malware_family = $${params.length}`);
    }

    if (fields.campaign_name !== undefined) {
      params.push(fields.campaign_name);
      setClauses.push(`campaign_name = $${params.length}`);
    }

    if (fields.expiration_date !== undefined) {
      params.push(fields.expiration_date ? new Date(fields.expiration_date) : null);
      setClauses.push(`expiration_date = $${params.length}`);
    }

    if (fields.tags !== undefined) {
      params.push(JSON.stringify(fields.tags || []));
      setClauses.push(`tags = $${params.length}`);
    }

    if (setClauses.length === 0) {
      return this.getIOC(id, organizationId, dbClient);
    }

    setClauses.push(`updated_at = NOW()`);

    const query = `
      UPDATE public.threat_iocs
      SET ${setClauses.join(', ')}
      WHERE id = $1 AND organization_id = $2
      RETURNING *;
    `;

    const res = await dbClient.query(query, params);
    return res.rows[0] || null;
  },

  /**
   * Deletes an IOC by ID
   */
  async deleteIOC(id, organizationId, client = null) {
    const dbClient = client || db;
    const query = `
      DELETE FROM public.threat_iocs
      WHERE id = $1 AND organization_id = $2
      RETURNING id;
    `;
    const res = await dbClient.query(query, [id, organizationId]);
    return res.rowCount > 0;
  },

  /**
   * Searches and filters IOCs with pagination
   */
  async searchIOCs({
    organization_id,
    ioc_type = null,
    q = null,
    min_risk = null,
    include_expired = false,
    limit = 50,
    offset = 0
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['organization_id = $1'];
    const params = [organization_id];

    if (ioc_type) {
      params.push(ioc_type.toLowerCase());
      conditions.push(`ioc_type = $${params.length}`);
    }

    if (q) {
      params.push(`%${q.toLowerCase()}%`);
      const qIdx = params.length;
      conditions.push(`(lower(ioc_value) LIKE $${qIdx} OR lower(COALESCE(threat_actor, '')) LIKE $${qIdx} OR lower(COALESCE(malware_family, '')) LIKE $${qIdx})`);
    }

    if (min_risk !== null && min_risk !== undefined) {
      params.push(parseInt(min_risk, 10));
      conditions.push(`risk_score >= $${params.length}`);
    }

    if (!include_expired) {
      conditions.push(`(expiration_date IS NULL OR expiration_date > NOW())`);
    }

    params.push(parseInt(limit, 10) || 50);
    const limitIdx = params.length;

    params.push(parseInt(offset, 10) || 0);
    const offsetIdx = params.length;

    const query = `
      SELECT *, COUNT(*) OVER() AS total_count
      FROM public.threat_iocs
      WHERE ${conditions.join(' AND ')}
      ORDER BY risk_score DESC, updated_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;

    const res = await dbClient.query(query, params);
    const total = res.rows.length > 0 ? parseInt(res.rows[0].total_count, 10) : 0;
    return {
      data: res.rows.map(r => {
        const { total_count, ...ioc } = r;
        return ioc;
      }),
      total
    };
  },

  /**
   * Records a sighting of an IOC match
   */
  async recordSighting({
    organization_id,
    ioc_id,
    event_id = null,
    detection_id = null,
    source_ip = null,
    destination_ip = null,
    user_name = null,
    asset_name = null,
    metadata = {}
  }, client = null) {
    const dbClient = client || db;

    const query = `
      INSERT INTO public.threat_ioc_sightings (
        organization_id,
        ioc_id,
        event_id,
        detection_id,
        matched_at,
        source_ip,
        destination_ip,
        user_name,
        asset_name,
        metadata
      )
      VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9)
      RETURNING *;
    `;

    const res = await dbClient.query(query, [
      organization_id,
      ioc_id,
      event_id,
      detection_id,
      source_ip,
      destination_ip,
      user_name,
      asset_name,
      JSON.stringify(metadata || {})
    ]);

    // Touch last_seen on IOC
    await dbClient.query(
      `UPDATE public.threat_iocs SET last_seen = NOW(), updated_at = NOW() WHERE id = $1;`,
      [ioc_id]
    );

    return res.rows[0];
  },

  /**
   * Retrieves sightings with filters and pagination
   */
  async getSightings({
    organization_id,
    ioc_id = null,
    startDate = null,
    endDate = null,
    limit = 50,
    offset = 0
  } = {}, client = null) {
    const dbClient = client || db;
    const conditions = ['s.organization_id = $1'];
    const params = [organization_id];

    if (ioc_id) {
      params.push(ioc_id);
      conditions.push(`s.ioc_id = $${params.length}`);
    }

    if (startDate) {
      params.push(new Date(startDate));
      conditions.push(`s.matched_at >= $${params.length}`);
    }

    if (endDate) {
      params.push(new Date(endDate));
      conditions.push(`s.matched_at <= $${params.length}`);
    }

    params.push(parseInt(limit, 10) || 50);
    const limitIdx = params.length;

    params.push(parseInt(offset, 10) || 0);
    const offsetIdx = params.length;

    const query = `
      SELECT
        s.*,
        i.ioc_type,
        i.ioc_value,
        i.threat_actor,
        i.malware_family,
        i.risk_score,
        COUNT(*) OVER() AS total_count
      FROM public.threat_ioc_sightings s
      JOIN public.threat_iocs i ON s.ioc_id = i.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY s.matched_at DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx};
    `;

    const res = await dbClient.query(query, params);
    const total = res.rows.length > 0 ? parseInt(res.rows[0].total_count, 10) : 0;
    return {
      data: res.rows.map(r => {
        const { total_count, ...sighting } = r;
        return sighting;
      }),
      total
    };
  },

  /**
   * Retrieves threat intelligence dashboard statistics
   */
  async getIOCStatistics(organizationId, client = null) {
    const dbClient = client || db;

    const query = `
      SELECT
        COUNT(*)::int AS total_iocs,
        COUNT(CASE WHEN expiration_date IS NULL OR expiration_date > NOW() THEN 1 END)::int AS active_iocs,
        COUNT(CASE WHEN expiration_date <= NOW() THEN 1 END)::int AS expired_iocs,
        COUNT(CASE WHEN risk_score >= 70 THEN 1 END)::int AS high_risk_iocs
      FROM public.threat_iocs
      WHERE organization_id = $1;
    `;
    const statsRes = await dbClient.query(query, [organizationId]);
    const counts = statsRes.rows[0] || {};

    const sightingsTodayRes = await dbClient.query(`
      SELECT COUNT(*)::int AS sightings_today
      FROM public.threat_ioc_sightings
      WHERE organization_id = $1 AND matched_at >= NOW() - INTERVAL '24 hours';
    `, [organizationId]);

    const topActorsRes = await dbClient.query(`
      SELECT threat_actor, COUNT(*)::int AS count
      FROM public.threat_iocs
      WHERE organization_id = $1 AND threat_actor IS NOT NULL
      GROUP BY threat_actor
      ORDER BY count DESC
      LIMIT 5;
    `, [organizationId]);

    const topMalwareRes = await dbClient.query(`
      SELECT malware_family, COUNT(*)::int AS count
      FROM public.threat_iocs
      WHERE organization_id = $1 AND malware_family IS NOT NULL
      GROUP BY malware_family
      ORDER BY count DESC
      LIMIT 5;
    `, [organizationId]);

    const topCampaignsRes = await dbClient.query(`
      SELECT campaign_name, COUNT(*)::int AS count
      FROM public.threat_iocs
      WHERE organization_id = $1 AND campaign_name IS NOT NULL
      GROUP BY campaign_name
      ORDER BY count DESC
      LIMIT 5;
    `, [organizationId]);

    return {
      total_iocs: counts.total_iocs || 0,
      active_iocs: counts.active_iocs || 0,
      expired_iocs: counts.expired_iocs || 0,
      high_risk_iocs: counts.high_risk_iocs || 0,
      sightings_today: sightingsTodayRes.rows[0]?.sightings_today || 0,
      top_threat_actors: topActorsRes.rows,
      top_malware_families: topMalwareRes.rows,
      top_campaigns: topCampaignsRes.rows
    };
  }
};

module.exports = ThreatIOC;
