const db = require('../config/db');
const { transaction } = require('../config/db');
const IncidentRelationship = require('../models/IncidentRelationship');
const { log: auditLog, AUDIT_ACTIONS } = require('./auditService');

/**
 * Normalizes a URL or domain string to extract the raw domain/hostname.
 * E.g. 'https://evil.com/phish' -> 'evil.com'
 *      'http://sub.attacker.org:8080/path' -> 'sub.attacker.org'
 *      'evil.com' -> 'evil.com'
 */
function extractDomain(val) {
  if (!val || typeof val !== 'string') return null;
  const trimmed = val.trim().toLowerCase();
  if (!trimmed) return null;

  try {
    const withProto = trimmed.startsWith('http://') || trimmed.startsWith('https://')
      ? trimmed
      : `http://${trimmed}`;
    const parsed = new URL(withProto);
    return parsed.hostname || null;
  } catch {
    const cleaned = trimmed
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .split(':')[0]
      .trim();
    return cleaned || null;
  }
}

/**
 * Links two incidents with a correlation relationship edge.
 * Enforces:
 *  1. No self references
 *  2. Duplicate edge prevention
 *  3. Strict tenant isolation
 *  4. DB transaction
 *  5. Audit logging
 */
async function linkIncidents(sourceIdOrObj, targetIdParam, typeParam, confidenceParam, metadataParam = {}, clientParam = null) {
  let sourceId;
  let targetId;
  let relationshipType;
  let confidenceScore;
  let metadata = {};
  let ruleId = null;
  let organizationId = null;
  let client = null;

  if (typeof sourceIdOrObj === 'object' && sourceIdOrObj !== null) {
    sourceId = sourceIdOrObj.sourceId || sourceIdOrObj.source_incident_id;
    targetId = sourceIdOrObj.targetId || sourceIdOrObj.target_incident_id;
    relationshipType = sourceIdOrObj.type || sourceIdOrObj.relationship_type;
    confidenceScore = sourceIdOrObj.confidence || sourceIdOrObj.confidence_score;
    metadata = sourceIdOrObj.metadata || {};
    ruleId = sourceIdOrObj.ruleId || sourceIdOrObj.rule_id || null;
    organizationId = sourceIdOrObj.organizationId || sourceIdOrObj.organization_id || null;
    client = sourceIdOrObj.client || null;
  } else {
    sourceId = sourceIdOrObj;
    targetId = targetIdParam;
    relationshipType = typeParam;
    confidenceScore = confidenceParam;
    metadata = metadataParam || {};
    client = clientParam;
  }

  // 1. Prevent self references
  if (!sourceId || !targetId || sourceId === targetId) {
    return null;
  }

  // Work function executing inside transaction
  const executeLink = async (dbClient) => {
    // 2. Tenant isolation verification
    const incRes = await dbClient.query(
      `SELECT id, organization_id FROM public.incidents WHERE id IN ($1, $2);`,
      [sourceId, targetId]
    );

    if (incRes.rows.length !== 2) {
      throw new Error(`Tenant isolation / incident lookup failed: one or both incidents do not exist (${sourceId}, ${targetId})`);
    }

    const orgSource = incRes.rows.find(r => r.id === sourceId)?.organization_id;
    const orgTarget = incRes.rows.find(r => r.id === targetId)?.organization_id;

    if (!orgSource || !orgTarget || orgSource !== orgTarget) {
      throw new Error(`Tenant isolation violation: source (${orgSource}) and target (${orgTarget}) belong to different organizations`);
    }

    const resolvedOrgId = organizationId || orgSource;

    // 3. Duplicate edge check
    const alreadyExists = await IncidentRelationship.exists(sourceId, targetId, relationshipType, dbClient);
    if (alreadyExists) {
      return null;
    }

    // 4. Create relationship edge
    const created = await IncidentRelationship.create({
      organization_id: resolvedOrgId,
      source_incident_id: sourceId,
      target_incident_id: targetId,
      relationship_type: relationshipType,
      confidence_score: confidenceScore,
      rule_id: ruleId,
      metadata
    }, dbClient);

    if (!created) {
      return null;
    }

    // 5. Record audit logs
    await auditLog({
      organization_id: resolvedOrgId,
      actor_type: 'system_guard',
      action: AUDIT_ACTIONS.INCIDENT_RELATIONSHIP_CREATED || 'INCIDENT_RELATIONSHIP_CREATED',
      resource_type: 'incident_relationship',
      resource_id: created.id,
      details: {
        relationship_id: created.id,
        source_incident_id: sourceId,
        target_incident_id: targetId,
        relationship_type: relationshipType,
        confidence_score: confidenceScore,
        rule_id: ruleId
      }
    }, dbClient);

    await auditLog({
      organization_id: resolvedOrgId,
      actor_type: 'system_guard',
      action: AUDIT_ACTIONS.INCIDENT_CORRELATED || 'INCIDENT_CORRELATED',
      resource_type: 'incident',
      resource_id: sourceId,
      details: {
        incident_id: sourceId,
        correlated_with: targetId,
        relationship_type: relationshipType,
        confidence_score: confidenceScore,
        rule_id: ruleId
      }
    }, dbClient);

    return created;
  };

  if (client) {
    return executeLink(client);
  } else {
    return transaction(executeLink);
  }
}

/**
 * Core Incident Correlation Engine
 * Evaluates rules R1 through R5 against recent incidents in the same organization.
 */
async function correlateIncident(incidentId, organizationId, client = null) {
  const dbClient = client || db;

  // 1. Load current incident
  const currentIncRes = await dbClient.query(
    `SELECT id, organization_id, user_id, threat_type, device_id, status, created_at
     FROM public.incidents
     WHERE id = $1 AND organization_id = $2;`,
    [incidentId, organizationId]
  );

  const currentIncident = currentIncRes.rows[0];
  if (!currentIncident) {
    return [];
  }

  // 2. Load candidate incidents from SAME organization
  // Window: last 24 hours, excluding current incident and resolved incidents, max 100
  const candidateRes = await dbClient.query(
    `SELECT id, organization_id, user_id, threat_type, device_id, status, created_at
     FROM public.incidents
     WHERE organization_id = $1
       AND id != $2
       AND status != 'resolved'
       AND created_at >= NOW() - INTERVAL '24 hours'
     ORDER BY created_at DESC
     LIMIT 100;`,
    [organizationId, incidentId]
  );

  const candidates = candidateRes.rows;
  if (!candidates || candidates.length === 0) {
    return [];
  }

  const allIncidentIds = [currentIncident.id, ...candidates.map(c => c.id)];

  // 3. Pre-fetch detection signals
  const signalsRes = await dbClient.query(
    `SELECT incident_id, signal_name, signal_value
     FROM public.detection_signals
     WHERE incident_id = ANY($1::uuid[]);`,
    [allIncidentIds]
  );

  // Group signals by incident
  const signalsByInc = new Map();
  for (const sig of signalsRes.rows) {
    if (!signalsByInc.has(sig.incident_id)) {
      signalsByInc.set(sig.incident_id, []);
    }
    signalsByInc.get(sig.incident_id).push(sig);
  }

  // 4. Pre-fetch IOC matches
  const iocsRes = await dbClient.query(
    `SELECT incident_id, indicator_id
     FROM public.incident_ioc_matches
     WHERE incident_id = ANY($1::uuid[]);`,
    [allIncidentIds]
  );

  // Group IOC indicator IDs by incident
  const iocsByInc = new Map();
  for (const ioc of iocsRes.rows) {
    if (!iocsByInc.has(ioc.incident_id)) {
      iocsByInc.set(ioc.incident_id, new Set());
    }
    iocsByInc.get(ioc.incident_id).add(ioc.indicator_id);
  }

  const currentSignals = signalsByInc.get(currentIncident.id) || [];
  const currentIOCs = iocsByInc.get(currentIncident.id) || new Set();

  // Extract IPs and domains for current incident
  const currentIPs = new Set(
    currentSignals
      .filter(s => ['source_ip', 'ip_address'].includes(s.signal_name?.toLowerCase()) && s.signal_value)
      .map(s => s.signal_value.trim().toLowerCase())
  );

  const currentDomains = new Set(
    currentSignals
      .filter(s => ['domain', 'url'].includes(s.signal_name?.toLowerCase()) && s.signal_value)
      .map(s => extractDomain(s.signal_value))
      .filter(Boolean)
  );

  const currentTime = new Date(currentIncident.created_at).getTime();
  const createdRelationships = [];

  // 5. Evaluate deterministic rules against each candidate
  for (const candidate of candidates) {
    const candidateSignals = signalsByInc.get(candidate.id) || [];
    const candidateIOCs = iocsByInc.get(candidate.id) || new Set();
    const candidateTime = new Date(candidate.created_at).getTime();
    const timeDiffMs = Math.abs(currentTime - candidateTime);

    // ====================================================
    // RULE R1: Same IOC
    // Both incidents share same indicator_id inside incident_ioc_matches
    // ====================================================
    if (currentIOCs.size > 0 && candidateIOCs.size > 0) {
      const sharedIOCs = [...currentIOCs].filter(id => candidateIOCs.has(id));
      if (sharedIOCs.length > 0) {
        const edge = await linkIncidents({
          sourceId: currentIncident.id,
          targetId: candidate.id,
          type: 'shares_ioc',
          confidence: 0.95,
          ruleId: 'R1',
          organizationId,
          client: dbClient,
          metadata: {
            rule: 'R1',
            rule_name: 'Same IOC',
            shared_indicator_ids: sharedIOCs
          }
        });
        if (edge) createdRelationships.push(edge);
      }
    }

    // ====================================================
    // RULE R2: Same attacker IP
    // Same detection signal: signal_name IN ('source_ip', 'ip_address'), same signal_value
    // ====================================================
    if (currentIPs.size > 0) {
      const candidateIPs = new Set(
        candidateSignals
          .filter(s => ['source_ip', 'ip_address'].includes(s.signal_name?.toLowerCase()) && s.signal_value)
          .map(s => s.signal_value.trim().toLowerCase())
      );

      const sharedIPs = [...currentIPs].filter(ip => candidateIPs.has(ip));
      if (sharedIPs.length > 0) {
        const edge = await linkIncidents({
          sourceId: currentIncident.id,
          targetId: candidate.id,
          type: 'same_attacker_ip',
          confidence: 0.85,
          ruleId: 'R2',
          organizationId,
          client: dbClient,
          metadata: {
            rule: 'R2',
            rule_name: 'Same attacker IP',
            shared_ips: sharedIPs
          }
        });
        if (edge) createdRelationships.push(edge);
      }
    }

    // ====================================================
    // RULE R3: Same host progression
    // same device_id, different threat_type, within 2 hours
    // ====================================================
    if (
      currentIncident.device_id &&
      candidate.device_id &&
      currentIncident.device_id === candidate.device_id &&
      currentIncident.threat_type !== candidate.threat_type &&
      timeDiffMs <= 2 * 60 * 60 * 1000 // 2 hours
    ) {
      const edge = await linkIncidents({
        sourceId: currentIncident.id,
        targetId: candidate.id,
        type: 'same_host_progression',
        confidence: 0.90,
        ruleId: 'R3',
        organizationId,
        client: dbClient,
        metadata: {
          rule: 'R3',
          rule_name: 'Same host progression',
          device_id: currentIncident.device_id,
          source_threat: currentIncident.threat_type,
          target_threat: candidate.threat_type,
          time_difference_minutes: Math.round(timeDiffMs / 60000)
        }
      });
      if (edge) createdRelationships.push(edge);
    }

    // ====================================================
    // RULE R4: Same user campaign
    // same user_id, different threat_type, within 12 hours
    // ====================================================
    if (
      currentIncident.user_id &&
      candidate.user_id &&
      currentIncident.user_id === candidate.user_id &&
      currentIncident.threat_type !== candidate.threat_type &&
      timeDiffMs <= 12 * 60 * 60 * 1000 // 12 hours
    ) {
      const edge = await linkIncidents({
        sourceId: currentIncident.id,
        targetId: candidate.id,
        type: 'same_user_campaign',
        confidence: 0.80,
        ruleId: 'R4',
        organizationId,
        client: dbClient,
        metadata: {
          rule: 'R4',
          rule_name: 'Same user campaign',
          user_id: currentIncident.user_id,
          source_threat: currentIncident.threat_type,
          target_threat: candidate.threat_type,
          time_difference_minutes: Math.round(timeDiffMs / 60000)
        }
      });
      if (edge) createdRelationships.push(edge);
    }

    // ====================================================
    // RULE R5: Same infrastructure
    // same domain from detection_signals where signal_name IN ('domain', 'url')
    // ====================================================
    if (currentDomains.size > 0) {
      const candidateDomains = new Set(
        candidateSignals
          .filter(s => ['domain', 'url'].includes(s.signal_name?.toLowerCase()) && s.signal_value)
          .map(s => extractDomain(s.signal_value))
          .filter(Boolean)
      );

      const sharedDomains = [...currentDomains].filter(d => candidateDomains.has(d));
      if (sharedDomains.length > 0) {
        const edge = await linkIncidents({
          sourceId: currentIncident.id,
          targetId: candidate.id,
          type: 'same_infrastructure',
          confidence: 0.90,
          ruleId: 'R5',
          organizationId,
          client: dbClient,
          metadata: {
            rule: 'R5',
            rule_name: 'Same infrastructure',
            shared_domains: sharedDomains
          }
        });
        if (edge) createdRelationships.push(edge);
      }
    }
  }

  return createdRelationships;
}

module.exports = {
  correlateIncident,
  linkIncidents,
  extractDomain
};
