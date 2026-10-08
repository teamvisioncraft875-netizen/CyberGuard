const db = require('../../config/db');
const SiemAlert = require('../../models/SiemAlert');
const SoarCase = require('../../models/SoarCase');
const ThreatIOC = require('../../models/ThreatIOC');
const { log: auditLog } = require('../auditService');

/**
 * Threat Intel Enrichment Pipeline — Automatically enriches alerts and cases with IOC intelligence,
 * reputation telemetry, historical detections, similar attacks, and threat actor profiles.
 */
const threatEnrichmentService = {
  /**
   * Automatically enriches a SIEM Alert with IOC intelligence, reputation, and related incidents
   */
  async enrichAlert(alertId, organizationId, client = null) {
    const dbClient = client || db;

    // 1. Fetch Alert
    const alertQuery = `SELECT * FROM public.siem_alerts WHERE id = $1 AND organization_id = $2;`;
    const { rows: alertRows } = await dbClient.query(alertQuery, [alertId, organizationId]);
    const alert = alertRows[0];
    if (!alert) {
      throw new Error(`Alert "${alertId}" not found for organization`);
    }

    const metadata = alert.metadata || {};

    // 2. Extract potential IOCs from alert fields & metadata
    const extractedIocs = [];
    if (metadata.source_ip) extractedIocs.push({ type: 'ip', value: metadata.source_ip });
    if (metadata.destination_ip) extractedIocs.push({ type: 'ip', value: metadata.destination_ip });
    if (metadata.ip) extractedIocs.push({ type: 'ip', value: metadata.ip });
    if (metadata.domain) extractedIocs.push({ type: 'domain', value: metadata.domain });
    if (metadata.file_hash) extractedIocs.push({ type: 'sha256', value: metadata.file_hash });
    if (metadata.hash) extractedIocs.push({ type: 'sha256', value: metadata.hash });

    // Also regex search in title and notes for IPs or hashes
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const titleIps = (alert.title || '').match(ipRegex) || [];
    for (const ip of titleIps) {
      if (!extractedIocs.find(i => i.value === ip)) {
        extractedIocs.push({ type: 'ip', value: ip });
      }
    }

    // 3. Match against ThreatIOC Master Store
    const matchedIocs = [];
    for (const item of extractedIocs) {
      const iocRecord = await ThreatIOC.findByValue(organizationId, item.value, dbClient);
      if (iocRecord) {
        matchedIocs.push(iocRecord);
      }
    }

    // 4. Calculate Aggregate Reputation & Threat Context
    let maxRiskScore = 0;
    const threatActors = new Set();
    const malwareFamilies = new Set();
    for (const ioc of matchedIocs) {
      if (ioc.risk_score > maxRiskScore) maxRiskScore = ioc.risk_score;
      if (ioc.threat_actor) threatActors.add(ioc.threat_actor);
      if (ioc.malware_family) malwareFamilies.add(ioc.malware_family);
    }

    const reputationData = {
      matched_iocs_count: matchedIocs.length,
      highest_risk_score: maxRiskScore,
      threat_actors: Array.from(threatActors),
      malware_families: Array.from(malwareFamilies),
      reputation_verdict: maxRiskScore >= 80 ? 'MALICIOUS' : (maxRiskScore >= 50 ? 'SUSPICIOUS' : 'BENIGN')
    };

    // 5. Correlate Related Incidents (other alerts with matching technique or similar severity)
    const mitre = alert.mitre_technique;
    let relatedAlerts = [];
    if (mitre) {
      const relQuery = `
        SELECT id, title, severity, status, created_at
        FROM public.siem_alerts
        WHERE organization_id = $1 AND mitre_technique = $2 AND id != $3
        ORDER BY created_at DESC
        LIMIT 5;
      `;
      const { rows } = await dbClient.query(relQuery, [organizationId, mitre, alertId]);
      relatedAlerts = rows;
    }

    // 6. Find Related Cases (cases referencing this alert)
    const caseQuery = `
      SELECT id, title, severity, status
      FROM public.soar_cases
      WHERE organization_id = $1 AND (alert_id = $2 OR incident_ids @> $3::jsonb)
      LIMIT 5;
    `;
    const { rows: relatedCases } = await dbClient.query(caseQuery, [
      organizationId,
      alertId,
      JSON.stringify([alertId])
    ]);

    // 7. Assemble Enrichment Payload
    const enrichmentPayload = {
      enriched_at: new Date().toISOString(),
      matched_iocs: matchedIocs.map(i => ({
        id: i.id,
        type: i.ioc_type,
        value: i.ioc_value,
        risk_score: i.risk_score,
        confidence: i.confidence,
        threat_actor: i.threat_actor
      })),
      reputation: reputationData,
      related_incidents: relatedAlerts,
      related_cases: relatedCases,
      previous_detections: matchedIocs.reduce((acc, i) => acc + (i.observation_count || 1), 0)
    };

    // 8. Persist Enrichment back into Alert Metadata
    const updatedMetadata = {
      ...metadata,
      enrichment: enrichmentPayload
    };
    await dbClient.query(
      `UPDATE public.siem_alerts SET metadata = $1, updated_at = NOW() WHERE id = $2 AND organization_id = $3;`,
      [JSON.stringify(updatedMetadata), alertId, organizationId]
    );

    await auditLog({
      organization_id: organizationId,
      action: 'SOAR_ALERT_ENRICHED',
      resource_type: 'siem_alert',
      resource_id: alertId,
      details: {
        matched_iocs_count: matchedIocs.length,
        verdict: reputationData.reputation_verdict
      }
    });

    return {
      alert_id: alertId,
      enrichment: enrichmentPayload
    };
  },

  /**
   * Automatically enriches a SOAR Case with IOC telemetry, similar attacks, attack chains, and actors
   */
  async enrichCase(caseId, organizationId, client = null) {
    const dbClient = client || db;

    // 1. Fetch Case
    const soarCase = await SoarCase.findById(caseId, organizationId, dbClient);
    if (!soarCase) {
      throw new Error(`Case "${caseId}" not found for organization`);
    }

    // 2. Fetch Linked IOCs
    const linkedIocIds = Array.isArray(soarCase.ioc_ids) ? soarCase.ioc_ids : [];
    let linkedIocs = [];
    if (linkedIocIds.length > 0) {
      const iocQuery = `
        SELECT * FROM public.threat_iocs
        WHERE organization_id = $1 AND id = ANY($2::uuid[]);
      `;
      const { rows } = await dbClient.query(iocQuery, [organizationId, linkedIocIds]);
      linkedIocs = rows;
    }

    // 3. Identify Threat Actors from Linked IOCs
    const actors = Array.from(new Set(linkedIocs.map(i => i.threat_actor).filter(Boolean)));
    const malwareFamilies = Array.from(new Set(linkedIocs.map(i => i.malware_family).filter(Boolean)));

    // 4. Find Similar Attacks (other cases in same organization with same severity or matching tags)
    const similarQuery = `
      SELECT id, title, severity, status, tags, created_at
      FROM public.soar_cases
      WHERE organization_id = $1 AND id != $2 AND severity = $3
      ORDER BY created_at DESC
      LIMIT 5;
    `;
    const { rows: similarCases } = await dbClient.query(similarQuery, [
      organizationId,
      caseId,
      soarCase.severity
    ]);

    // 5. Historical Attack Chains / Mitre Correlated Hits
    const chainQuery = `
      SELECT id, title, mitre_technique, severity, created_at
      FROM public.siem_alerts
      WHERE organization_id = $1 AND mitre_technique IS NOT NULL
      ORDER BY created_at DESC
      LIMIT 5;
    `;
    const { rows: historicalChains } = await dbClient.query(chainQuery, [organizationId]);

    // 6. Build Comprehensive Enrichment Findings
    const enrichmentFindings = {
      enriched_at: new Date().toISOString(),
      linked_iocs: linkedIocs.map(i => ({
        id: i.id,
        type: i.ioc_type,
        value: i.ioc_value,
        risk_score: i.risk_score,
        threat_actor: i.threat_actor
      })),
      threat_actors: actors.length > 0 ? actors : ['Undetermined Threat Group'],
      malware_families: malwareFamilies.length > 0 ? malwareFamilies : ['Unspecified Payload'],
      similar_attacks: similarCases,
      historical_attack_chains: historicalChains,
      risk_assessment: {
        criticality: soarCase.severity === 'critical' ? 'IMMEDIATE_ACTION' : 'ELEVATED',
        composite_score: linkedIocs.length > 0 ? Math.max(...linkedIocs.map(i => i.risk_score || 50)) : 60
      }
    };

    // 7. Update Case with findings
    await dbClient.query(
      `UPDATE public.soar_cases 
       SET threat_intel_findings = $1, updated_at = NOW() 
       WHERE id = $2 AND organization_id = $3;`,
      [JSON.stringify(enrichmentFindings), caseId, organizationId]
    );

    await auditLog({
      organization_id: organizationId,
      action: 'SOAR_CASE_ENRICHED',
      resource_type: 'soar_case',
      resource_id: caseId,
      details: {
        threat_actors: enrichmentFindings.threat_actors,
        linked_iocs_count: linkedIocs.length
      }
    });

    return {
      case_id: caseId,
      findings: enrichmentFindings
    };
  }
};

module.exports = threatEnrichmentService;
