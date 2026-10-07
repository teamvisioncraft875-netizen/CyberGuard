const db = require('../../config/db');
const ThreatIOC = require('../../models/ThreatIOC');
const SoarCase = require('../../models/SoarCase');
const SoarResponseRecommendation = require('../../models/SoarResponseRecommendation');
const { log: auditLog } = require('../auditService');

/**
 * IOC Response Automation Service — Executes automated containment recommendations,
 * threat severity scoring, historical sighting analysis, and incident correlation.
 */
const iocResponseAutomationService = {
  /**
   * Automates response for Malicious IP IOC
   */
  async automateIpResponse({
    organization_id,
    ioc_value,
    case_id = null,
    alert_id = null,
    threat_actor = null,
    confidence = 85
  }, client = null) {
    const dbClient = client || db;

    // 1. Upsert / Fetch IOC in Threat Master Store
    const iocRecord = await ThreatIOC.upsertIOC({
      organization_id,
      ioc_type: 'ip',
      ioc_value: ioc_value.trim(),
      confidence,
      risk_score: Math.min(100, Math.max(30, confidence + 10)),
      threat_actor: threat_actor || 'Unknown APT',
      source_name: 'SOAR IOC Response Automation',
      tags: ['soar_automated', 'malicious_ip']
    }, dbClient);

    // 2. Track & Query Historical Sightings
    await ThreatIOC.recordSighting({
      organization_id,
      ioc_id: iocRecord.id,
      source_ip: ioc_value,
      metadata: { trigger: 'soar_ioc_automation', alert_id, case_id }
    }, dbClient);

    const sightingsRes = await ThreatIOC.getSightings({
      organization_id,
      ioc_id: iocRecord.id,
      limit: 20
    }, dbClient);
    const sightings = sightingsRes.data || [];
    const sightingsCount = typeof sightingsRes.total === 'number' ? sightingsRes.total : sightings.length;

    // 3. Compute Threat Severity Score
    let severityScore = iocRecord.risk_score || 75;
    if (sightingsCount > 3) severityScore = Math.min(100, severityScore + 15);
    if (threat_actor && threat_actor !== 'Unknown APT') severityScore = Math.min(100, severityScore + 10);

    const severityCategory = severityScore >= 80 ? 'critical' : (severityScore >= 60 ? 'high' : 'medium');

    // 4. Case Linkage: If case_id provided, attach IOC to case; else create or link
    let linkedCaseId = case_id;
    if (case_id) {
      await SoarCase.attachIOCs(case_id, organization_id, [iocRecord.id], dbClient).catch(() => {});
    }

    // 5. Automatic Firewall Block Recommendation
    const recommendation = await SoarResponseRecommendation.create({
      organization_id,
      alert_id,
      case_id: linkedCaseId,
      ioc_id: iocRecord.id,
      action_type: 'block_ip',
      recommended_action: `Block IP ${ioc_value} across perimeter firewalls`,
      action_payload: {
        ip: ioc_value,
        firewall_policy: 'drop',
        duration_hours: severityScore >= 90 ? 72 : 24
      },
      confidence_score: Math.min(99, Math.max(70, iocRecord.confidence || 85)),
      risk_score: severityScore,
      mitre_techniques: ['T1071.001', 'T1573'],
      rationale: `Automated analysis detected malicious IP with severity score ${severityScore}/100 and ${sightingsCount} historical sightings.`
    }, dbClient);

    await auditLog({
      organization_id,
      action: 'SOAR_IOC_AUTOMATION_TRIGGERED',
      resource_type: 'threat_ioc',
      resource_id: iocRecord.id,
      details: {
        ioc_type: 'ip',
        ioc_value,
        severity_score: severityScore,
        sightings_count: sightingsCount,
        recommendation_id: recommendation.id
      }
    });

    return {
      success: true,
      ioc_type: 'ip',
      ioc: iocRecord,
      severity_score: severityScore,
      severity_category: severityCategory,
      sightings_count: sightingsCount,
      sightings,
      case_id: linkedCaseId,
      recommendation
    };
  },

  /**
   * Automates response for Malicious Domain IOC
   */
  async automateDomainResponse({
    organization_id,
    ioc_value,
    case_id = null,
    alert_id = null,
    confidence = 80
  }, client = null) {
    const dbClient = client || db;

    // 1. Upsert / Fetch IOC in Threat Master Store
    const iocRecord = await ThreatIOC.upsertIOC({
      organization_id,
      ioc_type: 'domain',
      ioc_value: ioc_value.trim().toLowerCase(),
      confidence,
      risk_score: Math.min(100, confidence + 5),
      source_name: 'SOAR IOC Response Automation',
      tags: ['soar_automated', 'malicious_domain', 'c2_domain']
    }, dbClient);

    // 2. Domain Reputation Tracking
    const domainReputation = {
      domain: ioc_value,
      reputation_score: iocRecord.risk_score || 80,
      categories: ['Command and Control', 'Phishing Infrastructure'],
      first_resolved: iocRecord.first_seen,
      last_observed: new Date().toISOString(),
      threat_level: iocRecord.risk_score >= 80 ? 'HIGH_RISK' : 'SUSPICIOUS'
    };

    // 3. Related Incident Correlation (alerts matching domain in metadata or title)
    const correlatedIncidentsQuery = `
      SELECT id, title, severity, status, created_at
      FROM public.siem_alerts
      WHERE organization_id = $1
        AND (metadata::text ILIKE $2 OR title ILIKE $2)
      ORDER BY created_at DESC
      LIMIT 10;
    `;
    const { rows: relatedIncidents } = await dbClient.query(correlatedIncidentsQuery, [
      organization_id,
      `%${ioc_value}%`
    ]);

    // 4. DNS Sinkhole Recommendation
    const recommendation = await SoarResponseRecommendation.create({
      organization_id,
      alert_id,
      case_id,
      ioc_id: iocRecord.id,
      action_type: 'dns_sinkhole',
      recommended_action: `Reroute domain ${ioc_value} to internal DNS sinkhole`,
      action_payload: {
        domain: ioc_value,
        sinkhole_ip: '10.254.254.254',
        ttl_seconds: 300
      },
      confidence_score: Math.min(98, confidence || 85),
      risk_score: iocRecord.risk_score,
      mitre_techniques: ['T1071.004', 'T1566.002'],
      rationale: `Malicious C2 / Phishing domain identified with reputation score ${domainReputation.reputation_score} and ${relatedIncidents.length} related alerts.`
    }, dbClient);

    if (case_id) {
      await SoarCase.attachIOCs(case_id, organization_id, [iocRecord.id], dbClient).catch(() => {});
    }

    await auditLog({
      organization_id,
      action: 'SOAR_IOC_AUTOMATION_TRIGGERED',
      resource_type: 'threat_ioc',
      resource_id: iocRecord.id,
      details: {
        ioc_type: 'domain',
        ioc_value,
        reputation: domainReputation,
        related_incidents_count: relatedIncidents.length,
        recommendation_id: recommendation.id
      }
    });

    return {
      success: true,
      ioc_type: 'domain',
      ioc: iocRecord,
      reputation: domainReputation,
      related_incidents: relatedIncidents,
      recommendation
    };
  },

  /**
   * Automates response for Malicious Hash IOC
   */
  async automateHashResponse({
    organization_id,
    ioc_value,
    malware_family = 'LockBit',
    case_id = null,
    alert_id = null,
    confidence = 95
  }, client = null) {
    const dbClient = client || db;

    // 1. Upsert / Fetch IOC in Threat Master Store
    const iocRecord = await ThreatIOC.upsertIOC({
      organization_id,
      ioc_type: 'sha256',
      ioc_value: ioc_value.trim().toLowerCase(),
      confidence,
      risk_score: 95,
      malware_family,
      source_name: 'SOAR IOC Response Automation',
      tags: ['soar_automated', 'malicious_hash', malware_family.toLowerCase()]
    }, dbClient);

    // 2. Malware Family Tracking & Related IOC Clustering
    const clusterQuery = `
      SELECT id, ioc_type, ioc_value, malware_family, risk_score, first_seen
      FROM public.threat_iocs
      WHERE organization_id = $1
        AND (malware_family ILIKE $2 OR tags::text ILIKE $2)
        AND id != $3
      ORDER BY risk_score DESC
      LIMIT 10;
    `;
    const { rows: relatedCluster } = await dbClient.query(clusterQuery, [
      organization_id,
      `%${malware_family}%`,
      iocRecord.id
    ]);

    // 3. Endpoint Quarantine Recommendation
    const recommendation = await SoarResponseRecommendation.create({
      organization_id,
      alert_id,
      case_id,
      ioc_id: iocRecord.id,
      action_type: 'isolate_endpoint',
      recommended_action: `Isolate infected host and quarantine file hash ${ioc_value.substring(0, 16)}...`,
      action_payload: {
        file_hash: ioc_value,
        malware_family,
        quarantine_action: 'terminate_process_and_isolate'
      },
      confidence_score: 96.0,
      risk_score: 95,
      mitre_techniques: ['T1204.002', 'T1486'],
      rationale: `Critical file hash associated with ${malware_family} malware family identified. Clustered with ${relatedCluster.length} other known indicators.`
    }, dbClient);

    if (case_id) {
      await SoarCase.attachIOCs(case_id, organization_id, [iocRecord.id], dbClient).catch(() => {});
    }

    await auditLog({
      organization_id,
      action: 'SOAR_IOC_AUTOMATION_TRIGGERED',
      resource_type: 'threat_ioc',
      resource_id: iocRecord.id,
      details: {
        ioc_type: 'sha256',
        ioc_value,
        malware_family,
        cluster_size: relatedCluster.length,
        recommendation_id: recommendation.id
      }
    });

    return {
      success: true,
      ioc_type: 'sha256',
      ioc: iocRecord,
      malware_family,
      related_cluster: relatedCluster,
      recommendation
    };
  },

  /**
   * Unified dispatcher for IOC response automation
   */
  async automateResponse(params, client = null) {
    const { ioc_type } = params;
    const cleanType = (ioc_type || '').toLowerCase();

    if (cleanType === 'ip' || cleanType === 'ipv4' || cleanType === 'ipv6') {
      return await this.automateIpResponse(params, client);
    }
    if (cleanType === 'domain' || cleanType === 'hostname') {
      return await this.automateDomainResponse(params, client);
    }
    if (['sha256', 'sha1', 'md5', 'hash'].includes(cleanType)) {
      return await this.automateHashResponse(params, client);
    }

    throw new Error(`Unsupported IOC type for automation: "${ioc_type}". Supported: ip, domain, sha256/md5/sha1`);
  }
};

module.exports = iocResponseAutomationService;
