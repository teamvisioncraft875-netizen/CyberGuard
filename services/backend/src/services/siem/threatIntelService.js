const db = require('../../config/db');
const ThreatIOC = require('../../models/ThreatIOC');

/**
 * Threat Intelligence Service — IOC extraction, high-speed matching,
 * automated enrichment, and dynamic risk scoring.
 */
class ThreatIntelService {
  /**
   * Calculates composite IOC risk score based on confidence, sightings, recency, and campaigns.
   * Formula: confidence + sightings_weight + recency_weight + campaign_weight (clamped 0-100)
   */
  calculateRiskScore({
    confidence = 50,
    sightingsCount = 0,
    lastSeen = null,
    campaignName = null,
    threatActor = null
  } = {}) {
    let score = parseInt(confidence, 10) || 50;

    // Sightings count weight (up to +20 points)
    const sightingsWeight = Math.min(20, (parseInt(sightingsCount, 10) || 0) * 2);
    score += sightingsWeight;

    // Recency weight (up to +15 points)
    if (lastSeen) {
      const hoursAgo = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 3600);
      if (hoursAgo <= 24) {
        score += 15;
      } else if (hoursAgo <= 168) { // 7 days
        score += 8;
      }
    }

    // Campaign & Threat Actor severity weight (up to +20 points)
    if (campaignName && campaignName.trim().length > 0) {
      score += 10;
    }
    if (threatActor && threatActor.trim().length > 0) {
      score += 10;
    }

    return Math.min(100, Math.max(0, Math.round(score)));
  }

  /**
   * Extracts observable indicators from a raw or normalized event
   */
  extractObservables(event) {
    if (!event) return [];
    const observables = new Map(); // value -> type

    const add = (val, type) => {
      if (val && typeof val === 'string' && val.trim().length > 0) {
        const clean = val.trim().toLowerCase();
        if (!observables.has(clean)) {
          observables.set(clean, type);
        }
      }
    };

    const normData = event.normalized_data || {};
    const norm = event.normalized_event || event.normalized || {};
    const raw = event.raw_event || event.raw || {};
    const details = normData.details || norm.details || event.details || {};

    // 1. IP Addresses
    const ips = [
      event.destination_ip, event.dest_ip, event.dst_ip,
      event.source_ip, event.src_ip, event.ip,
      norm.destination_ip, norm.dest_ip, norm.dst_ip,
      norm.source_ip, norm.src_ip, norm.ip,
      normData.dest_ip, normData.source_ip,
      details.destination_ip, details.dest_ip, details.dst_ip,
      details.source_ip, details.src_ip, details.IpAddress, details.SourceNetworkAddress, details.ip,
      raw.destination_ip, raw.dest_ip, raw.dst_ip,
      raw.source_ip, raw.src_ip, raw.ip, raw.IpAddress
    ];
    for (const ip of ips) {
      if (ip && typeof ip === 'string' && ip !== '-') add(ip, 'ip');
    }

    // 2. Domains & Hostnames
    const domains = [
      event.domain, event.hostname, event.destination_host, event.dest_host,
      norm.domain, norm.hostname, norm.destination_host, norm.dest_host,
      normData.target_host,
      details.domain, details.host, details.hostname, details.Computer, details.WorkstationName,
      raw.domain, raw.host, raw.hostname
    ];
    for (const dom of domains) {
      if (dom && typeof dom === 'string') add(dom, 'domain');
    }

    // 3. URLs
    const urls = [
      event.url, norm.url, normData.url, details.url, raw.url
    ];
    for (const u of urls) {
      if (u && typeof u === 'string') add(u, 'url');
    }

    // 4. File Hashes
    const hashes = [
      event.sha256, event.sha1, event.md5, event.file_hash, event.hash,
      norm.sha256, norm.sha1, norm.md5, norm.file_hash, norm.hash,
      normData.file_hash,
      details.sha256, details.sha1, details.md5, details.file_hash, details.hash, details.Hashes,
      raw.sha256, raw.sha1, raw.md5, raw.file_hash, raw.hash
    ];
    for (const h of hashes) {
      if (h && typeof h === 'string') {
        const clean = h.trim();
        if (clean.length === 64) add(clean, 'sha256');
        else if (clean.length === 40) add(clean, 'sha1');
        else if (clean.length === 32) add(clean, 'md5');
        else add(clean, 'sha256');
      }
    }

    // 5. Emails
    const emails = [
      event.email, norm.email, details.email, raw.email,
      event.user, norm.user, details.user, raw.user,
      normData.target_user
    ];
    for (const em of emails) {
      if (em && typeof em === 'string' && em.includes('@')) {
        add(em, 'email');
      }
    }

    return Array.from(observables.entries()).map(([value, type]) => ({ value, type }));
  }

  /**
   * Evaluates an event against the tenant's IOC database.
   * Target latency < 5 ms via composite index idx_threat_iocs_org_val_lower.
   */
  async matchEvent(event, organizationId, client = null) {
    if (!organizationId) return [];

    const observables = this.extractObservables(event);
    if (observables.length === 0) return [];

    const values = observables.map(o => o.value);
    const dbClient = client || db;

    const query = `
      SELECT
        id AS ioc_id,
        ioc_type,
        ioc_value,
        threat_actor,
        malware_family,
        campaign_name,
        confidence,
        risk_score
      FROM public.threat_iocs
      WHERE organization_id = $1
        AND (expiration_date IS NULL OR expiration_date > NOW())
        AND lower(ioc_value) = ANY($2::text[]);
    `;

    const res = await dbClient.query(query, [organizationId, values]);
    if (!res.rows || res.rows.length === 0) return [];

    // Map each hit into structured enrichment payload
    return res.rows.map(row => ({
      ioc_id: row.ioc_id,
      ioc_type: row.ioc_type,
      ioc_value: row.ioc_value,
      threat_actor: row.threat_actor,
      malware_family: row.malware_family,
      campaign_name: row.campaign_name,
      confidence: row.confidence,
      risk_score: row.risk_score
    }));
  }
}

// Singleton export
const threatIntelService = new ThreatIntelService();
module.exports = threatIntelService;
