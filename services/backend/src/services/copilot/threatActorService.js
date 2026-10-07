const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * Curated Enterprise Threat Actor Knowledge Profiles
 */
const KNOWN_ACTORS = {
  'APT29': {
    actor: 'APT29 (Cozy Bear / Midnight Blizzard)',
    aliases: ['Cozy Bear', 'Nobelium', 'Midnight Blizzard'],
    category: 'Nation-State / APT',
    origin: 'Eastern Europe / Russia',
    tactics: ['Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Command and Control'],
    techniques: ['T1566', 'T1059', 'T1003', 'T1071.001', 'T1078'],
    malware_families: ['CobaltStrike', 'WellMess', 'EnvyScout'],
    campaigns: ['SolarStorm', 'Nobelium-SupplyChain', 'DiplomaticPhish'],
    base_confidence: 0.94
  },
  'APT28': {
    actor: 'APT28 (Fancy Bear / Forest Blizzard)',
    aliases: ['Fancy Bear', 'Strontium', 'Sednit'],
    category: 'Nation-State / APT',
    origin: 'Eastern Europe / Russia',
    tactics: ['Initial Access', 'Credential Access', 'Defense Evasion'],
    techniques: ['T1110', 'T1078', 'T1053', 'T1566'],
    malware_families: ['X-Agent', 'Sofacy', 'Zebrocy'],
    campaigns: ['ElectionTargeting', 'DNC-2016'],
    base_confidence: 0.92
  },
  'LOCKBIT': {
    actor: 'LockBit Ransomware Syndicate',
    aliases: ['LockBit 3.0', 'LockBit Black'],
    category: 'Ransomware-as-a-Service (RaaS)',
    tactics: ['Initial Access', 'Defense Evasion', 'Impact', 'Exfiltration'],
    techniques: ['T1486', 'T1078', 'T1003', 'T1059'],
    malware_families: ['LockBit 3.0', 'StealBit'],
    campaigns: ['DoubleExtortion-2023', 'GlobalRaaS-Wave'],
    base_confidence: 0.95
  },
  'BLACKCAT': {
    actor: 'BlackCat (ALPHV)',
    aliases: ['ALPHV', 'Noberus'],
    category: 'Ransomware-as-a-Service (RaaS)',
    tactics: ['Impact', 'Exfiltration', 'Privilege Escalation'],
    techniques: ['T1486', 'T1059', 'T1021'],
    malware_families: ['ALPHV-Rust', 'Exposé'],
    campaigns: ['HealthcareExtortion-2024'],
    base_confidence: 0.91
  }
};

class ThreatActorService {
  /**
   * Profiles a threat actor based on evidence, observables, or explicit actor query.
   *
   * @param {Object} params
   * @param {string} [params.actor_name]
   * @param {string} [params.ioc]
   * @param {string} [params.incident_id]
   * @param {string} [params.alert_id]
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Threat actor profile report
   */
  async profileActor({ actor_name = null, ioc = null, incident_id = null, alert_id = null, organization_id, user_id = null }, client = null) {
    if (!organization_id) throw new Error('ThreatActorService requires organization_id');
    const dbClient = client || db;

    let targetActorName = actor_name ? actor_name.trim() : null;
    let infrastructure = [];
    let observedTechniques = [];
    let linkedCampaigns = [];

    // 1. Pivot from IOC if passed
    if (ioc) {
      infrastructure.push(ioc);
      const iocRes = await dbClient.query(`
        SELECT * FROM public.threat_iocs
        WHERE organization_id = $1 AND LOWER(ioc_value) = LOWER($2)
        LIMIT 1;
      `, [organization_id, ioc.trim()]);
      if (iocRes.rows.length > 0) {
        const row = iocRes.rows[0];
        if (row.threat_actor && !targetActorName) targetActorName = row.threat_actor.trim();
        if (row.campaign_name) linkedCampaigns.push(row.campaign_name);
        if (row.tags && Array.isArray(row.tags)) {
          row.tags.forEach(t => { if (/^T\d{4}/i.test(t)) observedTechniques.push(t.toUpperCase()); });
        }
      }
    }

    // 2. Pivot from Incident
    if (incident_id) {
      const incRes = await dbClient.query(`
        SELECT * FROM public.incidents WHERE id = $1 AND organization_id = $2;
      `, [incident_id, organization_id]);
      if (incRes.rows.length > 0) {
        const inc = incRes.rows[0];
        if (inc.fingerprint) infrastructure.push(inc.fingerprint);
      }
    }

    // 3. Match Knowledge Base
    let profile = null;
    if (targetActorName) {
      const upperName = targetActorName.toUpperCase();
      for (const [key, known] of Object.entries(KNOWN_ACTORS)) {
        if (upperName.includes(key) || known.aliases.some(a => upperName.includes(a.toUpperCase()))) {
          profile = known;
          break;
        }
      }
    }

    // Fallback profile if not in hardcoded dict
    if (!profile) {
      const defaultActorName = targetActorName || 'APT-UNSPECIFIED';
      profile = {
        actor: defaultActorName,
        category: 'Adversary Threat Group',
        tactics: ['Initial Access', 'Command and Control'],
        techniques: observedTechniques.length > 0 ? observedTechniques : ['T1566', 'T1071'],
        malware_families: ['Custom Backdoor'],
        campaigns: linkedCampaigns.length > 0 ? linkedCampaigns : ['Targeted-Intrusion'],
        base_confidence: 0.85
      };
    }

    // 4. Query Tenant IOCs attributed to this actor
    const allIocRes = await dbClient.query(`
      SELECT ioc_value, campaign_name FROM public.threat_iocs
      WHERE organization_id = $1 AND (threat_actor ILIKE $2 OR campaign_name ILIKE $2)
      LIMIT 15;
    `, [organization_id, `%${targetActorName || 'APT'}%`]);
    allIocRes.rows.forEach(r => {
      infrastructure.push(r.ioc_value);
      if (r.campaign_name) linkedCampaigns.push(r.campaign_name);
    });

    const finalInfra = Array.from(new Set(infrastructure));
    const finalCampaigns = Array.from(new Set([...profile.campaigns, ...linkedCampaigns]));
    const finalTechniques = Array.from(new Set([...profile.techniques, ...observedTechniques]));

    const report = {
      actor: profile.actor,
      confidence: profile.base_confidence,
      category: profile.category,
      tactics: profile.tactics,
      techniques: finalTechniques,
      infrastructure: finalInfra,
      campaigns: finalCampaigns,
      malware_families: profile.malware_families
    };

    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_THREAT_ACTOR_PROFILED',
      resource_type: 'threat_actor',
      resource_id: profile.actor.slice(0, 50),
      details: { actor: profile.actor, confidence: profile.base_confidence, infra_count: finalInfra.length }
    }).catch(() => {});

    return report;
  }
}

module.exports = new ThreatActorService();
