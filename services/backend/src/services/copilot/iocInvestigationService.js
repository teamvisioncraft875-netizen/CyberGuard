const db = require('../../config/db');
const { log: auditLog } = require('../auditService');
const ThreatIOC = require('../../models/ThreatIOC');
const CopilotInvestigation = require('../../models/CopilotInvestigation');
const CopilotMessage = require('../../models/CopilotMessage');

class IocInvestigationService {
  /**
   * Automatically detects the IOC type from string.
   */
  detectType(value) {
    const val = String(value || '').trim();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) return 'ip';
    if (/^[0-9a-fA-F:]{3,39}$/.test(val) && val.includes(':')) return 'ip';
    if (/^https?:\/\//i.test(val)) return 'url';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return 'email';
    if (/^[a-fA-F0-9]{64}$/.test(val)) return 'sha256';
    if (/^[a-fA-F0-9]{40}$/.test(val)) return 'sha1';
    if (/^[a-fA-F0-9]{32}$/.test(val)) return 'md5';
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return 'domain';
    return 'unknown';
  }

  /**
   * Conducts a multi-hop IOC investigation pivoting across Threat Intel, Alerts, Incidents,
   * Assets, Users, and MITRE techniques.
   *
   * @param {Object} params
   * @param {string} params.ioc - The observable value to investigate
   * @param {string} params.organization_id - Mandatory tenant ID
   * @param {string} [params.session_id]
   * @param {string} [params.user_id]
   * @returns {Promise<Object>} Pivoted investigation report
   */
  async investigate({ ioc, organization_id, session_id = null, user_id = null }, client = null) {
    if (!organization_id) throw new Error('IocInvestigationService requires organization_id');
    if (!ioc) throw new Error('IocInvestigationService requires ioc');

    const dbClient = client || db;
    const cleanIoc = String(ioc).trim();
    const detectedType = this.detectType(cleanIoc);

    // 1. Pivot Threat Intelligence
    let threatIntelRecord = await ThreatIOC.findByValue(organization_id, cleanIoc, dbClient).catch(() => null);
    if (!threatIntelRecord) {
      // Try reverse query or partial match
      const iocQuery = `
        SELECT * FROM public.threat_iocs
        WHERE organization_id = $1 AND LOWER(ioc_value) = LOWER($2)
        LIMIT 1;
      `;
      const iocRes = await dbClient.query(iocQuery, [organization_id, cleanIoc]);
      threatIntelRecord = iocRes.rows[0] || null;
    }

    const threatIntel = threatIntelRecord ? {
      found: true,
      ioc_type: threatIntelRecord.ioc_type,
      risk_score: threatIntelRecord.risk_score,
      confidence: threatIntelRecord.confidence,
      threat_actor: threatIntelRecord.threat_actor,
      malware_family: threatIntelRecord.malware_family,
      campaign_name: threatIntelRecord.campaign_name,
      tags: threatIntelRecord.tags || [],
      first_seen: threatIntelRecord.first_seen,
      last_seen: threatIntelRecord.last_seen
    } : {
      found: false,
      ioc_type: detectedType,
      risk_score: 50,
      confidence: 50,
      threat_actor: null,
      malware_family: null,
      campaign_name: null,
      tags: [],
      note: 'No prior local threat intel sighting record; baseline intelligence applied.'
    };

    // 2. Pivot SIEM Alerts
    const alertSql = `
      SELECT id, title, severity, status, mitre_technique, metadata, created_at
      FROM public.siem_alerts
      WHERE organization_id = $1 AND (
        metadata::text ILIKE $2 OR
        title ILIKE $2
      )
      ORDER BY created_at DESC
      LIMIT 20;
    `;
    const alertRes = await dbClient.query(alertSql, [organization_id, `%${cleanIoc}%`]);
    const relatedAlerts = alertRes.rows;

    // 3. Pivot Incidents
    const incSql = `
      SELECT id, threat_type, risk_level, risk_score, explanation, fingerprint, device_id, user_id, status, created_at
      FROM public.incidents
      WHERE organization_id = $1 AND (
        fingerprint ILIKE $2 OR
        explanation ILIKE $2
      )
      ORDER BY created_at DESC
      LIMIT 20;
    `;
    const incRes = await dbClient.query(incSql, [organization_id, `%${cleanIoc}%`]);
    const relatedIncidents = incRes.rows;

    // 4. Identify Affected Assets
    const assetSet = new Set();
    relatedIncidents.forEach(inc => {
      if (inc.device_id) assetSet.add(String(inc.device_id));
    });
    relatedAlerts.forEach(al => {
      const meta = al.metadata || {};
      if (meta.hostname) assetSet.add(String(meta.hostname));
      if (meta.host) assetSet.add(String(meta.host));
      if (meta.source_ip && meta.source_ip !== cleanIoc) assetSet.add(String(meta.source_ip));
      if (meta.dest_ip && meta.dest_ip !== cleanIoc) assetSet.add(String(meta.dest_ip));
    });
    const affectedAssets = Array.from(assetSet).map(asset => ({ asset_identifier: asset }));

    // 5. Identify Affected Users
    const userSet = new Set();
    relatedIncidents.forEach(inc => {
      if (inc.user_id) userSet.add(String(inc.user_id));
    });
    relatedAlerts.forEach(al => {
      const meta = al.metadata || {};
      if (meta.username) userSet.add(String(meta.username));
      if (meta.user) userSet.add(String(meta.user));
      if (meta.email) userSet.add(String(meta.email));
    });
    const affectedUsers = Array.from(userSet).map(usr => ({ user_identifier: usr }));

    // 6. MITRE Techniques
    const mitreSet = new Set();
    relatedAlerts.forEach(al => {
      if (al.mitre_technique) mitreSet.add(al.mitre_technique.trim().toUpperCase());
    });
    if (threatIntel.tags && Array.isArray(threatIntel.tags)) {
      threatIntel.tags.forEach(t => {
        if (/^T\d{4}/i.test(t)) mitreSet.add(t.toUpperCase());
      });
    }
    const mitre = Array.from(mitreSet).map(tech => ({
      technique: tech
    }));

    const result = {
      ioc: cleanIoc,
      ioc_type: detectedType,
      related_alerts: relatedAlerts,
      related_incidents: relatedIncidents,
      affected_assets: affectedAssets,
      affected_users: affectedUsers,
      mitre,
      threat_intel: threatIntel
    };

    // Audit Log
    await auditLog({
      organization_id,
      user_id,
      actor_type: 'user',
      action: 'COPILOT_IOC_INVESTIGATED',
      resource_type: 'ioc',
      resource_id: cleanIoc.slice(0, 50),
      details: {
        ioc: cleanIoc,
        ioc_type: detectedType,
        alerts_count: relatedAlerts.length,
        incidents_count: relatedIncidents.length
      }
    }).catch(() => {});

    // Session Memory Persistence
    if (session_id) {
      await CopilotInvestigation.create({
        session_id,
        organization_id,
        investigation_type: 'ioc',
        title: `IOC Pivot: ${cleanIoc}`,
        target_type: detectedType,
        target_id: cleanIoc,
        findings: [
          { type: 'threat_intel', data: threatIntel },
          { type: 'related_alerts_count', count: relatedAlerts.length },
          { type: 'related_incidents_count', count: relatedIncidents.length }
        ],
        evidence: [
          ...relatedAlerts.map(a => ({ type: 'alert', id: a.id, title: a.title })),
          ...relatedIncidents.map(i => ({ type: 'incident', id: i.id, threat_type: i.threat_type }))
        ],
        recommendations: [
          `Pivot on correlated alerts and evaluate host isolation for ${affectedAssets.length} affected assets.`
        ],
        severity: (threatIntel.risk_score >= 80 || relatedAlerts.some(a => a.severity === 'critical')) ? 'critical' : 'high',
        confidence: 0.92,
        created_by: user_id
      }, dbClient).catch(() => {});

      await CopilotMessage.create({
        session_id,
        role: 'assistant',
        content: `Investigated IOC ${cleanIoc} (${detectedType}). Identified ${relatedAlerts.length} alerts, ${relatedIncidents.length} incidents, ${affectedAssets.length} assets, and ${affectedUsers.length} users.`,
        metadata: { ioc_investigation: result }
      }, dbClient).catch(() => {});
    }

    return result;
  }
}

module.exports = new IocInvestigationService();
