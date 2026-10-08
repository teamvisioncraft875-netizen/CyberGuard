const db = require('../../config/db');
const auditService = require('../auditService');

/**
 * Playbook Recommendation Service — Discovers, ranks, and explains matching SOAR playbooks
 * for natural-language inquiries, active alerts, and specific threat categories.
 */
class PlaybookRecommendationService {
  /**
   * Discovers and ranks relevant security playbooks.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Tenant ID
   * @param {string} [params.query] - Natural language query (e.g. "What playbook should I run for ransomware?")
   * @param {string} [params.threat_type] - Threat type (e.g. ransomware, phishing, credential_dumping)
   * @param {string} [params.mitre_technique] - MITRE ATT&CK technique (e.g. T1486)
   * @param {string} [params.alert_id] - Optional alert UUID
   * @param {string} [params.actor_id] - User UUID
   * @returns {Promise<{ recommendations: Array<Object> }>}
   */
  async recommendPlaybooks({
    organization_id,
    query = '',
    threat_type = null,
    mitre_technique = null,
    alert_id = null,
    actor_id = null
  }) {
    if (!organization_id) {
      throw new Error('PlaybookRecommendationService Error: organization_id is required');
    }

    const qLower = String(query || '').toLowerCase();
    const threatLower = String(threat_type || '').toLowerCase();

    // 1. Fetch available playbooks for the organization
    const res = await db.query(
      `SELECT id, name, description, trigger_type, trigger_conditions, enabled
       FROM public.soar_playbooks
       WHERE organization_id = $1 AND enabled = true
       ORDER BY created_at DESC;`,
      [organization_id]
    );

    let playbooks = res.rows;

    // Detect target threat domain from query
    let targetDomain = 'general';
    if (qLower.includes('ransomware') || threatLower.includes('ransomware') || mitre_technique === 'T1486') {
      targetDomain = 'ransomware';
    } else if (qLower.includes('phish') || threatLower.includes('phish') || mitre_technique === 'T1566') {
      targetDomain = 'phishing';
    } else if (qLower.includes('credential') || qLower.includes('mimikatz') || qLower.includes('dumping') || mitre_technique === 'T1003') {
      targetDomain = 'credential_theft';
    } else if (qLower.includes('brute force') || qLower.includes('login') || mitre_technique === 'T1110') {
      targetDomain = 'brute_force';
    } else if (qLower.includes('lateral') || qLower.includes('traversal') || mitre_technique === 'T1021') {
      targetDomain = 'lateral_movement';
    } else if (qLower.includes('c2') || qLower.includes('beacon') || mitre_technique === 'T1071') {
      targetDomain = 'c2_beaconing';
    }

    const scored = [];

    for (const pb of playbooks) {
      const nameLower = (pb.name || '').toLowerCase();
      const descLower = (pb.description || '').toLowerCase();
      const condStr = JSON.stringify(pb.trigger_conditions || {}).toLowerCase();

      let score = 0.50; // base score
      let matchReasons = [];

      if (targetDomain !== 'general') {
        const domainKeywords = {
          ransomware: ['ransomware', 'encrypt', 'crypto', 'shadow', 't1486'],
          phishing: ['phish', 'email', 'lure', 'attachment', 't1566'],
          credential_theft: ['credential', 'mimikatz', 'dump', 'lsass', 't1003'],
          brute_force: ['brute', 'password', 'login', 'auth', 't1110'],
          lateral_movement: ['lateral', 'remote', 'smb', 'wmi', 't1021'],
          c2_beaconing: ['c2', 'beacon', 'command', 'dns', 't1071']
        }[targetDomain] || [];

        const keywordHit = domainKeywords.find(k => nameLower.includes(k));
        if (keywordHit) {
          score += 0.45;
          matchReasons.push(`Title explicitly addresses ${targetDomain} threats ("${keywordHit}")`);
        } else if (domainKeywords.some(k => descLower.includes(k))) {
          score += 0.35;
          matchReasons.push(`Description matches ${targetDomain} incident handling procedures`);
        } else if (domainKeywords.some(k => condStr.includes(k))) {
          score += 0.25;
          matchReasons.push(`Trigger conditions include ${targetDomain} telemetry indicators`);
        }
      }

      if (mitre_technique && (condStr.includes(mitre_technique.toLowerCase()) || descLower.includes(mitre_technique.toLowerCase()))) {
        score += 0.20;
        matchReasons.push(`Directly mapped to ATT&CK technique ${mitre_technique}`);
      }

      if (qLower && nameLower.includes(qLower)) {
        score += 0.30;
      }

      const finalConfidence = Math.min(0.99, Math.round(score * 100) / 100);

      scored.push({
        playbook_id: pb.id,
        name: pb.name,
        description: pb.description || 'Standard automated incident response workflow.',
        confidence: finalConfidence,
        reason: matchReasons.length > 0
          ? matchReasons.join('. ') + '.'
          : `Automated ${pb.trigger_type} response playbook applicable to general security event containment.`,
        trigger_type: pb.trigger_type
      });
    }

    // If no custom playbooks exist in DB, provide standard CyberGuard response playbook recommendations
    if (scored.length === 0) {
      const defaultRecommendations = [
        {
          playbook_id: 'pb-ransomware-containment',
          name: 'Ransomware Emergency Containment Playbook',
          description: 'Automated host isolation, shadow copy verification, and network boundary quarantine for rapid ransomware containment.',
          confidence: targetDomain === 'ransomware' ? 0.96 : 0.80,
          reason: 'Tailored for rapid endpoint isolation, memory acquisition, and lateral perimeter fencing.',
          trigger_type: 'alert'
        },
        {
          playbook_id: 'pb-credential-quarantine',
          name: 'Credential Dumping & Identity Quarantine Playbook',
          description: 'Suspends compromised accounts, revokes Kerberos tickets, and quarantines target identity assets.',
          confidence: targetDomain === 'credential_theft' ? 0.95 : 0.75,
          reason: 'Targets LSASS/in-memory credential harvesting, triggering immediate identity revocation.',
          trigger_type: 'alert'
        },
        {
          playbook_id: 'pb-c2-perimeter-sinkhole',
          name: 'C2 Beaconing & Perimeter Sinkhole Playbook',
          description: 'Blocks malicious IP/domain IOCs at firewall and redirects internal DNS requests to security sinkhole.',
          confidence: targetDomain === 'c2_beaconing' ? 0.94 : 0.70,
          reason: 'Drops outbound Command and Control channels and sinkholes active malicious indicators.',
          trigger_type: 'alert'
        }
      ];

      scored.push(...defaultRecommendations);
    }

    // Sort by confidence descending
    scored.sort((a, b) => b.confidence - a.confidence);

    // Audit logging
    await auditService.log({
      organization_id,
      actor_id,
      action: 'COPILOT_PLAYBOOK_RECOMMENDED',
      resource_type: 'soar_playbooks',
      resource_id: scored[0]?.playbook_id || 'playbook_discovery',
      details: {
        query: query.slice(0, 100),
        threat_domain: targetDomain,
        recommended_count: scored.length,
        top_playbook: scored[0]?.name
      }
    }).catch(err => console.error('[PlaybookRecommendationService] Audit log error:', err.message));

    return { recommendations: scored };
  }
}

const playbookRecommendationService = new PlaybookRecommendationService();
module.exports = playbookRecommendationService;
