const auditService = require('../auditService');

/**
 * Entity Extraction Service — Extracts security observables, targets, and identifiers
 * from natural language analyst instructions.
 */
class EntityExtractionService {
  /**
   * Extracts typed cybersecurity entities from text.
   *
   * @param {string} text - Input text or command
   * @param {Object} [options]
   * @param {string} [options.organization_id]
   * @param {string} [options.actor_id]
   * @returns {Promise<Object>} Extracted entities
   */
  async extractEntities(text = '', options = {}) {
    const raw = String(text || '').trim();

    const entities = {
      ipv4: null,
      ipv6: null,
      domain: null,
      url: null,
      hash: null,
      username: null,
      email: null,
      alert_id: null,
      incident_id: null,
      case_id: null,
      playbook_name: null,
      mitre_technique: null,
      host: null
    };

    if (!raw) return entities;

    // 1. IPv4
    const ipMatch = raw.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
    if (ipMatch) {
      entities.ipv4 = ipMatch[0];
    }

    // 2. IPv6
    const ipv6Match = raw.match(/\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/i);
    if (ipv6Match) {
      entities.ipv6 = ipv6Match[0];
    }

    // 3. URLs
    const urlMatch = raw.match(/\bhttps?:\/\/[^\s/$.?#].[^\s]*/i);
    if (urlMatch) {
      entities.url = urlMatch[0];
    }

    // 4. Email
    const emailMatch = raw.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/);
    if (emailMatch) {
      entities.email = emailMatch[0];
      entities.username = emailMatch[0].split('@')[0];
    }

    // 5. Domain (excluding URL match and email)
    const domainRegex = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|edu|gov|co|info|biz|xyz|internal|cc))\b/gi;
    const domainMatches = Array.from(raw.matchAll(domainRegex)).map(m => m[1].toLowerCase());
    const validDomain = domainMatches.find(d => {
      const inUrl = entities.url && entities.url.toLowerCase().includes(d);
      const inEmail = entities.email && entities.email.toLowerCase().includes(d);
      return !inUrl && !inEmail;
    });
    if (validDomain) {
      entities.domain = validDomain;
    }

    // 6. Hashes (MD5, SHA1, SHA256)
    const sha256Match = raw.match(/\b([a-fA-F0-9]{64})\b/);
    const sha1Match = raw.match(/\b([a-fA-F0-9]{40})\b/);
    const md5Match = raw.match(/\b([a-fA-F0-9]{32})\b/);
    if (sha256Match) {
      entities.hash = sha256Match[1].toLowerCase();
    } else if (sha1Match) {
      entities.hash = sha1Match[1].toLowerCase();
    } else if (md5Match) {
      entities.hash = md5Match[1].toLowerCase();
    }

    // 7. Usernames
    if (!entities.username) {
      const userMatch = raw.match(/(?:@|user\s+|account\s+|username\s+)([a-zA-Z0-9_.-]+)/i) || raw.match(/\b(svc_[a-zA-Z0-9_-]+)\b/i);
      if (userMatch) {
        entities.username = userMatch[1];
      }
    }

    // 8. MITRE Technique
    const mitreMatch = raw.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
    if (mitreMatch) {
      entities.mitre_technique = mitreMatch[1].toUpperCase();
    }

    // 9. Alert ID
    const alertMatch = raw.match(/(?:alert\s+(?:id\s+)?|alert_id\s*=\s*)([0-9a-fA-F-]{36}|ALT-[a-zA-Z0-9_-]+|\d+)/i);
    if (alertMatch) {
      entities.alert_id = alertMatch[1];
    }

    // 10. Incident ID
    const incidentMatch = raw.match(/(?:incident\s+(?:id\s+)?|incident_id\s*=\s*)([0-9a-fA-F-]{36}|INC-[a-zA-Z0-9_-]+|\d+)/i);
    if (incidentMatch) {
      entities.incident_id = incidentMatch[1];
    }

    // 11. Case ID
    const caseMatch = raw.match(/(?:case\s+(?:id\s+)?|case_id\s*=\s*)([0-9a-fA-F-]{36}|SEC-[a-zA-Z0-9_-]+|\d+)/i);
    if (caseMatch) {
      entities.case_id = isNaN(Number(caseMatch[1])) ? caseMatch[1] : Number(caseMatch[1]);
    }

    // 12. Host / Endpoint
    const hostMatch = raw.match(/(?:host|endpoint|workstation|server|machine|device)\s+([a-zA-Z0-9_.-]+)/i);
    if (hostMatch) {
      entities.host = hostMatch[1];
    }

    // 13. Playbook Name
    const quotedPlaybook = raw.match(/["']([^"']+(?:containment|playbook|quarantine|response|investigation)[^"']*)["']/i);
    if (quotedPlaybook) {
      entities.playbook_name = quotedPlaybook[1].trim();
    } else {
      const pbPattern = raw.match(/(?:run|execute|launch|trigger)\s+(?:the\s+)?([a-zA-Z0-9_\s-]+?)\s+(?:on|for|against|playbook)/i);
      if (pbPattern) {
        entities.playbook_name = pbPattern[1].trim();
      } else if (raw.toLowerCase().includes('ransomware containment')) {
        entities.playbook_name = 'ransomware containment';
      } else if (raw.toLowerCase().includes('credential quarantine')) {
        entities.playbook_name = 'credential quarantine';
      }
    }

    // Audit Logging if organization_id is provided
    if (options.organization_id) {
      const extractedCount = Object.values(entities).filter(Boolean).length;
      await auditService.log({
        organization_id: options.organization_id,
        actor_id: options.actor_id || null,
        action: 'COPILOT_ENTITY_EXTRACTED',
        resource_type: 'copilot_entities',
        resource_id: 'entity_extractor',
        details: {
          extracted_count: extractedCount,
          entities
        }
      }).catch(err => console.error('[EntityExtractionService] Audit log error:', err.message));
    }

    return entities;
  }
}

const entityExtractionService = new EntityExtractionService();
module.exports = entityExtractionService;
