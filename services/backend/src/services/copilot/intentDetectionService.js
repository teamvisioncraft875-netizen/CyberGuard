const auditService = require('../auditService');

/**
 * Intent Detection Service — Classifies natural language SOC analyst instructions
 * into structured operational intents (single-step and multi-step).
 */
class IntentDetectionService {
  constructor() {
    this.INTENT_PATTERNS = [
      // 1. Playbook execution vs recommendation
      {
        intent: 'recommend_playbook',
        regex: /(?:what|which|recommend|suggest)\s+playbook|playbook\s+should\s+i\s+run/i,
        baseConfidence: 0.96
      },
      {
        intent: 'execute_playbook',
        regex: /(?:run|execute|launch|trigger|start)\s+(?:playbook|runbook)|run\s+[\w\s-]+\s+(?:containment|response|playbook)/i,
        baseConfidence: 0.95
      },

      // 2. SOAR Cases
      {
        intent: 'create_case',
        regex: /(?:create|open|start|new|initialize)\s+(?:soar\s+)?case/i,
        baseConfidence: 0.98
      },
      {
        intent: 'escalate_case',
        regex: /(?:escalate|raise\s+priority\s+of|bump)\s+case/i,
        baseConfidence: 0.95
      },
      {
        intent: 'show_case',
        regex: /(?:show|view|get|display|details\s+of)\s+case/i,
        baseConfidence: 0.94
      },

      // 3. Containment Actions
      {
        intent: 'isolate_endpoint',
        regex: /(?:isolate|quarantine|sever|disconnect)\s+(?:host|endpoint|workstation|server|machine|device)/i,
        baseConfidence: 0.96
      },
      {
        intent: 'block_ip',
        regex: /(?:block|ban|firewall|drop|blacklist)\s+(?:ip\s+)?(?:\d{1,3}\.){3}\d{1,3}|block\s+ip/i,
        baseConfidence: 0.96
      },
      {
        intent: 'block_domain',
        regex: /(?:block|sinkhole|blacklist)\s+(?:domain|url|fqdn|site)/i,
        baseConfidence: 0.94
      },
      {
        intent: 'disable_account',
        regex: /(?:disable|lock|suspend|revoke)\s+(?:user|account|credentials?|identity)/i,
        baseConfidence: 0.95
      },

      // 4. External Integrations
      {
        intent: 'create_jira_ticket',
        regex: /(?:create|file|open)\s+(?:jira|ticket|issue)/i,
        baseConfidence: 0.95
      },
      {
        intent: 'send_slack_message',
        regex: /(?:notify|send|message|post\s+to|alert)\s+slack/i,
        baseConfidence: 0.95
      },
      {
        intent: 'send_teams_message',
        regex: /(?:notify|send|message|post\s+to|alert)\s+teams/i,
        baseConfidence: 0.95
      },

      // 5. Approvals
      {
        intent: 'create_approval',
        regex: /(?:request|require|create|ask\s+for)\s+approval/i,
        baseConfidence: 0.95
      },

      // 6. Memory & Summarization
      {
        intent: 'summarize_session',
        regex: /(?:what\s+actions|actions\s+taken|summary\s+of\s+actions|what\s+did\s+we\s+do|session\s+actions|timeline)/i,
        baseConfidence: 0.94
      },

      // 7. Listings
      {
        intent: 'list_incidents',
        regex: /(?:list|show|get|display|active)\s+incidents/i,
        baseConfidence: 0.93
      },
      {
        intent: 'list_alerts',
        regex: /(?:list|show|get|display|critical)\s+alerts/i,
        baseConfidence: 0.93
      }
    ];
  }

  /**
   * Detects intent(s) from natural language analyst input.
   *
   * @param {string} command - Analyst instruction
   * @param {Object} [options]
   * @param {string} [options.organization_id]
   * @param {string} [options.actor_id]
   * @returns {Promise<{ intent: string, intents: string[], confidence: number, raw_command: string }>}
   */
  async detectIntent(command = '', options = {}) {
    const raw = String(command || '').trim();
    if (!raw) {
      return {
        intent: 'unknown',
        intents: [],
        confidence: 0,
        raw_command: raw
      };
    }

    // Split compound instructions connected by "and", "then", ";" or "&"
    const subClauses = raw.split(/\s+(?:and\s+then|and|then|;|\&)\s+/i).filter(Boolean);
    const matchedIntents = [];
    let topConfidence = 0.50;

    for (const clause of subClauses) {
      let clauseIntent = null;
      let clauseConf = 0.50;

      for (const pattern of this.INTENT_PATTERNS) {
        if (pattern.regex.test(clause)) {
          clauseIntent = pattern.intent;
          clauseConf = pattern.baseConfidence;
          break;
        }
      }

      // Fallbacks if clause didn't match directly
      if (!clauseIntent) {
        if (/\b(?:185\.|10\.|192\.|172\.|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/.test(clause) && /block/i.test(raw)) {
          clauseIntent = 'block_ip';
          clauseConf = 0.92;
        } else if (/case/i.test(clause) && /create/i.test(raw)) {
          clauseIntent = 'create_case';
          clauseConf = 0.92;
        } else if (/slack/i.test(clause)) {
          clauseIntent = 'send_slack_message';
          clauseConf = 0.90;
        } else if (/jira/i.test(clause)) {
          clauseIntent = 'create_jira_ticket';
          clauseConf = 0.90;
        }
      }

      if (clauseIntent && !matchedIntents.includes(clauseIntent)) {
        matchedIntents.push(clauseIntent);
        if (clauseConf > topConfidence) {
          topConfidence = clauseConf;
        }
      }
    }

    // If no clause matched, test whole raw command
    if (matchedIntents.length === 0) {
      for (const pattern of this.INTENT_PATTERNS) {
        if (pattern.regex.test(raw)) {
          matchedIntents.push(pattern.intent);
          topConfidence = pattern.baseConfidence;
          break;
        }
      }
    }

    const primaryIntent = matchedIntents[0] || 'unknown';

    // Audit Logging if organization_id is provided
    if (options.organization_id) {
      await auditService.log({
        organization_id: options.organization_id,
        actor_id: options.actor_id || null,
        action: 'COPILOT_INTENT_DETECTED',
        resource_type: 'copilot_intent',
        resource_id: primaryIntent,
        details: {
          raw_command: raw.slice(0, 150),
          intent: primaryIntent,
          intents: matchedIntents,
          confidence: topConfidence
        }
      }).catch(err => console.error('[IntentDetectionService] Audit log error:', err.message));
    }

    return {
      intent: primaryIntent,
      intents: matchedIntents,
      confidence: topConfidence,
      raw_command: raw
    };
  }
}

const intentDetectionService = new IntentDetectionService();
module.exports = intentDetectionService;
