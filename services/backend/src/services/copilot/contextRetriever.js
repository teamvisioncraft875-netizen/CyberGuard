const db = require('../../config/db');
const { log: auditLog } = require('../auditService');

/**
 * Context Retriever — Gathers organization-scoped security context for RAG copilot queries.
 * Enforces strict multi-tenant boundaries and limits token bloat.
 */
class ContextRetriever {
  /**
   * Retrieves security context based on query type and optional entity_id.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Tenant ID (mandatory)
   * @param {string} [params.user_id] - Querying user ID
   * @param {string} params.type - Task type (e.g. explain_alert, explain_incident, etc.)
   * @param {string} [params.entity_id] - Target entity UUID or identifier
   * @param {string} [params.question] - Analyst inquiry
   * @param {Object} [client] - Optional DB client
   * @returns {Promise<{ contextText: string, sources: Array<{ type: string, id: string, label: string }>, entity: Object|null }>}
   */
  async retrieveContext({
    organization_id,
    user_id = null,
    type,
    entity_id = null,
    question = ''
  }, client = null) {
    if (!organization_id) {
      throw new Error('ContextRetriever requires organization_id');
    }

    const dbClient = client || db;
    const sources = [];
    const contextSections = [];
    let mainEntity = null;

    // 1. Fetch Primary Entity based on task type & entity_id
    if (entity_id) {
      switch (type) {
        case 'explain_alert': {
          const alertRes = await dbClient.query(
            `SELECT id, title, severity, status, source_type, mitre_technique, metadata, created_at
             FROM public.siem_alerts
             WHERE id = $1 AND organization_id = $2;`,
            [entity_id, organization_id]
          );
          if (alertRes.rows[0]) {
            mainEntity = alertRes.rows[0];
            sources.push({ type: 'siem_alert', id: mainEntity.id, label: mainEntity.title });
            contextSections.push(
              `[PRIMARY ALERT]: ID=${mainEntity.id} | Title="${mainEntity.title}" | Severity=${mainEntity.severity} | MITRE=${mainEntity.mitre_technique || 'N/A'} | SourceType=${mainEntity.source_type || 'N/A'}\n` +
              `Metadata: ${JSON.stringify(mainEntity.metadata || {})}`
            );
          }
          break;
        }

        case 'explain_incident': {
          const incRes = await dbClient.query(
            `SELECT id, threat_type, source_type, risk_level, risk_score, explanation, status, priority, created_at
             FROM public.incidents
             WHERE id = $1 AND organization_id = $2;`,
            [entity_id, organization_id]
          );
          if (incRes.rows[0]) {
            mainEntity = incRes.rows[0];
            const incLabel = `Incident [${mainEntity.threat_type || 'threat'}] - ${mainEntity.risk_level || 'high'}`;
            sources.push({ type: 'incident', id: mainEntity.id, label: incLabel });
            contextSections.push(
              `[PRIMARY INCIDENT]: ID=${mainEntity.id} | Threat Type=${mainEntity.threat_type} | Risk Level=${mainEntity.risk_level} (Score ${mainEntity.risk_score}) | Status=${mainEntity.status} | Priority=${mainEntity.priority}\n` +
              `Explanation: ${mainEntity.explanation || 'None'}`
            );
          }
          break;
        }

        case 'explain_attack_chain': {
          const chainRes = await dbClient.query(
            `SELECT id, root_incident_id, confidence_score, chain_length, timeline, metadata, created_at
             FROM public.attack_chain_snapshots
             WHERE (id = $1 OR root_incident_id = $1) AND organization_id = $2
             ORDER BY created_at DESC LIMIT 1;`,
            [entity_id, organization_id]
          );
          if (chainRes.rows[0]) {
            mainEntity = chainRes.rows[0];
            sources.push({ type: 'attack_chain', id: mainEntity.id, label: `Attack Chain (Root Incident ${mainEntity.root_incident_id})` });
            contextSections.push(
              `[PRIMARY ATTACK CHAIN]: ID=${mainEntity.id} | Root Incident=${mainEntity.root_incident_id} | Confidence=${mainEntity.confidence_score} | Length=${mainEntity.chain_length}\n` +
              `Timeline: ${JSON.stringify(mainEntity.timeline || [])}\n` +
              `Metadata: ${JSON.stringify(mainEntity.metadata || {})}`
            );
          }
          break;
        }

        case 'summarize_ioc': {
          const iocRes = await dbClient.query(
            `SELECT id, ioc_type, ioc_value, confidence, risk_score, threat_actor, malware_family, tags, first_seen, last_seen
             FROM public.threat_iocs
             WHERE (id::text = $1 OR lower(ioc_value) = lower($1)) AND organization_id = $2
             LIMIT 1;`,
            [entity_id, organization_id]
          );
          if (iocRes.rows[0]) {
            mainEntity = iocRes.rows[0];
            sources.push({ type: 'threat_ioc', id: mainEntity.id, label: `${mainEntity.ioc_type}:${mainEntity.ioc_value}` });
            contextSections.push(
              `[PRIMARY IOC]: ID=${mainEntity.id} | Type=${mainEntity.ioc_type} | Value="${mainEntity.ioc_value}" | Risk Score=${mainEntity.risk_score}/100 | Confidence=${mainEntity.confidence}%\n` +
              `Threat Actor: ${mainEntity.threat_actor || 'Unknown'} | Malware Family: ${mainEntity.malware_family || 'None'} | Tags: ${JSON.stringify(mainEntity.tags || [])}`
            );
          }
          break;
        }

        default:
          break;
      }
    }

    // 2. Correlate Related Context (IOCs, Cases, Playbooks)
    // Related Threat IOCs
    const iocRows = await dbClient.query(
      `SELECT id, ioc_type, ioc_value, risk_score, threat_actor, malware_family
       FROM public.threat_iocs
       WHERE organization_id = $1
       ORDER BY risk_score DESC LIMIT 5;`,
      [organization_id]
    );
    if (iocRows.rows.length > 0 && type !== 'summarize_ioc') {
      const iocSummaries = iocRows.rows.map(i => {
        sources.push({ type: 'threat_ioc', id: i.id, label: `${i.ioc_type}:${i.ioc_value}` });
        return `• ${i.ioc_type}: ${i.ioc_value} (Risk: ${i.risk_score}, Actor: ${i.threat_actor || 'N/A'}, Family: ${i.malware_family || 'N/A'})`;
      }).join('\n');
      contextSections.push(`[KNOWN THREAT IOCs IN TENANT]:\n${iocSummaries}`);
    }

    // Related SOAR Playbooks (crucial for recommend_playbook)
    const playbookRows = await dbClient.query(
      `SELECT id, name, description, trigger_type, enabled
       FROM public.soar_playbooks
       WHERE organization_id = $1 AND enabled = true
       ORDER BY created_at DESC LIMIT 5;`,
      [organization_id]
    ).catch(() => ({ rows: [] }));
    if (playbookRows.rows.length > 0) {
      const pbSummaries = playbookRows.rows.map(p => {
        sources.push({ type: 'soar_playbook', id: p.id, label: p.name });
        return `• [Playbook ${p.id}] "${p.name}" (Trigger: ${p.trigger_type}): ${p.description || 'No description'}`;
      }).join('\n');
      contextSections.push(`[AVAILABLE SOAR PLAYBOOKS]:\n${pbSummaries}`);
    }

    // Related SOAR Cases (for investigations and notes)
    if (['investigation_steps', 'generate_analyst_note', 'explain_incident'].includes(type)) {
      const caseRows = await dbClient.query(
        `SELECT id, title, severity, status, threat_intel_findings
         FROM public.soar_cases
         WHERE organization_id = $1
         ORDER BY created_at DESC LIMIT 3;`,
        [organization_id]
      ).catch(() => ({ rows: [] }));
      if (caseRows.rows.length > 0) {
        const caseSummaries = caseRows.rows.map(c => {
          sources.push({ type: 'soar_case', id: c.id, label: c.title });
          return `• [Case ${c.id}] "${c.title}" (${c.severity}/${c.status}): Findings=${JSON.stringify(c.threat_intel_findings || {})}`;
        }).join('\n');
        contextSections.push(`[ACTIVE SOAR CASES]:\n${caseSummaries}`);
      }
    }

    // Deduplicate sources by id
    const uniqueSources = [];
    const seenIds = new Set();
    for (const src of sources) {
      if (!seenIds.has(src.id)) {
        seenIds.add(src.id);
        uniqueSources.push(src);
      }
    }

    const contextText = contextSections.length > 0
      ? contextSections.join('\n\n')
      : 'No organizational context records found for the query parameters.';

    // Audit context retrieval
    await auditLog({
      organization_id,
      user_id,
      action: 'COPILOT_CONTEXT_RETRIEVED',
      resource_type: 'copilot',
      resource_id: entity_id || 'context',
      details: {
        query_type: type,
        entity_id,
        sources_count: uniqueSources.length
      }
    }).catch(() => {});

    return {
      contextText,
      sources: uniqueSources,
      entity: mainEntity
    };
  }
}

const contextRetriever = new ContextRetriever();
module.exports = contextRetriever;
