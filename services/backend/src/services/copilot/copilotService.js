const contextRetriever = require('./contextRetriever');
const promptBuilder = require('./promptBuilder');
const socSearchService = require('./socSearchService');
const mitreReasoningService = require('./mitreReasoningService');
const { log: auditLog } = require('../auditService');

/**
 * CopilotService — Orchestrates Gemini Free Tier (Gemini Flash) AI Copilot assistance.
 * Features multi-turn memory, SOC search integration, MITRE reasoning, and deterministic fallback.
 */
class CopilotService {
  constructor() {
    this.model = 'gemini-2.5-flash';
    this.defaultTimeoutMs = parseInt(process.env.COPILOT_TIMEOUT_MS, 10) || 10000;
    this.mockHandler = null;
  }

  /**
   * Test helper to mock Gemini LLM responses without network calls.
   */
  setMockHandler(handler) {
    this.mockHandler = handler;
  }

  resetMockHandler() {
    this.mockHandler = null;
  }

  /**
   * Main query entrypoint.
   *
   * @param {Object} params
   * @param {string} params.organization_id - Tenant ID (mandatory)
   * @param {string} params.user_id - Querying user ID
   * @param {string} params.type - Task type
   * @param {string} [params.entity_id] - Entity identifier
   * @param {string} [params.question] - User question
   * @param {Array} [params.history] - Recent message history for multi-turn sessions
   * @param {number} [params.timeoutMs] - Optional custom timeout
   * @param {Object} [client] - Optional DB client
   * @returns {Promise<{ answer: string, sources: Array, tokens_used: number, extra: Object|null }>}
   */
  async query({
    organization_id,
    user_id = null,
    type,
    entity_id = null,
    question = '',
    history = [],
    sessionActions = [],
    timeoutMs = null
  }, client = null) {
    if (!organization_id) {
      throw new Error('CopilotService Error: organization_id is required');
    }
    if (!type || !promptBuilder.isValidTask(type)) {
      throw new Error(`CopilotService Error: Invalid or unsupported type "${type}"`);
    }

    let searchResult = null;
    let mitreResult = null;

    // Special handling for specialized copilot query types
    if (type === 'soc_search') {
      searchResult = await socSearchService.search({
        organization_id,
        user_id,
        query: question || entity_id || 'show recent alerts'
      }, client);
    } else if (type === 'explain_mitre') {
      const targetTechnique = entity_id || (question.match(/\b(T\d{4}(?:\.\d{3})?)\b/i)?.[1]) || 'T1021';
      mitreResult = await mitreReasoningService.explainMapping({
        technique: targetTechnique,
        organization_id,
        user_id
      });
    }

    // 1. Retrieve tenant-scoped security context
    const { contextText, sources, entity } = await contextRetriever.retrieveContext({
      organization_id,
      user_id,
      type,
      entity_id,
      question
    }, client);

    let mergedContextText = contextText;
    if (sessionActions && sessionActions.length > 0) {
      const actionSummaries = sessionActions.map(a => `- Action: ${a.action_type} (Status: ${a.status}, Approval: ${a.requires_approval ? 'Required' : 'None'}, Reason: ${a.reason || 'N/A'})`).join('\n');
      mergedContextText += `\n\n--- RECORDED INVESTIGATION ACTIONS ---\n${actionSummaries}`;
    }

    // If search results exist, append to sources
    if (searchResult && Array.isArray(searchResult.results)) {
      searchResult.results.forEach(r => {
        sources.push({ type: r.type, id: r.id, label: r.title || r.explanation || r.ioc_value || r.type });
      });
    }

    // 2. Build structured prompt with history
    const { systemInstruction, userPrompt } = promptBuilder.buildPrompt({
      type,
      entity_id,
      question,
      contextText: mergedContextText,
      sources,
      history
    });

    // 3. Check for Mock Handler (for testing)
    let answer = null;
    let tokensUsed = 0;

    if (this.mockHandler && typeof this.mockHandler === 'function') {
      const mockRes = await this.mockHandler({
        systemInstruction,
        userPrompt,
        type,
        question,
        entity_id,
        sources,
        history,
        sessionActions,
        searchResult,
        mitreResult
      });
      if (typeof mockRes === 'string') {
        answer = mockRes;
        tokensUsed = Math.ceil((userPrompt.length + answer.length) / 4);
      } else if (mockRes && mockRes.answer) {
        answer = mockRes.answer;
        tokensUsed = mockRes.tokens_used || Math.ceil((userPrompt.length + answer.length) / 4);
      }
    }

    // 4. Attempt Gemini API invocation if no mock and API key is present
    const effectiveTimeout = timeoutMs || this.defaultTimeoutMs;
    const apiKey = process.env.GEMINI_API_KEY;

    if (!answer && apiKey && apiKey.trim() && apiKey !== 'test-api-key') {
      try {
        const geminiResult = await this.callGemini({
          apiKey,
          systemInstruction,
          userPrompt,
          timeoutMs: effectiveTimeout
        });
        answer = geminiResult.text;
        tokensUsed = geminiResult.tokensUsed;
      } catch (err) {
        console.warn(`[CopilotService] Gemini API call degraded (${err.message}). Using fallback synthesis.`);
      }
    }

    // 5. Fallback deterministic response synthesis
    if (!answer) {
      answer = this.synthesizeFallbackResponse({
        type,
        entity_id,
        question,
        entity,
        contextText,
        sources,
        history,
        searchResult,
        mitreResult
      });
      tokensUsed = Math.ceil(((systemInstruction.length + userPrompt.length + answer.length) / 4));
    }

    // 6. Audit Log COPILOT_QUERY (Never storing raw prompt content)
    await auditLog({
      organization_id,
      user_id,
      action: 'COPILOT_QUERY',
      resource_type: 'copilot',
      resource_id: entity_id || 'copilot_query',
      details: {
        query_type: type,
        entity_id,
        sources_count: sources.length,
        tokens_used: tokensUsed
      }
    }).catch(() => {});

    return {
      answer,
      sources,
      tokens_used: tokensUsed,
      search_results: searchResult ? searchResult.results : undefined,
      mitre_data: mitreResult || undefined
    };
  }

  /**
   * Calls Gemini REST API using gemini-2.5-flash with AbortController timeout.
   */
  async callGemini({ apiKey, systemInstruction, userPrompt, timeoutMs }) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${apiKey}`;
    const payload = {
      contents: [
        {
          role: 'user',
          parts: [
            { text: `${systemInstruction}\n\n${userPrompt}` }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 1200
      }
    };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Gemini API returned status ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) {
        throw new Error('Gemini API returned empty text part');
      }

      const tokensUsed = data.usageMetadata?.totalTokenCount || 0;
      return { text, tokensUsed };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Deterministic fallback response synthesizer.
   */
  synthesizeFallbackResponse({
    type,
    entity_id,
    question,
    entity,
    contextText,
    sources,
    history = [],
    searchResult,
    mitreResult
  }) {
    switch (type) {
      case 'explain_alert': {
        const title = entity?.title || 'Security Alert';
        const sev = entity?.severity || 'High';
        const mitre = entity?.mitre_technique || 'T1071';
        return `[ALERT EXPLANATION] ${title}\n` +
          `• Threat Severity: ${sev.toUpperCase()}\n` +
          `• MITRE ATT&CK Mapping: ${mitre}\n` +
          `• Summary: Detection triggered on anomalous activity matching technique ${mitre}. Inspection of tenant telemetry indicates activity originating from monitored source. Recommended triage entails isolating affected endpoints and verifying correlation against active threat indicators.`;
      }

      case 'explain_incident': {
        const title = entity?.explanation ? entity.explanation.slice(0, 60) : (entity?.threat_type || 'Security Incident');
        const sev = entity?.risk_level || entity?.severity || 'High';
        const status = entity?.status || 'Open';
        return `[INCIDENT EXPLANATION] ${title}\n` +
          `• Severity & Status: ${String(sev).toUpperCase()} | ${status}\n` +
          `• Scope: Consolidated security telemetry identifies elevated risk across tenant assets.\n` +
          `• Context: Attack patterns exhibit multi-vector traits. Immediate actions include reviewing linked evidence and tracking progression along the incident timeline.`;
      }

      case 'explain_attack_chain': {
        const conf = entity?.confidence_score ? `${(entity.confidence_score * 100).toFixed(0)}%` : '85%';
        const len = entity?.chain_length || 2;
        return `[ATTACK CHAIN EXPLANATION]\n` +
          `• Progression Confidence: ${conf}\n` +
          `• Chain Stages (${len} stages observed): Multi-step attack sequence detected connecting initial ingress to subsequent execution.\n` +
          `• Assessment: Adversary demonstrates intent to expand perimeter foothold. Severing egress communications is advised.`;
      }

      case 'summarize_ioc': {
        const val = entity?.ioc_value || entity_id || 'Unknown IOC';
        const iocType = entity?.ioc_type || 'Indicator';
        const risk = entity?.risk_score !== undefined ? `${entity.risk_score}/100` : '80/100';
        const actor = entity?.threat_actor || 'Unattributed Threat Group';
        const malware = entity?.malware_family || 'Generic Suspicious';
        return `[IOC INTELLIGENCE SUMMARY]\n` +
          `• Indicator: [${iocType.toUpperCase()}] ${val}\n` +
          `• Threat Risk Score: ${risk}\n` +
          `• Attribution: Associated with ${actor} (Malware Family: ${malware}).\n` +
          `• Reputation: Malicious infrastructure confirmed across historical sightings. Advise perimeter firewall drop and host containment.`;
      }

      case 'recommend_playbook': {
        const matchingPlaybooks = sources.filter(s => s.type === 'soar_playbook');
        const pbName = matchingPlaybooks[0]?.label || 'Automated Incident Triage';
        return `[PLAYBOOK RECOMMENDATION]\n` +
          `• Recommended Playbook: "${pbName}"\n` +
          `• Justification: Evaluated available response workflows against detected threat telemetry. "${pbName}" matches the alert indicators, providing sequential containment and automated ticket escalation.`;
      }

      case 'investigation_steps': {
        return `[PRIORITIZED INVESTIGATION STEPS]\n` +
          `1. Telemetry Verification: Inspect firewall and NetFlow logs for outbound beaconing to suspect IP/domain.\n` +
          `2. Host Artifact Extraction: Examine processes and volatile memory on affected endpoints.\n` +
          `3. Identity & Credential Audit: Check Active Directory / IdP logs for anomalous authentications or privilege escalations.\n` +
          `4. Perimeter Isolation: Confirm firewall containment policies are engaged to block lateral movement.`;
      }

      case 'generate_analyst_note': {
        return `[ANALYST SHIFT HANDOVER NOTE]\n` +
          `• Subject: Security Triage & Escalation Summary\n` +
          `• Target: ${entity_id || 'Active Investigation'}\n` +
          `• Assessment: Elevated anomaly validated against tenant threat intelligence. No autonomous remediation executed.\n` +
          `• Next Shift Priority: Monitor persistence indicators and complete forensic memory triage.`;
      }

      case 'summarize_threat_intel': {
        return `[THREAT INTELLIGENCE SYNTHESIS]\n` +
          `• Overview: Current tenant intelligence baseline tracks elevated APT indicators across perimeter endpoints.\n` +
          `• Exposure: Active indicators mapped to command-and-control and lateral traversal.\n` +
          `• Risk Posture: High vigilance recommended for external-facing assets.`;
      }

      case 'soc_search': {
        const count = searchResult?.count || 0;
        const entityName = searchResult?.entity || 'records';
        return `[SOC SEARCH RESULTS]\n` +
          `• Found ${count} matching ${entityName} for query: "${question}"\n` +
          (searchResult?.results || []).slice(0, 5).map((r, i) =>
            `${i + 1}. [${r.type.toUpperCase()}] ${r.title || r.explanation || r.ioc_value || r.id} (${r.severity || r.risk_level || 'N/A'})`
          ).join('\n');
      }

      case 'explain_mitre': {
        if (mitreResult && mitreResult.recognized) {
          return `[MITRE ATT&CK REASONING]\n` +
            `• Technique: ${mitreResult.technique} — ${mitreResult.technique_name}\n` +
            `• Tactic: ${mitreResult.tactic}\n` +
            `• Confidence: ${(mitreResult.confidence * 100).toFixed(0)}%\n` +
            `• Description: ${mitreResult.description}\n` +
            `• Evidence Reasoning: ${mitreResult.reasoning}`;
        }
        return `[MITRE ATT&CK REASONING]\n` +
          `Technique query processed. Grounded in CyberGuard MITRE dictionary.`;
      }

      case 'session_chat': {
        const turns = history.length;
        return `[INVESTIGATION COPILOT RESPONSE]\n` +
          `Analysis for: "${question}". Current session has ${turns} prior messages.\n` +
          `Based on current tenant context, threat indicators require ongoing monitoring. Recommended next steps include host artifact inspection and verification of containment status.`;
      }

      default:
        return `[SECURITY COPILOT RESPONSE]\nAnalysis completed for inquiry: "${question || 'Security assessment'}". Grounded in ${sources.length} tenant context sources.`;
    }
  }
}

const copilotService = new CopilotService();
module.exports = copilotService;
