/**
 * Prompt Builder — Constructs strict, security-focused prompt templates for CyberGuard AI Copilot.
 */
class PromptBuilder {
  static SUPPORTED_TASKS = [
    'explain_alert',
    'explain_incident',
    'explain_attack_chain',
    'summarize_threat_intel',
    'summarize_ioc',
    'recommend_playbook',
    'investigation_steps',
    'generate_analyst_note',
    'soc_search',
    'explain_mitre',
    'session_chat'
  ];

  static SYSTEM_PROMPT = `You are CyberGuard AI Security Copilot, a Tier-2/3 SOC analyst virtual assistant.
Your sole purpose is to provide analyst assistance based strictly on provided organizational context.

STRICT CONSTRAINTS & BEHAVIORAL RULES:
1. CYBERSECURITY SCOPE ONLY: Only answer inquiries related to cybersecurity, threat detection, incident response, digital forensics, threat intelligence, and SOC procedures. Explicitly decline non-cybersecurity queries.
2. GROUNDED IN CONTEXT: Rely strictly on the provided organizational context. Never fabricate indicators, IP addresses, hashes, CVEs, or timestamps.
3. INSUFFICIENT CONTEXT: If the provided context is missing or insufficient to answer the question accurately, explicitly state: "Insufficient context exists in the current tenant records to confirm this detail."
4. NO AUTONOMOUS ACTION: You are a read-only advisory system. NEVER claim you executed any remediations, blocked any IPs, or altered any firewall rules. You only analyze, explain, and suggest.
5. FACTUAL EVIDENCE: Never state an attack was contained or mitigated unless the context explicitly documents that status.`;

  /**
   * Validates if task type is supported.
   */
  isValidTask(type) {
    return PromptBuilder.SUPPORTED_TASKS.includes(type);
  }

  /**
   * Builds the formatted prompt and system instruction.
   *
   * @param {Object} params
   * @param {string} params.type - Task type
   * @param {string} [params.entity_id] - Entity identifier
   * @param {string} [params.question] - User inquiry
   * @param {string} params.contextText - Retrieved organizational context
   * @param {Array} params.sources - Source metadata
   * @param {Array} [params.history] - Conversation history messages
   * @returns {{ systemInstruction: string, userPrompt: string }}
   */
  buildPrompt({
    type,
    entity_id = null,
    question = '',
    contextText = '',
    sources = [],
    history = []
  }) {
    if (!this.isValidTask(type)) {
      throw new Error(`Unsupported Copilot task: "${type}". Supported: ${PromptBuilder.SUPPORTED_TASKS.join(', ')}`);
    }

    const taskInstructions = {
      explain_alert: 'Analyze the given alert: explain the underlying security anomaly, potential adversary objectives, and threat severity.',
      explain_incident: 'Explain the incident timeline, scope of affected assets, correlated events, and tactical significance.',
      explain_attack_chain: 'Summarize the multi-stage attack sequence across the kill chain, showing progression from initial access to objective.',
      summarize_threat_intel: 'Synthesize threat intelligence findings, active threat actors, campaign indicators, and organizational risk level.',
      summarize_ioc: 'Summarize the provided Indicator of Compromise (IOC), sighting history, malware association, and threat reputation.',
      recommend_playbook: 'Recommend the most appropriate SOAR response playbook(s) from the available playbooks to handle the threat scenario, explaining why.',
      investigation_steps: 'Provide prioritized, actionable triage and investigation steps for the SOC analyst to verify and scope the activity.',
      generate_analyst_note: 'Draft an executive-ready SOC analyst shift handover note summarizing the key findings, triage status, and next steps.',
      soc_search: 'Execute structured SOC entity search based on natural language query and summarize findings.',
      explain_mitre: 'Explain MITRE ATT&CK technique mapping, tactic placement, technical indicators, and evidence rationale.',
      session_chat: 'Conduct multi-turn interactive investigation conversation with the SOC analyst, maintaining context.'
    };

    const taskGoal = taskInstructions[type] || 'Provide cybersecurity analysis.';

    let historySection = '';
    if (Array.isArray(history) && history.length > 0) {
      const historyLines = history.slice(-10).map(m => `${m.role === 'user' ? 'Analyst' : 'Copilot'}: ${m.content}`).join('\n');
      historySection = `\n### RECENT INVESTIGATION HISTORY:\n${historyLines}\n`;
    }

    const userPrompt = `### TASK: ${type.toUpperCase()}
Goal: ${taskGoal}
Target Entity ID: ${entity_id || 'Not specified'}
Analyst Question: ${question || 'Provide standard security assessment.'}
${historySection}
### PROVIDED CONTEXT:
${contextText}

### INSTRUCTIONS FOR RESPONSE:
- Provide a clear, professional SOC analyst response answering the question using ONLY the provided context.
- Ground all facts in the context.
- If relevant context is missing, note it explicitly.
- Formulate concrete recommendations where applicable.`;

    return {
      systemInstruction: PromptBuilder.SYSTEM_PROMPT,
      userPrompt
    };
  }
}

const promptBuilder = new PromptBuilder();
module.exports = promptBuilder;
