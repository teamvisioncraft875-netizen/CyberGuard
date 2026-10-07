const auditService = require('../auditService');

/**
 * Command Planner Service — Converts extracted intents and cybersecurity entities
 * into an ordered, executable multi-step action plan with risk assessments and gating flags.
 */
class CommandPlannerService {
  constructor() {
    this.HIGH_RISK_ACTIONS = [
      'isolate_endpoint',
      'disable_account',
      'block_ip',
      'block_domain'
    ];
  }

  /**
   * Generates an actionable execution plan from intent and entity context.
   *
   * @param {Object} params
   * @param {string} params.intent - Primary intent
   * @param {string[]} [params.intents] - Array of detected sequential intents
   * @param {Object} params.entities - Extracted entities
   * @param {string} [params.raw_command] - Original instruction
   * @param {string} [params.organization_id]
   * @param {string} [params.actor_id]
   * @param {Object} [params.context] - Session or runtime context
   * @returns {Promise<{ plan: Array<Object>, summary: string }>}
   */
  async createPlan({
    intent,
    intents = [],
    entities = {},
    raw_command = '',
    organization_id = null,
    actor_id = null,
    context = {}
  }) {
    const targetIntents = Array.isArray(intents) && intents.length > 0 ? intents : [intent];
    const steps = [];

    let stepNum = 1;
    for (const curIntent of targetIntents) {
      if (!curIntent || curIntent === 'unknown') continue;

      const step = this._buildPlanStep(curIntent, entities, context, stepNum++);
      if (step) {
        steps.push(step);
      }
    }

    const summary = steps.length === 1
      ? `Single-step plan: ${steps[0].action}`
      : `Multi-step plan with ${steps.length} sequential operations: ${steps.map(s => s.action).join(' -> ')}`;

    // Audit Logging if organization_id is provided
    if (organization_id) {
      await auditService.log({
        organization_id,
        actor_id,
        action: 'COPILOT_PLAN_GENERATED',
        resource_type: 'copilot_plan',
        resource_id: `plan_${Date.now()}`,
        details: {
          raw_command: (raw_command || '').slice(0, 150),
          step_count: steps.length,
          actions: steps.map(s => s.action),
          requires_approval: steps.some(s => s.requires_approval)
        }
      }).catch(err => console.error('[CommandPlannerService] Audit log error:', err.message));
    }

    return {
      plan: steps,
      summary
    };
  }

  /**
   * Internal mapper from intent to structured step definition.
   */
  _buildPlanStep(intent, entities = {}, context = {}, stepIndex = 1) {
    const host = entities.host || context.host || 'unknown_host';
    const ip = entities.ipv4 || entities.ipv6 || context.ip || '198.51.100.25';
    const domain = entities.domain || entities.url || context.domain || 'malicious-domain.com';
    const user = entities.username || entities.email || context.user || 'compromised_user';
    const caseId = entities.case_id || context.case_id || null;
    const alertId = entities.alert_id || context.alert_id || null;
    const mitre = entities.mitre_technique || context.mitre_technique || 'T1000';

    switch (intent) {
      case 'isolate_endpoint':
        return {
          step: stepIndex,
          action: 'isolate_endpoint',
          payload: { host, reason: 'Quarantining host due to verified compromise' },
          requires_approval: true,
          risk_level: 'critical',
          reason: `Isolate host ${host} to sever network communications and contain lateral spread.`,
          mitre_mapping: mitre,
          evidence: `Observed anomalous activity or credential abuse on host ${host}.`
        };

      case 'block_ip':
        return {
          step: stepIndex,
          action: 'block_ip',
          payload: { ip, reason: 'Dropping perimeter traffic from suspicious indicator' },
          requires_approval: true,
          risk_level: 'high',
          reason: `Provision firewall rule to block all inbound and outbound traffic with IP ${ip}.`,
          mitre_mapping: mitre !== 'T1000' ? mitre : 'T1071',
          evidence: `Network connections identified communicating with external address ${ip}.`
        };

      case 'block_domain':
        return {
          step: stepIndex,
          action: 'block_domain',
          payload: { domain, reason: 'Sinkholing malicious domain' },
          requires_approval: true,
          risk_level: 'high',
          reason: `Sinkhole domain ${domain} to prevent command and control callbacks.`,
          mitre_mapping: 'T1071.001',
          evidence: `DNS lookups identified targeting ${domain}.`
        };

      case 'disable_account':
        return {
          step: stepIndex,
          action: 'disable_account',
          payload: { user, reason: 'Compromised identity lockout' },
          requires_approval: true,
          risk_level: 'high',
          reason: `Temporarily lock account ${user} to revoke active sessions and Kerberos tickets.`,
          mitre_mapping: mitre !== 'T1000' ? mitre : 'T1078',
          evidence: `Suspicious privilege usage or brute force targeting account ${user}.`
        };

      case 'create_case':
        return {
          step: stepIndex,
          action: 'create_soar_case',
          payload: {
            title: `SOAR Case: ${alertId ? `Alert ${alertId}` : 'Incident Investigation'}`,
            description: 'Created via Copilot natural language command',
            severity: 'high',
            alert_id: alertId
          },
          requires_approval: false,
          risk_level: 'low',
          reason: `Initialize new SOAR incident investigation case with attached evidence.`,
          mitre_mapping: mitre,
          evidence: `Initiated by analyst triage command.`
        };

      case 'escalate_case':
        return {
          step: stepIndex,
          action: 'escalate_case',
          payload: { case_id: caseId, priority: 'critical', severity: 'critical' },
          requires_approval: false,
          risk_level: 'medium',
          reason: `Escalate case ${caseId || 'current'} to critical priority for Senior SOC review.`,
          mitre_mapping: mitre,
          evidence: `Analyst requested priority elevation.`
        };

      case 'execute_playbook':
        return {
          step: stepIndex,
          action: 'launch_playbook',
          payload: {
            playbook_name: entities.playbook_name || 'Automated Response Playbook',
            case_id: caseId,
            alert_id: alertId
          },
          requires_approval: false,
          risk_level: 'medium',
          reason: `Execute playbook "${entities.playbook_name || 'Incident Response'}" against target case.`,
          mitre_mapping: mitre,
          evidence: `Matched automated runbook procedures.`
        };

      case 'create_jira_ticket':
        return {
          step: stepIndex,
          action: 'create_jira_ticket',
          payload: {
            title: `Security Case ${caseId || alertId || 'Triage'} Escalation`,
            priority: 'High',
            case_id: caseId
          },
          requires_approval: false,
          risk_level: 'low',
          reason: `File Jira engineering tracking ticket for external follow-up.`,
          mitre_mapping: mitre,
          evidence: `Case ${caseId || 'evidence'} attached.`
        };

      case 'send_slack_message':
        return {
          step: stepIndex,
          action: 'send_slack_message',
          payload: {
            channel: '#soc-alerts',
            message: `[SOC ALERT] Incident update for Case ${caseId || alertId || 'Event'}`
          },
          requires_approval: false,
          risk_level: 'low',
          reason: `Broadcast automated notification to SOC Slack channel.`,
          mitre_mapping: mitre,
          evidence: `Security event summary payload.`
        };

      case 'send_teams_message':
        return {
          step: stepIndex,
          action: 'send_teams_message',
          payload: {
            channel: 'General',
            message: `[SOC ALERT] Incident update for Case ${caseId || alertId || 'Event'}`
          },
          requires_approval: false,
          risk_level: 'low',
          reason: `Broadcast automated notification to Microsoft Teams channel.`,
          mitre_mapping: mitre,
          evidence: `Security event summary payload.`
        };

      case 'create_approval':
        return {
          step: stepIndex,
          action: 'create_approval',
          payload: {
            reason: 'Supervisor approval requested for operational containment',
            level: 'L1'
          },
          requires_approval: false,
          risk_level: 'low',
          reason: `Submit human-in-the-loop authorization request to SOC supervisor.`,
          mitre_mapping: mitre,
          evidence: `Pending high-impact operational action.`
        };

      default:
        return {
          step: stepIndex,
          action: intent,
          payload: { ...entities },
          requires_approval: this.HIGH_RISK_ACTIONS.includes(intent),
          risk_level: this.HIGH_RISK_ACTIONS.includes(intent) ? 'high' : 'low',
          reason: `Execute SOC action ${intent}.`,
          mitre_mapping: mitre,
          evidence: `Command invocation.`
        };
    }
  }
}

const commandPlannerService = new CommandPlannerService();
module.exports = commandPlannerService;
