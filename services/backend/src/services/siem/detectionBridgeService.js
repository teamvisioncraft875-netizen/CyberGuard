const { persistDetectionIncident } = require('../incidentService');

/**
 * Detection Bridge Service — Bridges normalized SIEM events into the core CYBERGUARD
 * detection, deduplication, correlation, and SOC prioritization pipeline.
 */

/**
 * Evaluates whether a normalized security event constitutes an actionable security incident.
 * Returns threat metadata if a rule triggers, or null if benign/informational.
 */
function evaluateDetectionRules(normalizedEvent) {
  const { event_type, severity, normalized_data = {} } = normalizedEvent;
  const {
    action,
    target_user,
    target_host,
    source_ip,
    dest_ip,
    dest_port,
    process_name,
    command_line,
    parent_process_name,
    file_path,
    registry_key,
    details = {}
  } = normalized_data;

  // RULE 1: Windows 1102 — Defense Evasion / Audit Log Cleared
  if (event_type === 'windows_audit_log_cleared' || action === 'audit_log_cleared') {
    return {
      triggered: true,
      threatType: 'technical_threat',
      riskLevel: 'critical',
      riskScore: 95,
      ruleId: 'SIEM-DEF-1102',
      mitreTechnique: 'T1070',
      explanation: `Security audit log was cleared on host ${target_host || 'unknown'} by user ${target_user || 'unknown'}. High indicator of adversary defense evasion.`,
      signals: {
        event_id: '1102',
        source_ip: source_ip || null,
        target_user: target_user || null,
        target_host: target_host || null,
        action: 'audit_log_cleared'
      },
      recommendedActions: [
        'Isolate compromised workstation from the internal network immediately',
        'Revoke active session tokens for the initiating user account',
        'Verify backup retention and export audit logs from secondary SIEM mirror'
      ]
    };
  }

  // RULE 2: Windows 4732 / Linux Escalation — Privilege Escalation
  if (
    (event_type === 'windows_local_group_member_added' && severity === 'high') ||
    event_type === 'linux_privilege_escalation' ||
    action === 'privilege_escalation'
  ) {
    return {
      triggered: true,
      threatType: 'account_takeover',
      riskLevel: 'critical',
      riskScore: 90,
      ruleId: 'SIEM-PRV-ESCALATION',
      mitreTechnique: 'TA0004',
      explanation: `Unauthorized privilege escalation detected: user ${target_user || 'unknown'} gained elevated administrative privileges on ${target_host || 'unknown'}.`,
      signals: {
        target_user: target_user || null,
        target_host: target_host || null,
        source_ip: source_ip || null,
        group_name: details.group_name || null,
        action: 'privilege_escalation'
      },
      recommendedActions: [
        'Audit recent administrative group additions and remove unauthorized account',
        'Force multi-factor re-authentication across all privileged identities',
        'Review PowerShell and bash history on the affected host'
      ]
    };
  }

  // RULE 3: Brute Force / Authentication Attacks (Windows 4625 or Linux failed login)
  if (
    event_type === 'windows_logon_failure' ||
    event_type === 'linux_failed_login' ||
    action === 'login_failure'
  ) {
    return {
      triggered: true,
      threatType: 'account_takeover',
      riskLevel: 'high',
      riskScore: 78,
      ruleId: 'SIEM-AUTH-BRUTE',
      mitreTechnique: 'T1110',
      explanation: `Authentication failure detected for account ${target_user || 'unknown'} from source IP ${source_ip || 'unknown'}. Potential credential stuffing or brute-force attack.`,
      signals: {
        source_ip: source_ip || null,
        ip_address: source_ip || null,
        target_user: target_user || null,
        failure_reason: details.failure_reason || null,
        action: 'login_failure'
      },
      recommendedActions: [
        'Temporarily lock affected user account pending identity verification',
        'Apply automated IP rate-limiting and firewall drop rule on source IP',
        'Review authentication logs for lateral spray patterns across other accounts'
      ]
    };
  }

  // RULE 4: Sysmon Malicious Process / Ransomware / LOLBin Execution
  if (
    event_type === 'sysmon_process_creation' &&
    (severity === 'high' || severity === 'critical')
  ) {
    return {
      triggered: true,
      threatType: 'technical_threat',
      riskLevel: 'critical',
      riskScore: 92,
      ruleId: 'SIEM-PROC-SUSP',
      mitreTechnique: 'TA0002',
      explanation: `Suspicious high-risk binary or script executed: ${process_name || 'unknown process'} with command: ${command_line || 'unknown'}.`,
      signals: {
        process_name: process_name || null,
        command_line: command_line || null,
        parent_process_name: parentProcessName || null,
        source_ip: source_ip || null,
        target_user: target_user || null,
        target_host: target_host || null
      },
      recommendedActions: [
        'Terminate suspicious process tree on target device',
        'Quarantine executable and extract SHA-256 for threat intel lookup',
        'Check Volume Shadow Copies for ransomware tamper attempts'
      ]
    };
  }

  // RULE 5: Suspicious Network Connection / C2 Beaconing (Sysmon Event 3)
  if (
    event_type === 'sysmon_network_connection' &&
    (severity === 'high' || [4444, 1337, 8888, 3389].includes(dest_port))
  ) {
    return {
      triggered: true,
      threatType: 'technical_threat',
      riskLevel: 'high',
      riskScore: 82,
      ruleId: 'SIEM-NET-C2',
      mitreTechnique: 'TA0011',
      explanation: `Anomalous outbound network connection initiated to ${dest_ip}:${dest_port} by process ${process_name || 'unknown'}. Potential command & control beaconing.`,
      signals: {
        source_ip: source_ip || null,
        dest_ip: dest_ip || null,
        dest_port: dest_port ? String(dest_port) : null,
        process_name: process_name || null,
        ip_address: dest_ip || null
      },
      recommendedActions: [
        'Block egress traffic to destination IP at perimeter firewall',
        'Inspect DNS request logs for domain generation algorithm (DGA) signatures',
        'Capture network packet trace from endpoint for protocol anomaly analysis'
      ]
    };
  }

  // RULE 6: High-Risk Linux Sudo Command
  if (event_type === 'linux_sudo_command' && severity === 'high') {
    return {
      triggered: true,
      threatType: 'technical_threat',
      riskLevel: 'high',
      riskScore: 80,
      ruleId: 'SIEM-LIN-SUDO',
      mitreTechnique: 'T1548',
      explanation: `Privileged sudo execution of sensitive system modification: ${command_line || 'unknown'} by user ${target_user || 'unknown'}.`,
      signals: {
        target_user: target_user || null,
        command_line: command_line || null,
        action: 'sudo_exec'
      },
      recommendedActions: [
        'Audit sudoers configuration and verify user authorization',
        'Verify integrity of /etc/shadow and /etc/passwd files'
      ]
    };
  }

  // Default: Informational or low-risk events do not trigger automated incidents
  return null;
}

const DetectionBridgeService = {
  /**
   * Evaluates a single normalized event and routes it to the incident pipeline if a threat is matched.
   */
  async processEvent(normalizedEvent, organizationId, client = null) {
    if (!normalizedEvent || !organizationId) return null;

    const evaluation = evaluateDetectionRules(normalizedEvent);
    if (!evaluation || !evaluation.triggered) {
      return null;
    }

    const {
      threatType,
      riskLevel,
      riskScore,
      ruleId,
      explanation,
      signals,
      recommendedActions
    } = evaluation;

    const userObj = {
      id: normalizedEvent.user_id || null,
      organization_id: organizationId,
      role: 'analyst',
      device_id: normalizedEvent.device_id || null
    };

    const incidentPayload = {
      user: userObj,
      threatType,
      sourceType: 'siem',
      deviceId: normalizedEvent.device_id || null,
      mlResult: {
        risk_level: riskLevel,
        risk_score: riskScore,
        explanation,
        signals: {
          ...signals,
          event_type: normalizedEvent.event_type,
          source_type: normalizedEvent.source_type,
          siem_event_id: normalizedEvent.event_id
        },
        details: {
          rule_id: ruleId,
          siem_event_id: normalizedEvent.event_id,
          event_type: normalizedEvent.event_type,
          source_type: normalizedEvent.source_type,
          ...normalizedEvent.normalized_data
        }
      },
      recommendedActions: recommendedActions || []
    };

    // Feeds directly into existing incident pipeline (Task 1 dedup -> Task 2 correlation -> Task 3 groups -> Task 4 attack chain -> SOC triage)
    const incident = await persistDetectionIncident(incidentPayload, client);
    return {
      incident,
      rule_id: ruleId,
      threat_type: threatType,
      risk_score: riskScore
    };
  },

  /**
   * Processes a batch of normalized events through the detection bridge.
   */
  async processBatch(normalizedEvents, organizationId, client = null) {
    if (!Array.isArray(normalizedEvents) || normalizedEvents.length === 0) {
      return [];
    }

    const detectedIncidents = [];
    for (const ev of normalizedEvents) {
      try {
        const result = await this.processEvent(ev, organizationId, client);
        if (result) {
          detectedIncidents.push(result);
        }
      } catch (err) {
        console.warn('[DetectionBridge Warning] Error processing event into incident pipeline:', err.message);
      }
    }

    return detectedIncidents;
  },

  evaluateDetectionRules
};

module.exports = DetectionBridgeService;
