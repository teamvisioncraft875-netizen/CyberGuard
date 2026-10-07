const crypto = require('crypto');

/**
 * Normalization Service — Unified Event Schema normalizer
 * Supports Windows Event Logs, Sysmon Events, and Linux Syslog formats.
 */

/**
 * Extracts a deterministic or provided unique event ID.
 */
function extractEventId(raw) {
  if (raw.event_id || raw.EventId || raw.EventID || raw.id) {
    return String(raw.event_id || raw.EventId || raw.EventID || raw.id);
  }
  const content = typeof raw === 'string' ? raw : JSON.stringify(raw);
  return `ev_${crypto.createHash('sha256').update(content).digest('hex').slice(0, 16)}`;
}

/**
 * Extracts a valid ISO timestamp from raw inputs.
 */
function extractTimestamp(raw) {
  const ts = raw.timestamp || raw.event_timestamp || raw.TimeCreated || raw.UtcTime || raw.date || raw.time;
  if (ts) {
    const parsed = new Date(ts);
    if (!isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return new Date().toISOString();
}

/**
 * Extracts file base name from a path.
 */
function extractFileName(fullPath) {
  if (!fullPath || typeof fullPath !== 'string') return null;
  const parts = fullPath.split(/[\\/]/);
  return parts[parts.length - 1] || null;
}

// =========================================================================
// WINDOWS EVENT LOG NORMALIZER
// =========================================================================
function normalizeWindowsEvent(raw) {
  const eventIdStr = String(raw.EventID || raw.event_id || raw.EventId || raw.Id || '').trim();
  const eventData = raw.EventData || raw.event_data || raw;

  let eventType = `windows_${eventIdStr || 'unknown'}`;
  let severity = 'info';
  let action = 'windows_event';
  let status = 'unknown';
  let targetUser = eventData.TargetUserName || eventData.TargetUser || eventData.SubjectUserName || null;
  let targetHost = eventData.WorkstationName || eventData.Computer || raw.Computer || null;
  let sourceIp = eventData.IpAddress || eventData.SourceNetworkAddress || eventData.IpPort ? eventData.IpAddress : null;
  let commandLine = null;
  let details = { event_id: eventIdStr, ...eventData };

  switch (eventIdStr) {
    case '4624':
      eventType = 'windows_logon_success';
      severity = 'info';
      action = 'logon_success';
      status = 'success';
      targetUser = eventData.TargetUserName || targetUser;
      sourceIp = eventData.IpAddress !== '-' ? eventData.IpAddress : null;
      details.logon_type = eventData.LogonType;
      break;

    case '4625':
      eventType = 'windows_logon_failure';
      severity = 'medium';
      action = 'logon_failure';
      status = 'failure';
      targetUser = eventData.TargetUserName || targetUser;
      sourceIp = eventData.IpAddress !== '-' ? eventData.IpAddress : null;
      details.failure_reason = eventData.SubStatus || eventData.Status;
      details.logon_type = eventData.LogonType;
      break;

    case '4720':
      eventType = 'windows_user_created';
      severity = 'medium';
      action = 'user_created';
      status = 'success';
      targetUser = eventData.TargetUserName || targetUser;
      details.created_by = eventData.SubjectUserName;
      break;

    case '4728':
      eventType = 'windows_group_member_added';
      severity = 'medium';
      action = 'group_member_added';
      status = 'success';
      details.group_name = eventData.TargetUserName;
      details.member_name = eventData.MemberName;
      details.added_by = eventData.SubjectUserName;
      break;

    case '4732': {
      eventType = 'windows_local_group_member_added';
      const groupName = String(eventData.TargetUserName || '').toLowerCase();
      // Elevated privilege detection for Administrator/Administrators
      severity = groupName.includes('admin') ? 'high' : 'medium';
      action = 'local_group_member_added';
      status = 'success';
      details.group_name = eventData.TargetUserName;
      details.member_name = eventData.MemberName;
      details.added_by = eventData.SubjectUserName;
      break;
    }

    case '1102':
      eventType = 'windows_audit_log_cleared';
      severity = 'critical';
      action = 'audit_log_cleared';
      status = 'success';
      targetUser = eventData.SubjectUserName || targetUser;
      details.cleared_by = eventData.SubjectUserName;
      break;

    default:
      if (raw.severity) severity = raw.severity;
      break;
  }

  return {
    source_type: 'windows',
    event_type: eventType,
    severity,
    action,
    target_user: targetUser,
    target_host: targetHost,
    source_ip: sourceIp,
    dest_ip: null,
    dest_port: null,
    process_name: null,
    process_path: null,
    command_line: commandLine,
    parent_process_name: null,
    file_path: null,
    registry_key: null,
    registry_value: null,
    status,
    details
  };
}

// =========================================================================
// SYSMON EVENT NORMALIZER
// =========================================================================
function normalizeSysmonEvent(raw) {
  const eventIdStr = String(raw.EventID || raw.event_id || raw.EventId || raw.Id || '').trim();
  const eventData = raw.EventData || raw.event_data || raw;

  let eventType = `sysmon_event_${eventIdStr || 'unknown'}`;
  let severity = 'info';
  let action = 'sysmon_event';
  let status = 'success';
  let sourceIp = null;
  let destIp = null;
  let destPort = null;
  let processName = null;
  let processPath = null;
  let commandLine = null;
  let parentProcessName = null;
  let filePath = null;
  let registryKey = null;
  let registryValue = null;
  let targetUser = eventData.User || raw.User || null;
  let targetHost = raw.Computer || null;
  let details = { event_id: eventIdStr, ...eventData };

  switch (eventIdStr) {
    case '1': // Process Creation
      eventType = 'sysmon_process_creation';
      action = 'process_create';
      processPath = eventData.Image || null;
      processName = extractFileName(processPath);
      commandLine = eventData.CommandLine || null;
      parentProcessName = extractFileName(eventData.ParentImage);
      targetUser = eventData.User || targetUser;

      // Severity heuristic based on common attacker tools / lolbins
      const cmdLower = String(commandLine || '').toLowerCase();
      const procLower = String(processName || '').toLowerCase();
      if (
        procLower.includes('vssadmin') ||
        cmdLower.includes('delete shadows') ||
        cmdLower.includes('bypass') ||
        cmdLower.includes('mimikatz') ||
        cmdLower.includes('downloadstring') ||
        procLower.includes('certutil') && cmdLower.includes('-urlcache')
      ) {
        severity = 'high';
      } else if (['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'].includes(procLower)) {
        severity = 'medium';
      } else {
        severity = 'low';
      }
      break;

    case '3': // Network Connection
      eventType = 'sysmon_network_connection';
      action = 'network_connect';
      processPath = eventData.Image || null;
      processName = extractFileName(processPath);
      sourceIp = eventData.SourceIp || null;
      destIp = eventData.DestinationIp || null;
      destPort = eventData.DestinationPort ? parseInt(eventData.DestinationPort, 10) : null;
      severity = (destPort === 4444 || destPort === 1337 || destPort === 8888 || destPort === 3389) ? 'high' : 'low';
      details.protocol = eventData.Protocol;
      break;

    case '11': // File Create
      eventType = 'sysmon_file_create';
      action = 'file_create';
      processPath = eventData.Image || null;
      processName = extractFileName(processPath);
      filePath = eventData.TargetFilename || null;
      const fileLower = String(filePath || '').toLowerCase();
      if (fileLower.endsWith('.locked') || fileLower.endsWith('.crypto') || fileLower.includes('ransom')) {
        severity = 'high';
      } else {
        severity = 'low';
      }
      break;

    case '12': // Registry Event (Object create and delete)
    case '13': // Registry Event (Value Set)
    case '14': // Registry Event (Key and Value Rename)
      eventType = 'sysmon_registry_change';
      action = 'registry_modify';
      processPath = eventData.Image || null;
      processName = extractFileName(processPath);
      registryKey = eventData.TargetObject || null;
      registryValue = eventData.Details || null;
      const regLower = String(registryKey || '').toLowerCase();
      if (regLower.includes('\\run\\') || regLower.includes('\\runonce\\') || regLower.includes('currentversion\\run')) {
        severity = 'high';
      } else {
        severity = 'low';
      }
      break;

    default:
      if (raw.severity) severity = raw.severity;
      break;
  }

  return {
    source_type: 'sysmon',
    event_type: eventType,
    severity,
    action,
    target_user: targetUser,
    target_host: targetHost,
    source_ip: sourceIp,
    dest_ip: destIp,
    dest_port: destPort,
    process_name: processName,
    process_path: processPath,
    command_line: commandLine,
    parent_process_name: parentProcessName,
    file_path: filePath,
    registry_key: registryKey,
    registry_value: registryValue,
    status,
    details
  };
}

// =========================================================================
// LINUX SYSLOG NORMALIZER
// =========================================================================
function normalizeLinuxSyslog(raw) {
  const message = typeof raw === 'string' ? raw : (raw.message || raw.raw_text || raw.log || JSON.stringify(raw));
  const rawObj = typeof raw === 'object' ? raw : {};

  let eventType = 'linux_syslog_generic';
  let severity = 'info';
  let action = 'syslog_event';
  let status = 'unknown';
  let targetUser = rawObj.user || null;
  let sourceIp = rawObj.ip || rawObj.source_ip || null;
  let destPort = null;
  let commandLine = null;
  let details = { message, ...rawObj };

  // 1. SSH Successful Login
  // e.g.: "Accepted publickey for root from 192.168.1.50 port 54321 ssh2"
  const sshAcceptedMatch = message.match(/Accepted\s+(?:publickey|password|keyboard-interactive)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F.:]+)(?:\s+port\s+(\d+))?/i);
  if (sshAcceptedMatch) {
    eventType = 'linux_ssh_login';
    severity = 'info';
    action = 'ssh_login';
    status = 'success';
    targetUser = sshAcceptedMatch[1];
    sourceIp = sshAcceptedMatch[2];
    destPort = sshAcceptedMatch[3] ? parseInt(sshAcceptedMatch[3], 10) : 22;
    if (targetUser === 'root') {
      severity = 'medium'; // Root SSH logins warrant scrutiny
    }
  }

  // 2. Failed Login / SSH Brute Force
  // e.g.: "Failed password for invalid user admin from 203.0.113.100 port 44321 ssh2"
  // or: "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.100  user=admin"
  const sshFailedMatch = message.match(/Failed\s+(?:password|none)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F.:]+)/i);
  const authFailMatch = message.match(/authentication failure;.*rhost=([0-9a-fA-F.:]+).*user=(\S+)/i);
  if (sshFailedMatch) {
    eventType = 'linux_failed_login';
    severity = 'medium';
    action = 'login_failure';
    status = 'failure';
    targetUser = sshFailedMatch[1];
    sourceIp = sshFailedMatch[2];
  } else if (authFailMatch) {
    eventType = 'linux_failed_login';
    severity = 'medium';
    action = 'login_failure';
    status = 'failure';
    sourceIp = authFailMatch[1];
    targetUser = authFailMatch[2];
  }

  // 3. sudo command execution
  // e.g.: "sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
  const sudoMatch = message.match(/sudo:\s+(\S+)\s+:\s+TTY=.*?;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/i);
  if (sudoMatch) {
    eventType = 'linux_sudo_command';
    action = 'sudo_exec';
    status = 'success';
    const executingUser = sudoMatch[1];
    const targetElevatedUser = sudoMatch[2];
    commandLine = sudoMatch[3]?.trim();
    targetUser = executingUser;
    details.elevated_target_user = targetElevatedUser;

    const cmdLower = (commandLine || '').toLowerCase();
    if (
      cmdLower.includes('/etc/shadow') ||
      cmdLower.includes('/etc/sudoers') ||
      cmdLower.includes('chmod 777') ||
      cmdLower.includes('nmap') ||
      cmdLower.includes('nc -e')
    ) {
      severity = 'high';
    } else {
      severity = 'low';
    }
  }

  // 4. Privilege Escalation (su, pkexec, dirty pipe, root session opened)
  // e.g.: "session opened for user root by analyst(uid=1001)"
  const suMatch = message.match(/session opened for user\s+(\S+)\s+by\s+(\S+)/i);
  const pkexecMatch = message.match(/pkexec.*executed.*by\s+(\S+)/i);
  if ((suMatch && suMatch[1] === 'root') || pkexecMatch || message.includes('dirtypipe') || message.includes('privilege escalation')) {
    eventType = 'linux_privilege_escalation';
    severity = 'high';
    action = 'privilege_escalation';
    status = 'success';
    if (suMatch) {
      details.escalated_to = suMatch[1];
      details.initiated_by = suMatch[2];
      targetUser = suMatch[2];
    }
  }

  return {
    source_type: 'linux_syslog',
    event_type: eventType,
    severity,
    action,
    target_user: targetUser,
    target_host: rawObj.host || rawObj.hostname || null,
    source_ip: sourceIp,
    dest_ip: null,
    dest_port: destPort,
    process_name: rawObj.program || rawObj.process || null,
    process_path: null,
    command_line: commandLine,
    parent_process_name: null,
    file_path: null,
    registry_key: null,
    registry_value: null,
    status,
    details
  };
}

// =========================================================================
// GENERIC / FALLBACK NORMALIZER
// =========================================================================
function normalizeGenericEvent(raw) {
  const rawObj = typeof raw === 'object' && raw !== null ? raw : { message: String(raw) };
  return {
    source_type: 'generic',
    event_type: rawObj.event_type || rawObj.type || 'generic_event',
    severity: rawObj.severity || 'info',
    action: rawObj.action || 'unknown',
    target_user: rawObj.user_id || rawObj.user || rawObj.username || null,
    target_host: rawObj.host || rawObj.hostname || null,
    source_ip: rawObj.source_ip || rawObj.ip || null,
    dest_ip: rawObj.dest_ip || null,
    dest_port: rawObj.dest_port || null,
    process_name: rawObj.process_name || rawObj.process || null,
    process_path: rawObj.process_path || null,
    command_line: rawObj.command_line || rawObj.cmd || null,
    parent_process_name: rawObj.parent_process || null,
    file_path: rawObj.file_path || rawObj.file || null,
    registry_key: rawObj.registry_key || null,
    registry_value: rawObj.registry_value || null,
    status: rawObj.status || 'unknown',
    details: rawObj
  };
}

// =========================================================================
// MAIN NORMALIZATION DISPATCHER
// =========================================================================
const NormalizationService = {
  /**
   * Transforms raw security event into the Unified Event Schema.
   */
  normalize(rawEvent, sourceTypeHint = null) {
    if (!rawEvent) {
      throw new Error('Normalization Error: rawEvent cannot be null or undefined');
    }

    const eventId = extractEventId(rawEvent);
    const timestamp = extractTimestamp(rawEvent);
    const userId = rawEvent.user_id || null;
    const deviceId = rawEvent.device_id || null;

    // Detect format / source type
    const sourceHint = (sourceTypeHint || rawEvent.source_type || rawEvent.SourceType || '').toLowerCase();
    const hasEventId = rawEvent.EventID !== undefined || rawEvent.EventId !== undefined;
    const isWindows = sourceHint === 'windows' || (hasEventId && (rawEvent.EventData || rawEvent.Channel));
    const isSysmon = sourceHint === 'sysmon' || (hasEventId && (rawEvent.Channel?.includes('Sysmon') || rawEvent.Source?.includes('Sysmon')));
    const isLinux = sourceHint === 'linux' || sourceHint === 'linux_syslog' || typeof rawEvent === 'string' || rawEvent.message;

    let normalizedCore;
    if (isSysmon) {
      normalizedCore = normalizeSysmonEvent(rawEvent);
    } else if (isWindows) {
      normalizedCore = normalizeWindowsEvent(rawEvent);
    } else if (isLinux && (typeof rawEvent === 'string' || rawEvent.message || sourceHint === 'linux_syslog')) {
      normalizedCore = normalizeLinuxSyslog(rawEvent);
    } else {
      normalizedCore = normalizeGenericEvent(rawEvent);
    }

    // Build Common Schema
    return {
      event_id: eventId,
      timestamp,
      source_type: normalizedCore.source_type,
      event_type: normalizedCore.event_type,
      severity: normalizedCore.severity,
      user_id: userId,
      device_id: deviceId,
      normalized_data: {
        action: normalizedCore.action,
        target_user: normalizedCore.target_user,
        target_host: normalizedCore.target_host,
        source_ip: normalizedCore.source_ip,
        dest_ip: normalizedCore.dest_ip,
        dest_port: normalizedCore.dest_port,
        process_name: normalizedCore.process_name,
        process_path: normalizedCore.process_path,
        command_line: normalizedCore.command_line,
        parent_process_name: normalizedCore.parent_process_name,
        file_path: normalizedCore.file_path,
        registry_key: normalizedCore.registry_key,
        registry_value: normalizedCore.registry_value,
        status: normalizedCore.status,
        details: normalizedCore.details
      }
    };
  },

  /**
   * Batch normalizes an array of raw events.
   */
  normalizeBatch(rawEvents, sourceTypeHint = null) {
    if (!Array.isArray(rawEvents)) return [];
    return rawEvents.map(ev => this.normalize(ev, sourceTypeHint));
  }
};

module.exports = NormalizationService;
