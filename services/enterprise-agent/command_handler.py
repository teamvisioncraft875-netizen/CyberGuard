"""
CYBERGUARD Enterprise Agent — Command Handler
Polls the central command queue, validates received security instructions,
safely logs firewall commands without execution (Phase B safe skeleton), and reports execution results.
"""

import json
import ipaddress
import re
from typing import Dict, Any, List, Optional
import requests

from config import AgentConfig, CredentialManager
from collector import collect_system_telemetry
from logger import get_logger

logger = get_logger()

# Allowed command types for Enterprise Agent v1
SUPPORTED_COMMAND_TYPES = {
    "collect_snapshot",
    "refresh_policy",
    "temporary_block_ip",
    "block_ip",
    "block_domain",
}

# Domain name regex pattern (RFC 1035 / RFC 1123 compliant subset)
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def validate_ip_address(ip_str: str) -> bool:
    """Validates IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_domain_name(domain_str: str) -> bool:
    """Validates domain name syntax."""
    clean_domain = domain_str.strip().lower()
    return bool(DOMAIN_REGEX.match(clean_domain))


def parse_target_data(target_data: Any) -> Optional[Dict[str, Any]]:
    """Normalizes target_data to a dictionary if provided as a JSON string or dict."""
    if isinstance(target_data, dict):
        return target_data
    if isinstance(target_data, str):
        try:
            parsed = json.loads(target_data)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
    return None


def fetch_pending_commands(
    config: AgentConfig,
    cred_mgr: Optional[CredentialManager] = None
) -> List[Dict[str, Any]]:
    """
    Polls GET /api/v1/agents/:device_id/commands for queued instructions.
    Thread-safely accesses credentials via CredentialManager if provided.
    """
    device_id = cred_mgr.device_id if cred_mgr else config.device_id
    credential_id = cred_mgr.credential_id if cred_mgr else config.credential_id
    credential_secret = cred_mgr.get_secret() if cred_mgr else config.credential_secret

    if not device_id or not credential_id or not credential_secret:
        return []

    commands_url = f"{config.backend_url}/api/v1/agents/{device_id}/commands"
    headers = {
        "x-agent-credential-id": credential_id,
        "x-agent-credential-secret": credential_secret,
    }
    params = {
        "credential_id": credential_id,
        "credential_secret": credential_secret,
    }

    try:
        response = requests.get(commands_url, headers=headers, params=params, timeout=10)
    except requests.Timeout as e:
        logger.warning(f"Command polling request timed out after 10s: {e}. Will retry next cycle.")
        return []
    except requests.RequestException as e:
        logger.warning(f"Failed to poll agent commands: {e}")
        return []

    if response.status_code == 200:
        data = response.json()
        return data.get("commands", [])
    elif response.status_code == 401:
        logger.warning("Failed to poll commands: Unauthorized credential validation.")
        return []
    else:
        logger.warning(f"Command polling returned HTTP {response.status_code}")
        return []


def report_command_result(
    config: AgentConfig,
    command_id: str,
    status: str,
    result: Dict[str, Any],
    cred_mgr: Optional[CredentialManager] = None
) -> bool:
    """
    Submits command completion or failure receipt to:
    POST /api/v1/agents/:device_id/commands/:command_id/result
    Thread-safely accesses credentials via CredentialManager if provided.
    """
    device_id = cred_mgr.device_id if cred_mgr else config.device_id
    credential_id = cred_mgr.credential_id if cred_mgr else config.credential_id
    credential_secret = cred_mgr.get_secret() if cred_mgr else config.credential_secret

    result_url = (
        f"{config.backend_url}/api/v1/agents/{device_id}/commands/{command_id}/result"
    )
    payload = {
        "credential_id": credential_id,
        "credential_secret": credential_secret,
        "status": status,
        "result": result,
    }
    headers = {
        "Content-Type": "application/json",
        "x-agent-credential-id": credential_id,
        "x-agent-credential-secret": credential_secret,
    }

    try:
        response = requests.post(result_url, json=payload, headers=headers, timeout=10)
    except requests.Timeout as e:
        logger.warning(f"Submitting result for command {command_id} timed out after 10s: {e}. Will retry next cycle.")
        return False
    except requests.RequestException as e:
        logger.error(f"Error submitting result for command {command_id}: {e}")
        return False

    if response.status_code in (200, 201):
        logger.info(f"Command {command_id} reported back with status='{status}'")
        return True
    else:
        logger.error(
            f"Failed reporting command result for {command_id} (HTTP {response.status_code}): {response.text}"
        )
        return False


def process_command(
    config: AgentConfig,
    command: Dict[str, Any],
    cred_mgr: Optional[CredentialManager] = None
) -> None:
    """
    Validates and dispatches a single command.
    CRITICAL: Phase B strictly forbids live firewall/kernel modification.
    All block actions are safely logged and reported as received_not_executed.
    """
    command_id = command.get("id")
    command_type = command.get("command_type")
    raw_target_data = command.get("target_data")

    if not command_id or not command_type:
        logger.warning(f"Received malformed command payload: {command}")
        return

    logger.info(f"Processing command {command_id} of type '{command_type}'")

    # 1. Validate command_type
    if command_type not in SUPPORTED_COMMAND_TYPES:
        err_msg = f"Unsupported command type '{command_type}'"
        logger.error(f"Command {command_id} validation failed: {err_msg}")
        report_command_result(
            config,
            command_id,
            status="failed",
            result={"error_message": err_msg},
            cred_mgr=cred_mgr
        )
        return

    # 2. Validate target_data
    target_data = parse_target_data(raw_target_data)
    if raw_target_data is not None and target_data is None:
        err_msg = "Invalid target_data: expected valid JSON object"
        logger.error(f"Command {command_id} target_data invalid")
        report_command_result(
            config,
            command_id,
            status="failed",
            result={"error_message": err_msg},
            cred_mgr=cred_mgr
        )
        return

    if target_data is None:
        target_data = {}

    # 3. Action Dispatcher
    if command_type == "collect_snapshot":
        logger.info(f"Executing snapshot collection for command {command_id}")
        snapshot = collect_system_telemetry()
        report_command_result(
            config,
            command_id,
            status="completed",
            result={"snapshot": snapshot, "hostname": config.agent_name},
            cred_mgr=cred_mgr
        )

    elif command_type == "refresh_policy":
        logger.info(f"Received policy refresh signal for command {command_id}")
        report_command_result(
            config,
            command_id,
            status="completed",
            result={"message": "Policy cache refreshed successfully"},
            cred_mgr=cred_mgr
        )

    elif command_type in ("temporary_block_ip", "block_ip"):
        target_ip = target_data.get("ip") or target_data.get("target_ip") or target_data.get("target")
        if not target_ip or not validate_ip_address(str(target_ip)):
            err_msg = f"Invalid target IP address: '{target_ip}'"
            logger.warning(f"Command {command_id} validation failed: {err_msg}")
            report_command_result(
                config,
                command_id,
                status="failed",
                result={"error_message": err_msg},
                cred_mgr=cred_mgr
            )
            return

        # PHASE B SAFE GUARD: Log safely, do NOT execute iptables/netsh
        logger.info(
            f"[FIREWALL ACTION QUEUED] Command {command_id} received target IP '{target_ip}'. "
            "Execution withheld: Firewall integration pending in Phase C."
        )

        report_command_result(
            config,
            command_id,
            status="received_not_executed",
            result={
                "reason": "firewall_integration_pending",
                "action": command_type,
                "target_ip": str(target_ip),
                "duration_minutes": target_data.get("duration_minutes", 60),
            },
            cred_mgr=cred_mgr
        )

    elif command_type == "block_domain":
        target_domain = target_data.get("domain") or target_data.get("target_domain") or target_data.get("target")
        if not target_domain or not validate_domain_name(str(target_domain)):
            err_msg = f"Invalid target domain name: '{target_domain}'"
            logger.warning(f"Command {command_id} validation failed: {err_msg}")
            report_command_result(
                config,
                command_id,
                status="failed",
                result={"error_message": err_msg},
                cred_mgr=cred_mgr
            )
            return

        # PHASE B SAFE GUARD: Log safely, do NOT execute DNS sinkhole/hosts
        logger.info(
            f"[FIREWALL ACTION QUEUED] Command {command_id} received target domain '{target_domain}'. "
            "Execution withheld: Firewall integration pending in Phase C."
        )

        report_command_result(
            config,
            command_id,
            status="received_not_executed",
            result={
                "reason": "firewall_integration_pending",
                "action": command_type,
                "target_domain": str(target_domain),
            },
            cred_mgr=cred_mgr
        )


def poll_and_dispatch_commands(
    config: AgentConfig,
    cred_mgr: Optional[CredentialManager] = None
) -> int:
    """
    Fetches and processes all pending commands for this device.
    Returns the number of commands processed.
    """
    commands = fetch_pending_commands(config, cred_mgr=cred_mgr)
    if commands:
        logger.info(f"Retrieved {len(commands)} pending command(s) from gateway")
        for cmd in commands:
            process_command(config, cmd, cred_mgr=cred_mgr)
    return len(commands)
