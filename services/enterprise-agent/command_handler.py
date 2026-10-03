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
    if clean_domain in ("localhost", "cyberguard.local"):
        return True
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
        "command_id": command_id,
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


# Cached protected targets list
_cached_protected_targets: Optional[Dict[str, Any]] = None


def fetch_protected_targets(
    config: AgentConfig,
    cred_mgr: Optional[CredentialManager] = None
) -> Dict[str, Any]:
    """
    Downloads safe target lists from GET /api/v1/agents/:device_id/protected-targets.
    Caches the list locally and falls back to safe built-in defaults if network call fails.
    """
    global _cached_protected_targets

    device_id = cred_mgr.device_id if cred_mgr else config.device_id
    if not device_id:
        return {
            "protected_ips": ["127.0.0.1", "0.0.0.0", "::1"],
            "protected_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
            "protected_domains": ["localhost", "cyberguard.local"]
        }

    url = f"{config.backend_url}/api/v1/agents/{device_id}/protected-targets"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            _cached_protected_targets = response.json()
            return _cached_protected_targets
    except Exception as e:
        logger.warning(f"Could not refresh protected targets list: {e}. Using cached/fallback defaults.")

    if _cached_protected_targets:
        return _cached_protected_targets

    return {
        "protected_ips": ["127.0.0.1", "0.0.0.0", "::1"],
        "protected_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
        "protected_domains": ["localhost", "cyberguard.local"]
    }


def is_ip_protected(ip_str: str, protected_targets: Dict[str, Any]) -> bool:
    """Checks whether an IP address is protected against blocking."""
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False

    # Check loopback, link-local, multicast, unspecified
    if (
        ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return True

    # Check static protected IPs list
    if clean_ip in protected_targets.get("protected_ips", []):
        return True

    # Check CIDR ranges (RFC 1918, 127/8, link-local, etc.)
    for cidr in protected_targets.get("protected_ip_ranges", []):
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue

    return False


def is_domain_protected(domain_str: str, protected_targets: Dict[str, Any]) -> bool:
    """Checks whether a domain name is protected against blocking."""
    clean_domain = domain_str.strip().lower().rstrip(".")
    if clean_domain in ("localhost", "cyberguard.local"):
        return True

    for prot in protected_targets.get("protected_domains", []):
        prot_lower = prot.strip().lower().rstrip(".")
        if clean_domain == prot_lower or clean_domain.endswith(f".{prot_lower}"):
            return True

    return False


from firewall_executor import FirewallExecutor, is_admin_windows, is_root_linux

# Default firewall executor singleton
_default_firewall_executor: Optional[FirewallExecutor] = None


def get_firewall_executor(
    protected_targets: Optional[Dict[str, Any]] = None,
    dry_run: bool = False
) -> FirewallExecutor:
    """Retrieves or lazily instantiates the default host firewall executor."""
    global _default_firewall_executor
    if _default_firewall_executor is None:
        _default_firewall_executor = FirewallExecutor(
            protected_targets=protected_targets,
            dry_run=dry_run
        )
    elif protected_targets:
        _default_firewall_executor.update_protected_targets(protected_targets)
    return _default_firewall_executor


def set_firewall_executor(executor: FirewallExecutor) -> None:
    """Overrides the default firewall executor instance (useful for testing and customization)."""
    global _default_firewall_executor
    _default_firewall_executor = executor


def process_command(
    config: AgentConfig,
    command: Dict[str, Any],
    cred_mgr: Optional[CredentialManager] = None,
    executor: Optional[FirewallExecutor] = None
) -> None:
    """
    Validates and dispatches a single command.
    Phase C.2: Dispatches block_ip / block_domain commands to host FirewallExecutor.
    Reports execution status back to the gateway.
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
            result={"error_message": err_msg, "error": "unsupported_command_type"},
            cred_mgr=cred_mgr
        )
        return

    # 2. Validate target_data structure
    target_data = parse_target_data(raw_target_data)
    if raw_target_data is not None and target_data is None:
        err_msg = "Invalid target_data: expected valid JSON object"
        logger.error(f"Command {command_id} target_data invalid")
        report_command_result(
            config,
            command_id,
            status="failed",
            result={"error_message": err_msg, "error": "invalid_payload"},
            cred_mgr=cred_mgr
        )
        return

    if target_data is None:
        target_data = {}

    # Ensure command dictionary contains normalized target_data
    normalized_command = {
        "id": command_id,
        "command_type": command_type,
        "target_data": target_data
    }

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
        # Fetch fresh protected targets on policy refresh
        fresh_targets = fetch_protected_targets(config, cred_mgr=cred_mgr)
        fw_exec = executor or get_firewall_executor()
        fw_exec.update_protected_targets(fresh_targets)
        report_command_result(
            config,
            command_id,
            status="completed",
            result={"message": "Policy cache refreshed successfully", "protected_targets": fresh_targets},
            cred_mgr=cred_mgr
        )

    elif command_type in ("temporary_block_ip", "block_ip", "block_domain"):
        fw_exec = executor or get_firewall_executor()

        # Refresh protected targets list dynamically from gateway
        latest_targets = fetch_protected_targets(config, cred_mgr=cred_mgr)
        fw_exec.update_protected_targets(latest_targets)

        # Execute host firewall rule safely (input validation, rate limiting, and zero shell execution)
        exec_result = fw_exec.validate_and_execute(normalized_command)

        if exec_result.get("success"):
            logger.info(
                f"[FIREWALL] Rule execution succeeded: {command_type} -> "
                f"{exec_result.get('target')} (firewall: {exec_result.get('firewall')})"
            )
            report_command_result(
                config,
                command_id,
                status="completed",
                result=exec_result,
                cred_mgr=cred_mgr
            )
        else:
            logger.warning(
                f"[FIREWALL] Rule execution failed for command {command_id}: "
                f"{exec_result.get('error')} — {exec_result.get('message')}"
            )
            report_command_result(
                config,
                command_id,
                status="failed",
                result=exec_result,
                cred_mgr=cred_mgr
            )


def poll_and_dispatch_commands(
    config: AgentConfig,
    cred_mgr: Optional[CredentialManager] = None,
    executor: Optional[FirewallExecutor] = None
) -> int:
    """
    Fetches and processes all pending commands for this device.
    Returns the number of commands processed.
    """
    commands = fetch_pending_commands(config, cred_mgr=cred_mgr)
    if commands:
        logger.info(f"Retrieved {len(commands)} pending command(s) from gateway")
        for cmd in commands:
            process_command(config, cmd, cred_mgr=cred_mgr, executor=executor)
    return len(commands)
