"""
CYBERGUARD Enterprise Agent — Heartbeat Module
Sends periodic device status and liveness pings to the central API gateway.
"""

from typing import Dict, Any, Optional
import requests

from config import AgentConfig, CredentialManager
from logger import get_logger

logger = get_logger()


def send_heartbeat(
    config: AgentConfig,
    network_connections_count: Optional[int] = None,
    cred_mgr: Optional[CredentialManager] = None
) -> Dict[str, Any]:
    """
    Dispatches a heartbeat ping to POST /api/v1/agents/:device_id/heartbeat.
    Authenticates with credential_id + credential_secret (read thread-safely via CredentialManager if provided).
    Returns dictionary with status, next_heartbeat_in_seconds, and commands_pending.
    """
    device_id = cred_mgr.device_id if cred_mgr else config.device_id
    credential_id = cred_mgr.credential_id if cred_mgr else config.credential_id
    credential_secret = cred_mgr.get_secret() if cred_mgr else config.credential_secret

    if not device_id or not credential_id or not credential_secret:
        logger.warning("Heartbeat skipped: Agent is not properly enrolled with active credentials.")
        return {
            "status": "not_enrolled",
            "next_heartbeat_in_seconds": config.heartbeat_interval,
            "commands_pending": 0,
        }

    heartbeat_url = f"{config.backend_url}/api/v1/agents/{device_id}/heartbeat"

    payload: Dict[str, Any] = {
        "credential_id": credential_id,
        "credential_secret": credential_secret,
        "agent_version": config.agent_version,
    }

    if network_connections_count is not None:
        payload["network_connections_count"] = int(network_connections_count)

    headers = {
        "Content-Type": "application/json",
        "x-agent-credential-id": credential_id,
        "x-agent-credential-secret": credential_secret,
    }

    try:
        response = requests.post(heartbeat_url, json=payload, headers=headers, timeout=10)
    except requests.Timeout as e:
        logger.warning(f"Heartbeat request timed out after 10s: {e}. Will retry on next cycle.")
        return {
            "status": "timeout",
            "next_heartbeat_in_seconds": config.heartbeat_interval,
            "commands_pending": 0,
        }
    except requests.RequestException as e:
        logger.warning(f"Heartbeat network transmission failed: {e}. Will retry next cycle.")
        return {
            "status": "network_error",
            "next_heartbeat_in_seconds": config.heartbeat_interval,
            "commands_pending": 0,
        }

    if response.status_code == 200:
        data = response.json()
        next_interval = data.get("next_heartbeat_in_seconds", config.heartbeat_interval)
        commands_pending = data.get("commands_pending", 0)
        status = data.get("status", "online")

        logger.info(
            f"Heartbeat sent, status={status}, commands_pending={commands_pending}, "
            f"next_in={next_interval}s"
        )

        return {
            "status": status,
            "next_heartbeat_in_seconds": next_interval,
            "commands_pending": commands_pending,
        }
    elif response.status_code == 401:
        logger.error(
            f"Heartbeat rejected: Unauthorized (HTTP 401). Agent credentials may have expired or been revoked."
        )
        return {
            "status": "unauthorized",
            "next_heartbeat_in_seconds": config.heartbeat_interval,
            "commands_pending": 0,
        }
    else:
        logger.warning(
            f"Heartbeat returned non-success HTTP {response.status_code}: {response.text}"
        )
        return {
            "status": "server_error",
            "next_heartbeat_in_seconds": config.heartbeat_interval,
            "commands_pending": 0,
        }
