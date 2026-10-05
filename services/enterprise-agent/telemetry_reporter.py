"""
CYBERGUARD Enterprise Agent — Telemetry Reporter
Transmits collected host metrics to the telemetry ingestion endpoint.
Gracefully handles offline states or network interruptions without terminating agent.
"""

import os
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import requests

from config import AgentConfig, CredentialManager
from logger import get_logger

logger = get_logger()


def report_telemetry(
    config: AgentConfig,
    telemetry_data: Dict[str, Any],
    linked_user_id: Optional[str] = None,
    cred_mgr: Optional[CredentialManager] = None
) -> bool:
    """
    Transmits OS telemetry data to POST /api/v1/telemetry/system-event.
    Complies with telemetry controller schema requirements (timestamp, event_type, details).
    Authenticates with device identity (read thread-safely via CredentialManager if provided).
    """
    telemetry_url = f"{config.backend_url}/api/v1/telemetry/system-event"
    now_iso = datetime.now(timezone.utc).isoformat()

    device_id = cred_mgr.device_id if cred_mgr else config.device_id
    credential_id = cred_mgr.credential_id if cred_mgr else config.credential_id
    credential_secret = cred_mgr.get_secret() if cred_mgr else config.credential_secret

    payload: Dict[str, Any] = {
        "timestamp": telemetry_data.get("timestamp", now_iso),
        "event_type": "agent_telemetry",
        "telemetry_type": "agent_telemetry",
        "source": "enterprise_agent",
        "device_id": device_id,
        "data": telemetry_data,
        "details": telemetry_data,
        "attack_surface": telemetry_data.get("attack_surface", {"listening_ports": []}),
    }

    # Payload-size protection (Max 64 KB = 65536 bytes)
    try:
        serialized = json.dumps(payload)
        if len(serialized.encode("utf-8")) > 65536:
            logger.warning("Telemetry payload exceeds 64 KB limit. Truncating attack_surface section.")
            payload["attack_surface"] = {"listening_ports": []}
            if isinstance(payload.get("data"), dict) and "attack_surface" in payload["data"]:
                payload["data"]["attack_surface"] = {"listening_ports": []}
            if isinstance(payload.get("details"), dict) and "attack_surface" in payload["details"]:
                payload["details"]["attack_surface"] = {"listening_ports": []}
    except Exception as e:
        logger.debug(f"Payload size serialization check note: {e}")

    if linked_user_id:
        payload["user_id"] = linked_user_id

    headers = {
        "Content-Type": "application/json",
    }

    if credential_id and credential_secret:
        payload["credential_id"] = credential_id
        payload["credential_secret"] = credential_secret
        headers["x-agent-credential-id"] = credential_id
        headers["x-agent-credential-secret"] = credential_secret

    # Optional bearer or API key if configured
    telemetry_token = os.getenv("TELEMETRY_API_KEY") or os.getenv("AGENT_TELEMETRY_TOKEN")
    if telemetry_token:
        headers["Authorization"] = f"Bearer {telemetry_token}"

    try:
        response = requests.post(telemetry_url, json=payload, headers=headers, timeout=10)
    except requests.Timeout as e:
        logger.warning(f"Telemetry report timed out after 10s: {e}. Will retry on next cycle.")
        return False
    except requests.RequestException as e:
        logger.warning(f"Telemetry report failed to transmit: {e}")
        return False

    if response.status_code in (200, 201):
        logger.info(
            f"Reported system telemetry snapshot (conns={telemetry_data.get('network_conn_count')}, "
            f"procs={len(telemetry_data.get('top_processes', []))})"
        )
        return True
    elif response.status_code in (401, 403):
        logger.warning(
            f"Telemetry transmission received HTTP {response.status_code}. "
            "Note: /telemetry/system-event may require user JWT; skipping crash."
        )
        return False
    else:
        logger.warning(
            f"Telemetry report returned HTTP {response.status_code}: {response.text[:200]}"
        )
        return False
