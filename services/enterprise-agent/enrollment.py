"""
CYBERGUARD Enterprise Agent — Enrollment Module
Handles initial one-time cryptographic enrollment with the backend and retrieves device credentials.
"""

import os
import sys
import platform
from typing import Optional, Dict, Any
import requests

from config import AgentConfig
from logger import get_logger

logger = get_logger()


class EnrollmentError(Exception):
    """Raised when device enrollment fails or server rejects the token."""
    pass


def enroll_device(config: AgentConfig) -> Dict[str, Any]:
    """
    Executes one-time device enrollment via POST /api/v1/agents/enroll.
    Returns dictionary with device_id, credential_id, credential_secret, organization_id.
    """
    if not config.enrollment_token:
        raise EnrollmentError(
            "ENROLLMENT_TOKEN is required for initial device enrollment. "
            "Please obtain a token from your CYBERGUARD administrator."
        )

    enroll_url = f"{config.backend_url}/api/v1/agents/enroll"
    os_name = platform.system() or "Unknown"
    os_detail = f"{os_name} {platform.release()}"
    client_platform = "desktop"

    payload = {
        "enrollment_token": config.enrollment_token,
        "hostname": config.agent_name,
        "os": os_detail,
        "platform": client_platform,
        "agent_version": config.agent_version,
    }

    logger.info(f"Initiating agent enrollment at {enroll_url} for host '{config.agent_name}'...")

    try:
        response = requests.post(enroll_url, json=payload, timeout=10)
    except requests.Timeout as e:
        logger.warning(f"Enrollment request timed out after 10s at {enroll_url}: {e}")
        raise EnrollmentError(f"Connection timed out contacting backend for enrollment: {e}")
    except requests.RequestException as e:
        raise EnrollmentError(f"Connection error contacting backend for enrollment: {e}")

    if response.status_code == 201:
        data = response.json()
        device_id = data.get("device_id")
        credential_id = data.get("credential_id")
        credential_secret = data.get("credential_secret")
        organization_id = data.get("organization_id")

        if not device_id or not credential_id or not credential_secret:
            raise EnrollmentError(f"Malformed response received during enrollment: {data}")

        # Persist ONLY non-secret metadata to disk
        config.save_credentials(
            device_id=device_id,
            credential_id=credential_id,
            organization_id=organization_id,
        )

        # Enforce 0600 file permissions on local credentials storage
        try:
            os.chmod(config.creds_file, 0o600)
        except Exception as e:
            logger.debug(f"Unable to set 0600 permissions on {config.creds_file}: {e}")

        # Store secret strictly in-memory
        config.credential_secret = credential_secret

        logger.info(
            f"Successfully enrolled device! device_id={device_id}, "
            f"credential_id={credential_id}, organization_id={organization_id}"
        )

        return {
            "device_id": device_id,
            "credential_id": credential_id,
            "credential_secret": credential_secret,
            "organization_id": organization_id,
        }

    elif response.status_code in (400, 401, 403):
        err_msg = response.json().get("message", response.text)
        raise EnrollmentError(f"Enrollment rejected by server (HTTP {response.status_code}): {err_msg}")
    else:
        raise EnrollmentError(f"Enrollment failed with server status {response.status_code}: {response.text}")


def enroll_or_load(config: AgentConfig) -> Dict[str, Any]:
    """
    Checks if agent has existing credentials cached on disk.
    If cached and valid in-memory secret exists, returns active credentials.
    If not cached or token present for fresh enroll, executes enroll_device.
    """
    has_cached = config.load_cached_credentials()

    # If we already have device_id and credential_id cached, and credential_secret is in memory
    if has_cached and config.credential_secret:
        logger.info(
            f"Using active agent credentials (device_id={config.device_id}, "
            f"credential_id={config.credential_id})"
        )
        return {
            "device_id": config.device_id,
            "credential_id": config.credential_id,
            "credential_secret": config.credential_secret,
            "organization_id": config.organization_id,
        }

    # If cached identity exists but no secret in memory, and no enrollment token provided
    if has_cached and not config.credential_secret and not config.enrollment_token:
        logger.warning(
            f"Device identity found ({config.device_id}) but credential_secret is not in memory. "
            f"Please set AGENT_CREDENTIAL_SECRET or provide a new ENROLLMENT_TOKEN to re-enroll."
        )

    # Perform fresh enrollment
    return enroll_device(config)
