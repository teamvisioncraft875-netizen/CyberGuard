"""
CYBERGUARD Enterprise Agent — Configuration Module
Manages environment variables, local non-secret credentials cache, and backend reachability validation.
"""

import os
import json
import socket
import threading
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

from logger import get_logger, sanitize_text

# Load .env file from working directory if present
load_dotenv()

logger = get_logger()

# Module-level thread synchronization lock for agent credentials
_cred_lock = threading.Lock()


class CredentialManager:
    """
    Thread-safe container and access manager for agent identity and in-memory credential secret.
    Synchronizes access across heartbeat, telemetry, and command polling worker threads.
    """

    def __init__(self, device_id: str, credential_id: str, credential_secret: str):
        self.device_id = device_id
        self.credential_id = credential_id
        self._credential_secret = credential_secret

    def get_secret(self) -> str:
        """Thread-safely retrieves credential_secret."""
        with _cred_lock:
            return self._credential_secret

    def update_secret(self, new_secret: str) -> None:
        """Thread-safely updates credential_secret."""
        with _cred_lock:
            self._credential_secret = new_secret

    def get_credentials(self) -> Dict[str, str]:
        """Thread-safely retrieves complete credential tuple."""
        with _cred_lock:
            return {
                "device_id": self.device_id,
                "credential_id": self.credential_id,
                "credential_secret": self._credential_secret,
            }


def ensure_creds_file_permissions(file_path: Path) -> None:
    """
    Enforces 0600 (owner read/write only) file permissions on credentials storage.
    Warns if permissions differ from 0600 and automatically fixes them.
    """
    if not file_path.exists():
        return
    try:
        current_mode = file_path.stat().st_mode & 0o777
        if current_mode != 0o600:
            logger.warning(
                f"Credentials file {file_path} permissions ({oct(current_mode)}) "
                "differ from 0o600. Correcting permissions to owner-only read/write."
            )
            os.chmod(file_path, 0o600)
    except Exception as e:
        logger.debug(f"Unable to verify/set 0600 permissions on {file_path}: {e}")


# Default configuration constants
DEFAULT_BACKEND_URL = "http://localhost:5000"
DEFAULT_AGENT_VERSION = "1.0.0"
DEFAULT_HEARTBEAT_INTERVAL = 60
DEFAULT_TELEMETRY_INTERVAL = 60
DEFAULT_COMMAND_POLL_INTERVAL = 60

# Secure default directory for agent credentials cache
DEFAULT_CREDS_DIR = Path.home() / ".cyberguard"
DEFAULT_CREDS_FILE = DEFAULT_CREDS_DIR / "agent_creds.json"
DEFAULT_LOG_FILE = DEFAULT_CREDS_DIR / "agent.log"


class AgentConfig:
    """Encapsulates runtime configuration for the Enterprise Agent."""

    def __init__(
        self,
        backend_url: Optional[str] = None,
        enrollment_token: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_version: Optional[str] = None,
        creds_file: Optional[Path] = None,
        heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
        telemetry_interval: int = DEFAULT_TELEMETRY_INTERVAL,
        command_poll_interval: int = DEFAULT_COMMAND_POLL_INTERVAL,
    ):
        self.backend_url = (
            backend_url or os.getenv("CYBERGUARD_BACKEND_URL", DEFAULT_BACKEND_URL)
        ).rstrip("/")
        self.enrollment_token = (
            enrollment_token or os.getenv("ENROLLMENT_TOKEN", "")
        ).strip()
        self.agent_name = (
            agent_name or os.getenv("AGENT_NAME", socket.gethostname())
        ).strip()
        self.agent_version = (
            agent_version or os.getenv("AGENT_VERSION", DEFAULT_AGENT_VERSION)
        ).strip()

        # Configurable creds file path (useful for testing or specific profiles)
        custom_creds_path = os.getenv("AGENT_CREDS_PATH")
        if creds_file:
            self.creds_file = Path(creds_file)
        elif custom_creds_path:
            self.creds_file = Path(custom_creds_path)
        else:
            self.creds_file = DEFAULT_CREDS_FILE

        self.heartbeat_interval = int(
            os.getenv("HEARTBEAT_INTERVAL", str(heartbeat_interval))
        )
        self.telemetry_interval = int(
            os.getenv("TELEMETRY_INTERVAL", str(telemetry_interval))
        )
        self.command_poll_interval = int(
            os.getenv("COMMAND_POLL_INTERVAL", str(command_poll_interval))
        )

        # In-memory only state (never written to disk)
        self.device_id: Optional[str] = None
        self.credential_id: Optional[str] = None
        self.credential_secret: Optional[str] = os.getenv("AGENT_CREDENTIAL_SECRET", None)
        self.organization_id: Optional[str] = None

    def load_cached_credentials(self) -> bool:
        """
        Attempts to load device_id and credential_id from the local credentials file.
        SECURITY: credential_secret is NEVER read from or expected in this file.
        """
        if not self.creds_file.exists():
            return False

        # Validate and enforce 0600 file permissions on startup
        ensure_creds_file_permissions(self.creds_file)

        try:
            with open(self.creds_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            device_id = data.get("device_id")
            credential_id = data.get("credential_id")

            if device_id and credential_id:
                self.device_id = device_id
                self.credential_id = credential_id
                self.organization_id = data.get("organization_id")
                logger.info(
                    f"Loaded existing agent credentials from {self.creds_file} "
                    f"(device_id={self.device_id}, credential_id={self.credential_id})"
                )
                return True
        except Exception as e:
            logger.warning(f"Could not read local credentials file {self.creds_file}: {e}")

        return False

    def save_credentials(
        self,
        device_id: str,
        credential_id: str,
        organization_id: Optional[str] = None
    ) -> bool:
        """
        Persists ONLY non-secret metadata (device_id, credential_id, organization_id)
        to ~/.cyberguard/agent_creds.json.
        SECURITY CRITICAL: credential_secret is strictly kept in-memory and NEVER saved!
        """
        try:
            self.creds_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "device_id": device_id,
                "credential_id": credential_id,
                "organization_id": organization_id,
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
            }

            with open(self.creds_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            # Enforce 0600 permissions immediately upon file creation
            ensure_creds_file_permissions(self.creds_file)

            self.device_id = device_id
            self.credential_id = credential_id
            self.organization_id = organization_id

            logger.info(f"Saved non-secret identity to {self.creds_file} (device_id={device_id})")
            return True
        except Exception as e:
            logger.error(f"Failed to save credentials file to {self.creds_file}: {e}")
            return False

    def validate_backend(self, timeout: float = 5.0) -> bool:
        """
        Performs a pre-flight reachability check against backend.
        Checks /api/v1/health or /health or base URL.
        """
        health_endpoints = [
            f"{self.backend_url}/api/v1/health",
            f"{self.backend_url}/health",
            self.backend_url
        ]

        for endpoint in health_endpoints:
            try:
                resp = requests.get(endpoint, timeout=timeout)
                if resp.status_code in (200, 204, 404):  # server responded
                    logger.debug(f"Backend reachability check succeeded at {endpoint} (HTTP {resp.status_code})")
                    return True
            except requests.RequestException:
                continue

        logger.warning(f"Backend at {self.backend_url} was not reachable within {timeout}s")
        return False

    def log_startup_summary(self) -> None:
        """Logs startup configuration, strictly omitting credential_secret."""
        token_display = "[SET]" if self.enrollment_token else "[NOT SET]"
        secret_display = "[IN-MEMORY]" if self.credential_secret else "[NOT SET]"

        logger.info("=== CYBERGUARD Enterprise Agent v1 Startup Configuration ===")
        logger.info(f"Backend URL:            {self.backend_url}")
        logger.info(f"Agent Name / Hostname:  {self.agent_name}")
        logger.info(f"Agent Version:          {self.agent_version}")
        logger.info(f"Credentials File:       {self.creds_file}")
        logger.info(f"Enrollment Token:       {token_display}")
        logger.info(f"Credential Secret:      {secret_display}")
        logger.info(f"Heartbeat Interval:     {self.heartbeat_interval}s")
        logger.info(f"Telemetry Interval:     {self.telemetry_interval}s")
        logger.info(f"Command Poll Interval:  {self.command_poll_interval}s")
        logger.info("===========================================================")
