"""
CYBERGUARD Enterprise Agent v1 — Main Entrypoint
Orchestrates background liveness heartbeats, OS telemetry reporting, and security command polling.
"""

import sys
import time
import signal
import threading
from typing import Optional

from config import AgentConfig, CredentialManager, DEFAULT_LOG_FILE
from enrollment import enroll_or_load, EnrollmentError
from heartbeat import send_heartbeat
from collector import collect_system_telemetry
from telemetry_reporter import report_telemetry
from command_handler import poll_and_dispatch_commands
from firewall_executor import FirewallExecutor
from logger import setup_logger, get_logger

# Initialize agent logger with optional file logging
setup_logger(log_file=str(DEFAULT_LOG_FILE))
logger = get_logger()


class EnterpriseAgent:
    """Enterprise Agent daemon orchestrator."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        firewall_executor: Optional[FirewallExecutor] = None
    ):
        self.config = config or AgentConfig()
        self.cred_mgr: Optional[CredentialManager] = None
        self.firewall_executor = firewall_executor or FirewallExecutor()
        self.stop_event = threading.Event()
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.telemetry_thread: Optional[threading.Thread] = None
        self.command_thread: Optional[threading.Thread] = None
        self.commands_pending_hint = 0

    def start(self) -> None:
        """Starts the agent lifecycle: configuration, enrollment, and workers."""
        self.config.log_startup_summary()

        # Step 0: Log privilege status and host firewall capabilities
        if sys.platform == "win32":
            priv_label = "Administrator (Elevated)" if self.firewall_executor.is_admin else "Standard User (Non-Elevated)"
        else:
            priv_label = "root (Elevated)" if self.firewall_executor.is_root else "Non-Root User"

        logger.info(f"Host Privilege Level: {priv_label}")
        if self.firewall_executor.can_execute:
            logger.info("Host Firewall Engine: ACTIVE (host-level containment enabled)")
        else:
            logger.warning(
                "Host Firewall Engine: RESTRICTED. Running with standard privileges — "
                "firewall block commands will be refused until elevated as admin/root."
            )

        # Step 1: Pre-flight backend check
        is_reachable = self.config.validate_backend()
        if not is_reachable:
            logger.warning(
                f"Backend gateway at {self.config.backend_url} may be currently offline. "
                "Agent will proceed with cached state and attempt retries."
            )

        # Step 2: Enroll or load existing device identity
        try:
            identity = enroll_or_load(self.config)
            # Create a single thread-safe CredentialManager shared across all worker threads
            self.cred_mgr = CredentialManager(
                device_id=self.config.device_id,
                credential_id=self.config.credential_id,
                credential_secret=self.config.credential_secret or identity.get("credential_secret")
            )
            logger.info(
                f"Agent enrolled as device_id={self.config.device_id}, waiting for commands..."
            )
        except EnrollmentError as e:
            logger.error(f"Agent enrollment failure: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error initializing agent identity: {e}")
            sys.exit(1)

        # Step 3: Register graceful signal handlers (only in main thread)
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._handle_shutdown)
                signal.signal(signal.SIGTERM, self._handle_shutdown)
            except (ValueError, AttributeError):
                pass

        # Step 4: Spawn background worker loops
        self._start_worker_threads()

        logger.info("CYBERGUARD Enterprise Agent is running actively.")

    def _start_worker_threads(self) -> None:
        """Launches threaded worker loops for heartbeat, telemetry, and commands."""
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="HeartbeatWorker",
            daemon=True
        )
        self.telemetry_thread = threading.Thread(
            target=self._telemetry_loop,
            name="TelemetryWorker",
            daemon=True
        )
        self.command_thread = threading.Thread(
            target=self._command_loop,
            name="CommandWorker",
            daemon=True
        )

        self.heartbeat_thread.start()
        self.telemetry_thread.start()
        self.command_thread.start()

    def _heartbeat_loop(self) -> None:
        """Periodically dispatches liveness heartbeats to backend."""
        logger.info("Heartbeat loop started.")
        while not self.stop_event.is_set():
            try:
                # Quick telemetry query for open connection counts
                conn_count = collect_system_telemetry().get("network_conn_count", 0)
                hb_result = send_heartbeat(
                    self.config,
                    network_connections_count=conn_count,
                    cred_mgr=self.cred_mgr
                )
                self.commands_pending_hint = hb_result.get("commands_pending", 0)

                # If backend informed us commands are waiting, wake up command poller
                if self.commands_pending_hint > 0:
                    logger.debug(f"Heartbeat signaled {self.commands_pending_hint} commands queued.")
                    poll_and_dispatch_commands(
                        self.config,
                        cred_mgr=self.cred_mgr,
                        executor=self.firewall_executor
                    )

                interval = hb_result.get("next_heartbeat_in_seconds", self.config.heartbeat_interval)
            except Exception as e:
                logger.error(f"Unhandled error in heartbeat loop: {e}")
                interval = self.config.heartbeat_interval

            # Sleep cleanly with interruptible stop_event
            self.stop_event.wait(interval)

    def _telemetry_loop(self) -> None:
        """Periodically collects OS process/system telemetry and posts to backend."""
        logger.info("Telemetry collection loop started.")
        while not self.stop_event.is_set():
            try:
                telemetry = collect_system_telemetry()
                report_telemetry(self.config, telemetry, cred_mgr=self.cred_mgr)
            except Exception as e:
                logger.error(f"Unhandled error in telemetry collection loop: {e}")

            self.stop_event.wait(self.config.telemetry_interval)

    def _command_loop(self) -> None:
        """Periodically polls for security response commands."""
        logger.info("Command polling loop started.")
        while not self.stop_event.is_set():
            try:
                poll_and_dispatch_commands(
                    self.config,
                    cred_mgr=self.cred_mgr,
                    executor=self.firewall_executor
                )
            except Exception as e:
                logger.error(f"Unhandled error in command polling loop: {e}")

            self.stop_event.wait(self.config.command_poll_interval)

    def _handle_shutdown(self, signum: int, frame) -> None:
        """Signal handler for SIGINT and SIGTERM."""
        logger.info(f"Received termination signal ({signum}). Initiating graceful shutdown...")
        self.stop()

    def stop(self) -> None:
        """Stops all threads cleanly."""
        self.stop_event.set()
        logger.info("Waiting for background workers to terminate...")
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2.0)
        if self.telemetry_thread and self.telemetry_thread.is_alive():
            self.telemetry_thread.join(timeout=2.0)
        if self.command_thread and self.command_thread.is_alive():
            self.command_thread.join(timeout=2.0)
        logger.info("CYBERGUARD Enterprise Agent shutdown complete.")

    def run_interactive(self) -> None:
        """Runs the agent and keeps main thread waiting for signals or stdin commands."""
        self.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(1.0)
        except (KeyboardInterrupt, SystemExit):
            self.stop()


def main():
    agent = EnterpriseAgent()
    agent.run_interactive()


if __name__ == "__main__":
    main()
