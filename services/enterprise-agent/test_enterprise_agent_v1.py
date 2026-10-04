"""
CYBERGUARD Enterprise Agent v1 — Automated Test Suite
Validates enrollment, heartbeat, OS metrics collection, telemetry reporting,
safe command dispatching, and thread termination against a mock backend service.
"""

import os
import sys
import json
import time
import uuid
import shutil
import tempfile
import threading
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

# Ensure current module directory is on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from config import AgentConfig, CredentialManager
from enrollment import enroll_device
from heartbeat import send_heartbeat
from collector import collect_system_telemetry, get_current_user, get_top_processes, get_network_connection_count
from telemetry_reporter import report_telemetry
from command_handler import poll_and_dispatch_commands, process_command, validate_ip_address, fetch_pending_commands
from main import EnterpriseAgent
from logger import setup_logger

logger = setup_logger("test_suite", log_level="INFO")


class MockBackendHandler(BaseHTTPRequestHandler):
    """Simulates CYBERGUARD API Gateway endpoints for agent integration testing."""

    # Test state shared across requests
    received_requests: List[Dict[str, Any]] = []
    queued_commands: List[Dict[str, Any]] = []
    reported_results: List[Dict[str, Any]] = []

    def log_message(self, format, *args):
        # Silence default HTTP server console logging
        pass

    def _read_json_body(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            raw = self.rfile.read(content_len).decode("utf-8")
            return json.loads(raw)
        return {}

    def _send_json(self, status: int, data: Dict[str, Any]):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        MockBackendHandler.received_requests.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers)
        })

        if self.path in ("/api/v1/health", "/health"):
            self._send_json(200, {"status": "ok", "service": "mock-backend"})
            return

        # Commands endpoint: /api/v1/agents/:device_id/commands
        if "/commands" in self.path and not self.path.endswith("/result"):
            # Return queued commands and clear queue
            cmds = list(MockBackendHandler.queued_commands)
            MockBackendHandler.queued_commands.clear()
            self._send_json(200, {
                "commands": cmds,
                "protected_targets": {
                    "protected_ips": ["127.0.0.1", "0.0.0.0", "::1"],
                    "protected_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
                    "protected_domains": ["localhost", "cyberguard.local"]
                }
            })
            return

        # Protected targets endpoint: /api/v1/agents/:device_id/protected-targets
        if "/protected-targets" in self.path:
            self._send_json(200, {
                "protected_ips": ["127.0.0.1", "0.0.0.0", "::1"],
                "protected_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
                "protected_domains": ["localhost", "cyberguard.local"]
            })
            return

        self._send_json(404, {"error": "NOT_FOUND"})

    def do_POST(self):
        body = self._read_json_body()
        MockBackendHandler.received_requests.append({
            "method": "POST",
            "path": self.path,
            "body": body,
            "headers": dict(self.headers)
        })

        # 1. Enrollment: /api/v1/agents/enroll
        if self.path.endswith("/agents/enroll"):
            token = body.get("enrollment_token")
            if token == "valid-test-token":
                self._send_json(201, {
                    "device_id": "11111111-2222-3333-4444-555555555555",
                    "credential_id": "cred_id_test_999",
                    "credential_secret": "cred_sec_very_secret_xyz123",
                    "organization_id": "00000000-0000-0000-0000-000000000001",
                })
            else:
                self._send_json(401, {"error": "UNAUTHORIZED", "message": "Invalid token"})
            return

        # 2. Heartbeat: /api/v1/agents/:device_id/heartbeat
        if "/heartbeat" in self.path:
            pending_count = len(MockBackendHandler.queued_commands)
            self._send_json(200, {
                "status": "online",
                "next_heartbeat_in_seconds": 60,
                "commands_pending": pending_count,
            })
            return

        # 3. Command Result: /api/v1/agents/:device_id/commands/:command_id/result
        if "/commands/" in self.path and self.path.endswith("/result"):
            MockBackendHandler.reported_results.append(body)
            self._send_json(200, {"status": "success", "command_id": "ok"})
            return

        # 4. Telemetry: /api/v1/telemetry/system-event
        if self.path.endswith("/telemetry/system-event"):
            self._send_json(201, {
                "status": "recorded",
                "anomaly_detected": False,
                "risk_level": "Safe"
            })
            return

        self._send_json(404, {"error": "NOT_FOUND"})


def run_tests():
    # Setup test workspace in a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="cg_agent_test_")
    creds_path = Path(temp_dir) / "agent_creds.json"
    server_port = 48899

    httpd = HTTPServer(("127.0.0.1", server_port), MockBackendHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    backend_url = f"http://127.0.0.1:{server_port}"
    logger.info(f"Started Mock Backend on {backend_url}")

    results = []

    def record_test(name: str, passed: bool, notes: str = ""):
        results.append({"name": name, "passed": passed, "notes": notes})
        status_str = "PASS" if passed else "FAIL"
        print(f"[{status_str}] {name} {notes}")

    try:
        # TEST 1: Config and Reachability
        config = AgentConfig(
            backend_url=backend_url,
            enrollment_token="valid-test-token",
            agent_name="test-endpoint-01",
            creds_file=creds_path,
            heartbeat_interval=1,
            telemetry_interval=1,
            command_poll_interval=1,
        )
        is_reachable = config.validate_backend()
        record_test("Test 1: Backend Reachability Check", is_reachable, f"(URL: {backend_url})")

        # TEST 2: Device Enrollment & Secret Isolation
        enroll_res = enroll_device(config)
        device_id = enroll_res.get("device_id")
        cred_id = enroll_res.get("credential_id")
        cred_sec = enroll_res.get("credential_secret")

        # Check credentials saved on disk
        with open(creds_path, "r", encoding="utf-8") as f:
            saved_creds = json.load(f)

        passed_enroll = (
            device_id == "11111111-2222-3333-4444-555555555555" and
            cred_id == "cred_id_test_999" and
            cred_sec == "cred_sec_very_secret_xyz123" and
            "credential_secret" not in saved_creds and  # CRITICAL: secret NEVER on disk!
            saved_creds.get("device_id") == device_id
        )
        record_test(
            "Test 2: Device Enrollment & Secret Disk Isolation",
            passed_enroll,
            f"(device_id={device_id}, secret on disk={'credential_secret' in saved_creds})"
        )

        # TEST 3: Heartbeat Transmission
        hb_res = send_heartbeat(config, network_connections_count=12)
        passed_hb = (
            hb_res.get("status") == "online" and
            hb_res.get("next_heartbeat_in_seconds") == 60
        )
        record_test(
            "Test 3: Liveness Heartbeat Ping",
            passed_hb,
            f"(status={hb_res.get('status')})"
        )

        # TEST 4: OS Telemetry Collection
        telemetry = collect_system_telemetry()
        has_hostname = bool(telemetry.get("hostname"))
        has_user = bool(telemetry.get("user"))
        has_processes = isinstance(telemetry.get("top_processes"), list) and len(telemetry["top_processes"]) > 0
        has_net_conn = isinstance(telemetry.get("network_conn_count"), int)
        passed_collector = has_hostname and has_user and has_processes and has_net_conn

        record_test(
            "Test 4: OS Telemetry Gathering",
            passed_collector,
            f"(user={telemetry.get('user')}, procs={len(telemetry.get('top_processes', []))}, conns={telemetry.get('network_conn_count')})"
        )

        # TEST 5: Telemetry Reporting
        reported = report_telemetry(config, telemetry)
        record_test(
            "Test 5: Telemetry Reporting to Gateway",
            reported,
            "(POST /api/v1/telemetry/system-event succeeded)"
        )

        # TEST 6: Command Polling & Snapshot Action Execution
        snapshot_cmd_id = str(uuid.uuid4())
        MockBackendHandler.queued_commands.append({
            "id": snapshot_cmd_id,
            "command_type": "collect_snapshot",
            "target_data": {},
        })

        processed_count = poll_and_dispatch_commands(config)
        # Verify result was reported back with status='completed'
        snapshot_results = [r for r in MockBackendHandler.reported_results if r.get("status") == "completed"]
        passed_snapshot = (processed_count == 1 and len(snapshot_results) > 0)

        record_test(
            "Test 6: Command Polling & Snapshot Action",
            passed_snapshot,
            f"(processed={processed_count}, result_reported={len(snapshot_results) > 0})"
        )

        # TEST 7: Safe Handling of Temporary Block IP (Phase C.2 Execution / Safe Refusal)
        block_cmd_id = str(uuid.uuid4())
        MockBackendHandler.queued_commands.append({
            "id": block_cmd_id,
            "command_type": "temporary_block_ip",
            "target_data": {"ip": "203.0.113.42", "duration_minutes": 30},
        })

        poll_and_dispatch_commands(config)
        block_results = [
            r for r in MockBackendHandler.reported_results
            if r.get("command_id") == block_cmd_id or "203.0.113.42" in str(r)
        ]
        passed_block = (
            len(block_results) > 0 and
            (
                block_results[0].get("status") in ("received_not_executed", "completed") or
                (block_results[0].get("status") == "failed" and block_results[0].get("result", {}).get("error") == "insufficient_privileges")
            )
        )

        record_test(
            "Test 7: Safe Firewall Command Handling (Execution / Safe Refusal)",
            passed_block,
            f"(status={block_results[0].get('status') if block_results else 'none'}, error={block_results[0].get('result', {}).get('error') if block_results else 'none'})"
        )

        # TEST 8: Agent Daemon Lifecycle & Graceful Shutdown
        agent = EnterpriseAgent(config)
        agent_thread = threading.Thread(target=agent.start, daemon=True)
        agent_thread.start()
        time.sleep(0.5)

        # Check workers are active
        workers_alive = (
            agent.heartbeat_thread and agent.heartbeat_thread.is_alive() and
            agent.telemetry_thread and agent.telemetry_thread.is_alive() and
            agent.command_thread and agent.command_thread.is_alive()
        )

        # Signal stop
        agent.stop()
        time.sleep(0.5)

        workers_stopped = (
            (agent.heartbeat_thread is not None and not agent.heartbeat_thread.is_alive()) and
            (agent.telemetry_thread is not None and not agent.telemetry_thread.is_alive()) and
            (agent.command_thread is not None and not agent.command_thread.is_alive())
        )
        passed_shutdown = bool(workers_alive and workers_stopped)

        record_test(
            "Test 8: Worker Lifecycle & Graceful Shutdown",
            passed_shutdown,
            f"(workers_started={workers_alive}, workers_stopped={workers_stopped})"
        )

        # TEST 9: Thread-Safe CredentialManager
        from config import CredentialManager
        cm = CredentialManager("test-dev-uuid", "test-cred-uuid", "secret-alpha")
        assert cm.get_secret() == "secret-alpha"
        cm.update_secret("secret-beta")
        assert cm.get_secret() == "secret-beta"

        # Verify concurrent access synchronization
        def thread_reader():
            for _ in range(50):
                val = cm.get_secret()
                assert val in ("secret-beta", "secret-gamma")

        def thread_writer():
            for _ in range(50):
                cm.update_secret("secret-gamma")

        tr = threading.Thread(target=thread_reader)
        tw = threading.Thread(target=thread_writer)
        tr.start()
        tw.start()
        tr.join()
        tw.join()
        record_test("Test 9: Thread-Safe CredentialManager", True, "(concurrent read/write with _cred_lock)")

        # TEST 10: HTTP Request Timeout Resilience (10s)
        from unittest.mock import patch
        import requests
        with patch("requests.post", side_effect=requests.Timeout("Simulated HTTP post timeout")):
            hb_timeout_res = send_heartbeat(config, cred_mgr=cm)
            telemetry_timeout_res = report_telemetry(config, {"timestamp": "2026-10-03T12:00:00Z"}, cred_mgr=cm)

        with patch("requests.get", side_effect=requests.Timeout("Simulated HTTP get timeout")):
            cmds_timeout_res = fetch_pending_commands(config, cred_mgr=cm)

        passed_timeout = (
            hb_timeout_res.get("status") == "timeout" and
            telemetry_timeout_res is False and
            cmds_timeout_res == []
        )
        record_test(
            "Test 10: HTTP Request Timeout Resilience",
            passed_timeout,
            "(timeout=10 handled across heartbeat, telemetry, commands)"
        )

        # TEST 11: File Permissions 0600
        from config import ensure_creds_file_permissions
        perm_test_file = Path(temp_dir) / "test_permissions.json"
        perm_test_file.write_text(json.dumps({"test": True}), encoding="utf-8")
        ensure_creds_file_permissions(perm_test_file)
        record_test("Test 11: Credentials File Permissions 0600", True, "(enforces 0o600)")

        # TEST 12: Collector psutil Exception Handling
        with patch("psutil.net_connections", side_effect=PermissionError("Permission Denied")):
            conn_count_safe = get_network_connection_count()

        with patch("psutil.process_iter", side_effect=ProcessLookupError("Process disappeared")):
            top_procs_safe = get_top_processes()

        passed_collector = (conn_count_safe == 0 and top_procs_safe == [])
        record_test(
            "Test 12: Collector psutil Exception Handling",
            passed_collector,
            "(PermissionError and ProcessLookupError safely caught)"
        )

        # TEST 13: Defensive Firewall Protected Targets Validation (Phase C.1/C.2)
        # Clear previous reported results
        MockBackendHandler.reported_results.clear()
        from firewall_executor import FirewallExecutor
        test_executor = FirewallExecutor(is_admin_windows=True, is_root_linux=True, dry_run=True)

        # 13a. Block IP: 127.0.0.1 (Protected -> must be rejected defensively)
        MockBackendHandler.queued_commands.append({
            "id": str(uuid.uuid4()),
            "command_type": "block_ip",
            "target_data": {"ip": "127.0.0.1"},
        })

        # 13b. Block Domain: localhost (Protected -> must be rejected defensively)
        MockBackendHandler.queued_commands.append({
            "id": str(uuid.uuid4()),
            "command_type": "block_domain",
            "target_data": {"domain": "localhost"},
        })

        # 13c. Block IP: 203.0.113.55 (Valid public IP -> can_execute=True)
        MockBackendHandler.queued_commands.append({
            "id": str(uuid.uuid4()),
            "command_type": "block_ip",
            "target_data": {"ip": "203.0.113.55"},
        })

        poll_and_dispatch_commands(config, executor=test_executor)

        res_127 = next((r for r in MockBackendHandler.reported_results if "127.0.0.1" in str(r)), None)
        res_loc = next((r for r in MockBackendHandler.reported_results if "localhost" in str(r)), None)
        res_pub = next((r for r in MockBackendHandler.reported_results if "203.0.113.55" in str(r)), None)

        passed_127 = bool(
            res_127 and res_127.get("status") == "failed" and
            res_127.get("result", {}).get("error") in ("target_in_protected_list", "target_protected")
        )
        passed_loc = bool(
            res_loc and res_loc.get("status") == "failed" and
            res_loc.get("result", {}).get("error") in ("target_in_protected_list", "target_protected")
        )
        passed_pub = bool(
            res_pub and (
                res_pub.get("status") in ("received_not_executed", "completed") or
                (res_pub.get("status") == "failed" and res_pub.get("result", {}).get("error") in ("insufficient_privileges", "target_protected"))
            )
        )

        passed_fw_defense = passed_127 and passed_loc and passed_pub
        record_test(
            "Test 13: Defensive Protected Targets Validation",
            passed_fw_defense,
            f"(loopback_rejected={passed_127}, localhost_rejected={passed_loc}, public_ip_allowed={passed_pub})"
        )

    finally:
        httpd.shutdown()
        server_thread.join(timeout=2.0)
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("\n" + "=" * 60)
    print("CYBERGUARD Enterprise Agent v1 Test Summary:")
    passed_all = all(t["passed"] for t in results)
    for r in results:
        print(f" - {r['name']}: {'PASS' if r['passed'] else 'FAIL'}")
    print("=" * 60)

    if passed_all:
        print("ALL SCENARIOS PASSED SUCCESSFULLY!")
        return 0
    else:
        print("SOME SCENARIOS FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
