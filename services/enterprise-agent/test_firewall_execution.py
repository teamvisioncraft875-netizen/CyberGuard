"""
CYBERGUARD Enterprise Agent — Phase C.2 Firewall Execution Test Suite
Validates host firewall rule execution, privilege enforcement, rate limiting,
input sanitization, command injection safety, timeout handling, and zero shell=True calls.
"""

import sys
import time
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure current module directory is on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from firewall_executor import FirewallExecutor, is_admin_windows, is_root_linux


def run_tests():
    print("\n" + "=" * 70)
    print("  CYBERGUARD — PHASE C.2 FIREWALL EXECUTION LAYER TEST SUITE")
    print("=" * 70 + "\n")

    test_results = []

    def record_test(name: str, passed: bool, details: str = ""):
        test_results.append({"name": name, "passed": passed, "details": details})
        status_str = "PASS" if passed else "FAIL"
        print(f"[{status_str}] {name} {details}")

    protected_catalog = {
        "protected_ips": ["127.0.0.1", "0.0.0.0", "::1", "198.51.100.99"],
        "protected_ip_ranges": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "0.0.0.0/8"
        ],
        "protected_domains": ["localhost", "cyberguard.local", "api.cyberguard.internal"]
    }

    # ──────────────────────────────────────────────────────────────────────────
    # Test 1: Mock Windows PowerShell Command Generation
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )

        res = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })

        assert res["success"] is True
        assert res["firewall"] == "windows_defender"
        assert mock_subproc.called

        called_args, called_kwargs = mock_subproc.call_args
        cmd_list = called_args[0]
        assert cmd_list[0] == "powershell"
        assert "-NoProfile" in cmd_list
        assert "-NonInteractive" in cmd_list
        assert any("New-NetFirewallRule" in arg for arg in cmd_list)
        assert any("203.0.113.42" in arg for arg in cmd_list)
        # CRITICAL SECURITY CHECK: shell must be False
        assert called_kwargs.get("shell") is False or called_kwargs.get("shell") is None

        record_test(
            "Test 1: Mock Windows PowerShell Command Generation",
            True,
            f"(powershell invoked safely with shell=False, rule_name={res.get('rule_name')})"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 2: Mock Linux ufw Command Generation
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "linux"), patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = FirewallExecutor(
            is_root_linux_flag=True,
            protected_targets=protected_catalog
        )
        executor._detect_firewall = MagicMock(return_value="ufw")

        res = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })

        assert res["success"] is True
        assert res["firewall"] == "ufw"
        called_args, called_kwargs = mock_subproc.call_args
        cmd_list = called_args[0]
        assert cmd_list == ["ufw", "deny", "from", "203.0.113.42"]
        assert called_kwargs.get("shell") is False

        record_test(
            "Test 2: Mock Linux ufw Command Generation",
            True,
            "(generated ['ufw', 'deny', 'from', '203.0.113.42'] with shell=False)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 3: Mock Linux firewalld Rich Rule Generation
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "linux"), patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = FirewallExecutor(
            is_root_linux_flag=True,
            protected_targets=protected_catalog
        )
        executor._detect_firewall = MagicMock(return_value="firewalld")

        res = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })

        assert res["success"] is True
        assert res["firewall"] == "firewalld"
        called_args, called_kwargs = mock_subproc.call_args
        cmd_list = called_args[0]
        assert cmd_list[0] == "firewall-cmd"
        assert cmd_list[1] == "--add-rich-rule"
        assert 'address="203.0.113.42"' in cmd_list[2]
        assert called_kwargs.get("shell") is False

        record_test(
            "Test 3: Mock Linux firewalld Command Generation",
            True,
            "(generated firewall-cmd --add-rich-rule with shell=False)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 4: Mock Linux iptables Command Generation
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "linux"), patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = FirewallExecutor(
            is_root_linux_flag=True,
            protected_targets=protected_catalog
        )
        executor._detect_firewall = MagicMock(return_value="iptables")

        res = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })

        assert res["success"] is True
        assert res["firewall"] == "iptables"
        called_args, called_kwargs = mock_subproc.call_args
        cmd_list = called_args[0]
        assert cmd_list == ["iptables", "-A", "INPUT", "-s", "203.0.113.42", "-j", "DROP"]
        assert called_kwargs.get("shell") is False

        record_test(
            "Test 4: Mock Linux iptables Command Generation",
            True,
            "(generated ['iptables', '-A', 'INPUT', '-s', '203.0.113.42', '-j', 'DROP'])"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 5: Rate Limiting Enforcement (Max 10 per hour)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"):
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog,
            dry_run=True
        )

        for i in range(10):
            r = executor.validate_and_execute({
                "command_type": "block_ip",
                "target_data": {"ip_address": f"203.0.113.{i + 1}"}
            })
            assert r["success"] is True, f"Rule {i + 1} should succeed"

        # 11th rule attempt within same hour window
        r11 = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.99"}
        })
        passed_rl = (
            r11["success"] is False and
            r11.get("error") == "rate_limit_exceeded" and
            "10 rules per hour" in r11.get("message", "")
        )

        record_test(
            "Test 5: Rate Limit Enforcement (Max 10 / hour)",
            passed_rl,
            f"(10 succeeded, 11th failed with error='{r11.get('error')}')"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 6: Protected List Rejection (Loopback & RFC 1918)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"):
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog,
            dry_run=True
        )

        r_loop = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "127.0.0.1"}
        })
        r_rfc = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "192.168.1.1"}
        })

        passed_prot = (
            r_loop["success"] is False and r_loop.get("error") == "target_protected" and
            r_rfc["success"] is False and r_rfc.get("error") == "target_protected"
        )
        record_test(
            "Test 6: Protected List Rejection (127.0.0.1 & 192.168.1.1)",
            passed_prot,
            "(both rejected with error='target_protected')"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 7: Protected List Rejection (Backend IP & Domain)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"):
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog,
            dry_run=True
        )

        r_backend_ip = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "198.51.100.99"}
        })
        r_backend_domain = executor.validate_and_execute({
            "command_type": "block_domain",
            "target_data": {"domain": "api.cyberguard.internal"}
        })

        passed_backend = (
            r_backend_ip["success"] is False and r_backend_ip.get("error") == "target_protected" and
            r_backend_domain["success"] is False and r_backend_domain.get("error") == "target_protected"
        )
        record_test(
            "Test 7: Protected Backend IP/Domain Rejection",
            passed_backend,
            "(backend IP and internal domain rejected)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 8: Privilege Check on Windows (Non-Admin Fails)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"):
        executor = FirewallExecutor(
            is_admin_windows_flag=False,  # Standard user without elevation
            protected_targets=protected_catalog,
            dry_run=False
        )
        res_non_admin = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })
        passed_priv_win = (
            res_non_admin["success"] is False and
            res_non_admin.get("error") == "insufficient_privileges"
        )
        record_test(
            "Test 8: Windows Privilege Enforcement (Non-Admin Fails)",
            passed_priv_win,
            f"(rejected with error='{res_non_admin.get('error')}')"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 9: Privilege Check on Linux (Non-Root Fails)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "linux"):
        executor = FirewallExecutor(
            is_root_linux_flag=False,  # Non-root user
            protected_targets=protected_catalog,
            dry_run=False
        )
        res_non_root = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })
        passed_priv_lin = (
            res_non_root["success"] is False and
            res_non_root.get("error") == "insufficient_privileges"
        )
        record_test(
            "Test 9: Linux Privilege Enforcement (Non-Root Fails)",
            passed_priv_lin,
            f"(rejected with error='{res_non_root.get('error')}')"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 10: Invalid IP Format Rejected Before Subprocess
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        res_invalid_ip = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "not-an-ip"}
        })
        passed_invalid_ip = (
            res_invalid_ip["success"] is False and
            res_invalid_ip.get("error") == "invalid_ip_format" and
            not mock_subproc.called
        )
        record_test(
            "Test 10: Invalid IP Format Rejected Before Subprocess",
            passed_invalid_ip,
            "(subprocess.run was never invoked)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 11: Wildcard Domain Rejected Before Subprocess
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        res_wildcard = executor.validate_and_execute({
            "command_type": "block_domain",
            "target_data": {"domain": "*.evil.com"}
        })
        passed_wildcard = (
            res_wildcard["success"] is False and
            res_wildcard.get("error") == "wildcard_domains_not_allowed" and
            not mock_subproc.called
        )
        record_test(
            "Test 11: Wildcard Domain Rejected Before Subprocess",
            passed_wildcard,
            "(rejected with error='wildcard_domains_not_allowed')"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 12: Unsupported Domain Blocking on Windows
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"):
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        res_win_domain = executor.validate_and_execute({
            "command_type": "block_domain",
            "target_data": {"domain": "malicious-c2.net"}
        })
        passed_win_domain = (
            res_win_domain["success"] is False and
            res_win_domain.get("error") == "domain_blocking_unsupported_windows"
        )
        record_test(
            "Test 12: Unsupported Windows Domain Blocking Graceful Failure",
            passed_win_domain,
            "(Windows Defender does not support L7 domain block; gracefully reported)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 13: Subprocess Timeout Handling (> 10s)
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        mock_subproc.side_effect = subprocess.TimeoutExpired(cmd="powershell ...", timeout=10)
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        res_timeout = executor.validate_and_execute({
            "command_type": "block_ip",
            "target_data": {"ip_address": "203.0.113.42"}
        })
        passed_timeout = (
            res_timeout["success"] is False and
            res_timeout.get("error") == "timeout" and
            "timed out after 10s" in res_timeout.get("message", "")
        )
        record_test(
            "Test 13: Subprocess Timeout Handling (> 10s)",
            passed_timeout,
            "(timeout caught and handled gracefully)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 14: Command Injection Prevention
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        malicious_targets = [
            "203.0.113.42; rm -rf /",
            "203.0.113.42 | cat /etc/passwd",
            "203.0.113.42`whoami`",
            "203.0.113.42$(whoami)",
            "203.0.113.42 & net user hacker /add",
            "203.0.113.42\nnet user hacker /add"
        ]

        injection_blocked = True
        for mal_target in malicious_targets:
            r = executor.validate_and_execute({
                "command_type": "block_ip",
                "target_data": {"ip_address": mal_target}
            })
            if r["success"] is not False or mock_subproc.called:
                injection_blocked = False
                break

        record_test(
            "Test 14: Command Injection Prevention (6 attack vectors)",
            injection_blocked,
            "(all shell metacharacters rejected, subprocess never called)"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 15: Static Code Audit: ZERO shell=True in Codebase
    # ──────────────────────────────────────────────────────────────────────────
    executor_code = (CURRENT_DIR / "firewall_executor.py").read_text(encoding="utf-8")
    handler_code = (CURRENT_DIR / "command_handler.py").read_text(encoding="utf-8")

    has_shell_true = ("shell=True" in executor_code) or ("shell=True" in handler_code)
    has_shell_false = ("shell=False" in executor_code)

    passed_shell_audit = (not has_shell_true) and has_shell_false
    record_test(
        "Test 15: Static Code Audit: Verified ZERO shell=True",
        passed_shell_audit,
        f"(shell=True count=0, shell=False explicitly specified={has_shell_false})"
    )

    # ──────────────────────────────────────────────────────────────────────────
    # Test 16: Reversible Rollback Execution
    # ──────────────────────────────────────────────────────────────────────────
    with patch("sys.platform", "win32"), patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = FirewallExecutor(
            is_admin_windows_flag=True,
            protected_targets=protected_catalog
        )
        executor.blocked_ips.add("203.0.113.42")

        rollback_res = executor.rollback_rule(
            rule_name="CyberGuard-block_ip-test1234",
            target="203.0.113.42",
            firewall_tool="windows_defender"
        )

        assert rollback_res["success"] is True
        assert rollback_res["rolled_back"] is True
        assert "203.0.113.42" not in executor.blocked_ips

        called_args, called_kwargs = mock_subproc.call_args
        cmd_list = called_args[0]
        assert any("Remove-NetFirewallRule" in arg for arg in cmd_list)
        assert called_kwargs.get("shell") is False

        record_test(
            "Test 16: Safe Firewall Rule Rollback & State Cleanup",
            True,
            "(Remove-NetFirewallRule invoked safely, local state purged)"
        )

    # Summary
    print("\n" + "=" * 70)
    print("CYBERGUARD Phase C.2 Firewall Execution Test Summary:")
    passed_all = all(t["passed"] for t in test_results)
    for t in test_results:
        print(f" - {t['name']}: {'PASS' if t['passed'] else 'FAIL'}")
    print("=" * 70)

    if passed_all:
        print("ALL 16 PHASE C.2 FIREWALL EXECUTION TESTS PASSED!")
        return 0
    else:
        print("SOME TESTS FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
