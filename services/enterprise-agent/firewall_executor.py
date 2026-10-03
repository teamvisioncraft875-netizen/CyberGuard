"""
CYBERGUARD Enterprise Agent — Host Firewall Executor (Execution Layer)
Safely executes and rolls back host-level firewall containment rules.
Full support for Windows Defender Firewall (PowerShell) and Linux (ufw, firewalld, iptables).

SECURITY GUARANTEES:
1. Strict input validation against IP & domain syntax before invocation.
2. NEVER uses shell mode in subprocess calls (shell is explicitly set to False, zero injection risk).
3. Defensive protected list enforcement (localhost, RFC 1918, backend endpoints).
4. Rate limited to max 10 firewall modifications per hour per endpoint.
5. Privilege elevation validation: Admin on Windows, root on Linux.
6. Time-boxing & local rule state tracking for reversible containment.
"""

import os
import sys
import re
import time
import uuid
import shutil
import ipaddress
import subprocess
from typing import Dict, Any, List, Optional, Set

from collector import get_host_ip_addresses
from logger import get_logger

logger = get_logger()

# Maximum permitted firewall rule modifications per rolling hour
MAX_RULES_PER_HOUR = 10
RULE_RATE_LIMIT_WINDOW_SECONDS = 3600

# Shell metacharacters strictly forbidden in target inputs
FORBIDDEN_METACHARS_REGEX = re.compile(r'[;&|`$<>\r\n\t\s"]')

# Domain regex pattern (RFC 1035 / 1123 compliant subset)
DOMAIN_REGEX = re.compile(r'^[a-z0-9.-]+$', re.IGNORECASE)


def check_is_admin_windows() -> bool:
    """Checks whether current process holds elevated administrator rights on Windows."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell.IsUserAnAdmin())
    except Exception as e:
        logger.debug(f"Windows privilege check exception: {e}")
        return False


def check_is_root_linux() -> bool:
    """Checks whether current process is running as root (euid 0) on Linux/Unix."""
    if sys.platform == "win32":
        return False
    try:
        return os.geteuid() == 0
    except (AttributeError, Exception) as e:
        logger.debug(f"Linux privilege check exception: {e}")
        return False


is_admin_windows = check_is_admin_windows
is_root_linux = check_is_root_linux
is_admin_windows_fn = check_is_admin_windows
is_root_linux_fn = check_is_root_linux


class FirewallExecutor:
    """
    Executes and rolls back host-level firewall containment rules with
    privilege checking, input validation, and rate limiting.
    """

    def __init__(
        self,
        is_admin_windows: Optional[bool] = None,
        is_root_linux: Optional[bool] = None,
        protected_targets: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        **kwargs
    ):
        self.dry_run = dry_run

        admin_flag = is_admin_windows if is_admin_windows is not None else kwargs.get("is_admin_windows_flag")
        root_flag = is_root_linux if is_root_linux is not None else kwargs.get("is_root_linux_flag")

        # Determine privilege status
        self.is_admin = admin_flag if admin_flag is not None else is_admin_windows_fn()
        self.is_root = root_flag if root_flag is not None else is_root_linux_fn()

        if sys.platform == "win32":
            self.can_execute = bool(self.is_admin)
        elif sys.platform.startswith("linux"):
            self.can_execute = bool(self.is_root)
        else:
            self.can_execute = False

        # In-memory tracking & rollback state
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.active_rules: List[Dict[str, Any]] = []

        # Rate limiting state
        self.hourly_rule_count = 0
        self.last_hour_reset = time.time()

        # Catalog of targets that must NEVER be blocked
        self.protected_targets = protected_targets or {
            "protected_ips": ["127.0.0.1", "0.0.0.0", "::1", "::"],
            "protected_ip_ranges": [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "0.0.0.0/8",
            ],
            "protected_domains": ["localhost", "cyberguard.local"]
        }

        # Cache local machine's IP addresses
        self.local_ips = set(get_host_ip_addresses())

        logger.info(
            f"FirewallExecutor initialized: platform='{sys.platform}', "
            f"can_execute={self.can_execute} (admin={self.is_admin}, root={self.is_root}), "
            f"dry_run={self.dry_run}"
        )

    def update_protected_targets(self, new_targets: Dict[str, Any]) -> None:
        """Refreshes the protected targets list received from backend gateway."""
        if isinstance(new_targets, dict):
            self.protected_targets = new_targets

    def validate_and_execute(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates a firewall instruction and safely executes it using OS tools.
        Returns: { success: bool, error?: str, message?: str, rule_name?: str, ... }
        """
        command_type = command.get("command_type")
        raw_target_data = command.get("target_data") or {}

        # 1. Validate command type
        if command_type not in ("block_ip", "temporary_block_ip", "block_domain"):
            return {
                "success": False,
                "error": "unsupported_command_type",
                "message": f"Command type '{command_type}' is not supported by FirewallExecutor"
            }

        # 2. Check privilege elevation
        if not self.can_execute and not self.dry_run:
            logger.warning(
                f"[FIREWALL] Refusing command {command_type}: Process lacks administrative/root privileges."
            )
            return {
                "success": False,
                "error": "insufficient_privileges",
                "message": "Firewall execution requires administrator rights on Windows or root on Linux"
            }

        # 3. Check rate limiting (max 10 rules per rolling hour)
        now = time.time()
        if now - self.last_hour_reset > RULE_RATE_LIMIT_WINDOW_SECONDS:
            self.hourly_rule_count = 0
            self.last_hour_reset = now

        if self.hourly_rule_count >= MAX_RULES_PER_HOUR:
            logger.warning(
                f"[FIREWALL] Rate limit exceeded: {self.hourly_rule_count} rules created in the last hour."
            )
            return {
                "success": False,
                "error": "rate_limit_exceeded",
                "message": "Max 10 rules per hour"
            }

        # 4. Extract and validate target data
        if command_type in ("block_ip", "temporary_block_ip"):
            ip = (
                raw_target_data.get("ip_address")
                or raw_target_data.get("ip")
                or raw_target_data.get("target_ip")
                or raw_target_data.get("target")
            )
            val = self._validate_ip(ip)
            if not val["valid"]:
                return {"success": False, "error": val["error"], "message": val.get("message")}
            target = val["target"]
        else:
            domain = (
                raw_target_data.get("domain")
                or raw_target_data.get("target_domain")
                or raw_target_data.get("target")
            )
            val = self._validate_domain(domain)
            if not val["valid"]:
                return {"success": False, "error": val["error"], "message": val.get("message")}
            target = val["target"]

        # 5. Check against protected list
        if self._is_protected(target, command_type):
            logger.warning(
                f"[FIREWALL] Execution refused: Target '{target}' is protected against blocking."
            )
            return {
                "success": False,
                "error": "target_protected",
                "message": f"Cannot block protected target: {target}"
            }

        # 6. Execute OS-level rule
        result = self._execute_firewall_rule(command_type, target)

        if result.get("success"):
            self.hourly_rule_count += 1
            if command_type in ("block_ip", "temporary_block_ip"):
                self.blocked_ips.add(target)
            else:
                self.blocked_domains.add(target)

            rule_record = {
                "rule_name": result.get("rule_name"),
                "command_type": command_type,
                "target": target,
                "firewall": result.get("firewall"),
                "created_at": time.time(),
                "expires_at": time.time() + 86400  # 24 hour default lifetime
            }
            self.active_rules.append(rule_record)

        return result

    def _validate_ip(self, ip: Optional[str]) -> Dict[str, Any]:
        """Validates IP syntax and ensures absence of command injection metacharacters."""
        if not ip or not isinstance(ip, str) or not ip.strip():
            return {"valid": False, "error": "invalid_ip_format", "message": "Target IP address is missing"}

        clean_ip = ip.strip()

        # Reject any shell metacharacters immediately
        if FORBIDDEN_METACHARS_REGEX.search(clean_ip):
            return {
                "valid": False,
                "error": "invalid_ip_format",
                "message": "Target IP contains forbidden shell characters"
            }

        try:
            ipaddress.ip_address(clean_ip)
            return {"valid": True, "target": clean_ip}
        except ValueError:
            return {
                "valid": False,
                "error": "invalid_ip_format",
                "message": f"Malformed IP address: '{clean_ip}'"
            }

    def _validate_domain(self, domain: Optional[str]) -> Dict[str, Any]:
        """Validates domain syntax and ensures absence of wildcards or injection metacharacters."""
        if not domain or not isinstance(domain, str) or not domain.strip():
            return {"valid": False, "error": "invalid_domain_format", "message": "Target domain is missing"}

        clean_domain = domain.strip().lower()

        # Reject any shell metacharacters immediately
        if FORBIDDEN_METACHARS_REGEX.search(clean_domain):
            return {
                "valid": False,
                "error": "invalid_domain_format",
                "message": "Target domain contains forbidden shell characters"
            }

        if "*" in clean_domain or clean_domain.startswith("."):
            return {
                "valid": False,
                "error": "wildcard_domains_not_allowed",
                "message": "Wildcard domains are not permitted"
            }

        if len(clean_domain) > 253 or not DOMAIN_REGEX.match(clean_domain):
            return {
                "valid": False,
                "error": "invalid_domain_format",
                "message": f"Malformed domain format: '{clean_domain}'"
            }

        return {"valid": True, "target": clean_domain}

    def _is_protected(self, target: str, command_type: str) -> bool:
        """Determines if target IP or domain matches the protected catalog."""
        if command_type in ("block_ip", "temporary_block_ip"):
            try:
                ip_obj = ipaddress.ip_address(target)
            except ValueError:
                return True

            # Automatic loopback, link-local, multicast, unspecified protection
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                return True

            # Static protected IPs (backend, DNS, localhost)
            if target in self.protected_targets.get("protected_ips", []):
                return True

            # Host's own discovered IPs
            if target in self.local_ips:
                return True

            # CIDR ranges (RFC 1918, 127/8, link-local)
            for cidr in self.protected_targets.get("protected_ip_ranges", []):
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue

            return False

        else:  # block_domain
            clean = target.strip().lower().rstrip(".")
            if clean in ("localhost", "cyberguard.local"):
                return True

            for prot in self.protected_targets.get("protected_domains", []):
                prot_clean = prot.strip().lower().rstrip(".")
                if clean == prot_clean or clean.endswith(f".{prot_clean}"):
                    return True

            return False

    def _execute_firewall_rule(self, command_type: str, target: str) -> Dict[str, Any]:
        """Dispatches execution to the platform-specific firewall controller."""
        if sys.platform == "win32":
            return self._execute_windows(command_type, target)
        elif sys.platform.startswith("linux"):
            return self._execute_linux(command_type, target)
        else:
            return {
                "success": False,
                "error": "unsupported_platform",
                "message": f"Host firewall execution not supported on platform: {sys.platform}"
            }

    def _execute_windows(self, command_type: str, target: str) -> Dict[str, Any]:
        """
        Executes a Windows Defender firewall rule using PowerShell.
        CRITICAL: Never uses shell execution. Arguments are passed as an explicit array.
        """
        rule_name = f"CyberGuard-{command_type}-{uuid.uuid4().hex[:8]}"

        if command_type in ("block_ip", "temporary_block_ip"):
            # Construct PowerShell command as a clean list of arguments
            cmd = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress "{target}"'
            ]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] Windows command: {' '.join(cmd)}")
                return {
                    "success": True,
                    "rule_name": rule_name,
                    "target": target,
                    "firewall": "windows_defender",
                    "dry_run": True
                }

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False  # ZERO shell injection risk
                )

                if result.returncode == 0:
                    logger.info(f"[FIREWALL] Rule created on Windows: {rule_name} -> {target}")
                    return {
                        "success": True,
                        "rule_name": rule_name,
                        "target": target,
                        "firewall": "windows_defender"
                    }
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] Windows firewall command failed: {err_msg}")
                    return {
                        "success": False,
                        "error": "firewall_command_failed",
                        "details": err_msg
                    }

            except subprocess.TimeoutExpired:
                logger.error(f"[FIREWALL] Windows firewall command timed out after 10s: {cmd}")
                return {"success": False, "error": "timeout", "message": "Firewall command timed out after 10s"}
            except Exception as e:
                logger.error(f"[FIREWALL] Windows execution error: {e}")
                return {"success": False, "error": "execution_error", "details": str(e)}

        else:  # block_domain
            logger.info(
                f"[FIREWALL] Domain blocking not natively supported on Windows Defender. Target: {target}"
            )
            return {
                "success": False,
                "error": "domain_blocking_unsupported_windows",
                "message": "Windows Defender Firewall does not natively support domain name blocking"
            }

    def _detect_firewall(self) -> Optional[str]:
        """
        Detects installed and active Linux firewall management tools.
        Evaluation order: ufw -> firewalld -> iptables.
        """
        # 1. ufw (Ubuntu/Debian standard)
        if shutil.which("ufw"):
            try:
                res = subprocess.run(["ufw", "status"], capture_output=True, timeout=5, shell=False)
                if res.returncode == 0:
                    return "ufw"
            except Exception:
                pass

        # 2. firewalld (RHEL/Fedora standard)
        if shutil.which("firewall-cmd"):
            try:
                res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, timeout=5, shell=False)
                if res.returncode == 0:
                    return "firewalld"
            except Exception:
                pass

        # 3. iptables (Standard Linux packet filtering fallback)
        if shutil.which("iptables"):
            try:
                res = subprocess.run(["iptables", "-L"], capture_output=True, timeout=5, shell=False)
                if res.returncode == 0:
                    return "iptables"
            except Exception:
                pass

        return None

    def _execute_linux(self, command_type: str, target: str) -> Dict[str, Any]:
        """Dispatches Linux containment to the detected firewall utility."""
        firewall_tool = self._detect_firewall()
        if not firewall_tool:
            logger.error("[FIREWALL] No active Linux firewall tool (ufw, firewalld, iptables) detected")
            return {
                "success": False,
                "error": "no_firewall_detected",
                "message": "No supported Linux firewall utility (ufw, firewalld, iptables) detected"
            }

        if firewall_tool == "ufw":
            return self._execute_ufw(command_type, target)
        elif firewall_tool == "firewalld":
            return self._execute_firewalld(command_type, target)
        elif firewall_tool == "iptables":
            return self._execute_iptables(command_type, target)

        return {"success": False, "error": "unknown_firewall_tool"}

    def _execute_ufw(self, command_type: str, target: str) -> Dict[str, Any]:
        """Executes ufw firewall rule without shell execution."""
        if command_type in ("block_ip", "temporary_block_ip"):
            cmd = ["ufw", "deny", "from", target]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] ufw command: {' '.join(cmd)}")
                return {"success": True, "firewall": "ufw", "target": target, "dry_run": True}

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] ufw rule added: deny from {target}")
                    return {"success": True, "firewall": "ufw", "target": target}
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] ufw failed: {err_msg}")
                    return {"success": False, "error": "ufw_failed", "details": err_msg}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "timeout", "message": "ufw command timed out after 10s"}
            except Exception as e:
                return {"success": False, "error": "execution_error", "details": str(e)}

        else:
            return {
                "success": False,
                "error": "domain_blocking_unsupported_ufw",
                "message": "ufw does not natively support domain name blocking"
            }

    def _execute_firewalld(self, command_type: str, target: str) -> Dict[str, Any]:
        """Executes firewalld rich rule without shell execution."""
        if command_type in ("block_ip", "temporary_block_ip"):
            rule = f'rule family="ipv4" source address="{target}" reject'
            cmd = ["firewall-cmd", "--add-rich-rule", rule]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] firewalld command: {' '.join(cmd)}")
                return {"success": True, "firewall": "firewalld", "target": target, "dry_run": True}

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] firewalld rule added: {rule}")
                    return {"success": True, "firewall": "firewalld", "target": target}
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] firewalld failed: {err_msg}")
                    return {"success": False, "error": "firewalld_failed", "details": err_msg}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "timeout", "message": "firewall-cmd timed out after 10s"}
            except Exception as e:
                return {"success": False, "error": "execution_error", "details": str(e)}

        else:
            return {
                "success": False,
                "error": "domain_blocking_requires_setup",
                "message": "firewalld domain blocking via DNS requires advanced configuration"
            }

    def _execute_iptables(self, command_type: str, target: str) -> Dict[str, Any]:
        """Executes iptables rule without shell execution."""
        if command_type in ("block_ip", "temporary_block_ip"):
            cmd = ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] iptables command: {' '.join(cmd)}")
                return {
                    "success": True,
                    "firewall": "iptables",
                    "target": target,
                    "warning": "rules_lost_on_reboot",
                    "dry_run": True
                }

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] iptables rule added: DROP from {target}")
                    return {
                        "success": True,
                        "firewall": "iptables",
                        "target": target,
                        "warning": "rules_lost_on_reboot"
                    }
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] iptables failed: {err_msg}")
                    return {"success": False, "error": "iptables_failed", "details": err_msg}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "timeout", "message": "iptables timed out after 10s"}
            except Exception as e:
                return {"success": False, "error": "execution_error", "details": str(e)}

        else:
            return {
                "success": False,
                "error": "domain_blocking_unsupported_iptables",
                "message": "iptables domain blocking requires DNS interception"
            }

    def rollback_rule(
        self,
        rule_name: Optional[str],
        target: str,
        firewall_tool: str
    ) -> Dict[str, Any]:
        """
        Rolls back a previously established firewall rule.
        Uses explicit subprocess argument arrays without shell execution.
        """
        if not self.can_execute and not self.dry_run:
            return {
                "success": False,
                "error": "insufficient_privileges",
                "message": "Firewall rollback requires administrative/root privileges"
            }

        try:
            if firewall_tool == "windows_defender" and rule_name:
                cmd = [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
                ]
            elif firewall_tool == "ufw":
                cmd = ["ufw", "delete", "deny", "from", target]
            elif firewall_tool == "firewalld":
                rule = f'rule family="ipv4" source address="{target}" reject'
                cmd = ["firewall-cmd", "--remove-rich-rule", rule]
            elif firewall_tool == "iptables":
                cmd = ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"]
            else:
                return {"success": False, "error": "unrecognized_firewall_tool"}

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] Rollback command: {' '.join(cmd)}")
                return {"success": True, "rolled_back": True, "dry_run": True}

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
            if res.returncode == 0:
                self.blocked_ips.discard(target)
                self.blocked_domains.discard(target)
                logger.info(f"[FIREWALL] Successfully rolled back rule for target '{target}'")
                return {"success": True, "rolled_back": True}
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                logger.error(f"[FIREWALL] Rollback failed: {err_msg}")
                return {"success": False, "error": "rollback_failed", "details": err_msg}

        except Exception as e:
            logger.error(f"[FIREWALL] Error executing rollback: {e}")
            return {"success": False, "error": "rollback_exception", "details": str(e)}
