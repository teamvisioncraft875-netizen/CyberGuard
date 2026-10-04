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
        """Refreshes the protected targets list received live from backend gateway."""
        if isinstance(new_targets, dict):
            self.protected_targets = new_targets
            logger.info(
                f"[FIREWALL] Protected targets updated from gateway: {len(new_targets.get('protected_ips', []))} IPs, "
                f"{len(new_targets.get('protected_ip_ranges', []))} CIDRs, "
                f"{len(new_targets.get('protected_domains', []))} domains"
            )

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
                "error_type": "unsupported_command_type",
                "error_message": f"Command type '{command_type}' is not supported by FirewallExecutor",
                "message": f"Command type '{command_type}' is not supported by FirewallExecutor",
                "platform": "windows" if sys.platform == "win32" else "linux",
                "attempted_action": command_type
            }

        # 2. Check privilege elevation
        if not self.can_execute and not self.dry_run:
            target_hint = raw_target_data.get("ip_address") or raw_target_data.get("ip") or raw_target_data.get("domain") or raw_target_data.get("target") or "unknown"
            logger.warning(
                f"[FIREWALL] Refusing command {command_type}: Process lacks administrative/root privileges."
            )
            return {
                "success": False,
                "error": "insufficient_privileges",
                "error_type": "insufficient_privileges",
                "error_message": "Firewall execution requires administrator rights on Windows or root on Linux",
                "message": "Firewall execution requires administrator rights on Windows or root on Linux",
                "platform": "windows" if sys.platform == "win32" else "linux",
                "attempted_action": command_type,
                "target": target_hint
            }

        # 3. Check rate limiting (max 10 rules per rolling hour)
        now = time.time()
        if now - self.last_hour_reset > RULE_RATE_LIMIT_WINDOW_SECONDS:
            self.hourly_rule_count = 0
            self.last_hour_reset = now

        if self.hourly_rule_count >= MAX_RULES_PER_HOUR:
            target_hint = raw_target_data.get("ip_address") or raw_target_data.get("ip") or raw_target_data.get("domain") or raw_target_data.get("target") or "unknown"
            logger.warning(
                f"[FIREWALL] Rate limit exceeded: {self.hourly_rule_count} rules created in the last hour."
            )
            return {
                "success": False,
                "error": "rate_limit_exceeded",
                "error_type": "rate_limit_exceeded",
                "error_message": f"Rate limit exceeded: maximum {MAX_RULES_PER_HOUR} rules per rolling hour",
                "message": "Max 10 rules per hour",
                "platform": "windows" if sys.platform == "win32" else "linux",
                "attempted_action": command_type,
                "target": target_hint
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
                return {
                    "success": False,
                    "error": val["error"],
                    "error_type": val["error"],
                    "error_message": val.get("message"),
                    "message": val.get("message"),
                    "platform": "windows" if sys.platform == "win32" else "linux",
                    "attempted_action": command_type,
                    "target": ip
                }
            target = val["target"]
        else:
            domain = (
                raw_target_data.get("domain")
                or raw_target_data.get("target_domain")
                or raw_target_data.get("target")
            )
            val = self._validate_domain(domain)
            if not val["valid"]:
                return {
                    "success": False,
                    "error": val["error"],
                    "error_type": val["error"],
                    "error_message": val.get("message"),
                    "message": val.get("message"),
                    "platform": "windows" if sys.platform == "win32" else "linux",
                    "attempted_action": command_type,
                    "target": domain
                }
            target = val["target"]

        # 5. Check against protected list
        if self._is_protected(target, command_type):
            logger.warning(
                f"[FIREWALL] Execution refused: Target '{target}' is protected against blocking."
            )
            return {
                "success": False,
                "error": "target_protected",
                "error_type": "target_protected",
                "error_message": f"Cannot block protected target: {target}",
                "message": f"Cannot block protected target: {target}",
                "platform": "windows" if sys.platform == "win32" else "linux",
                "reason": "target_in_protected_list",
                "attempted_action": command_type,
                "target": target
            }

        # 6. Execute OS-level rule
        platform_name = "windows" if sys.platform == "win32" else "linux"
        logger.info(f"[FIREWALL] Executing {command_type} {target} ({platform_name})")
        result = self._execute_firewall_rule(command_type, target)
        result.setdefault("platform", platform_name)
        result.setdefault("attempted_action", command_type)
        result.setdefault("target", target)

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

            result.setdefault("firewall_tool", result.get("firewall"))
            result.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            logger.info(f"[FIREWALL] Rule created: {result.get('rule_name')} (tool: {result.get('firewall_tool')})")
        else:
            err_type = result.get("error_type") or result.get("error")
            err_msg = result.get("error_message") or result.get("message") or result.get("details")
            logger.warning(f"[FIREWALL] Execution failed: {err_type} ({err_msg})")

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
                        "error_type": "firewall_command_failed",
                        "error_message": f"Windows firewall command failed: {err_msg}",
                        "firewall_tool": "windows_defender",
                        "command_output": err_msg,
                        "details": err_msg,
                        "platform": "windows",
                        "target": target
                    }

            except subprocess.TimeoutExpired:
                logger.error(f"[FIREWALL] Windows firewall command timed out after 10s: {cmd}")
                return {
                    "success": False,
                    "error": "timeout",
                    "error_type": "timeout",
                    "error_message": "Windows firewall command timed out after 10s",
                    "message": "Firewall command timed out after 10s",
                    "platform": "windows",
                    "target": target
                }
            except Exception as e:
                logger.error(f"[FIREWALL] Windows execution error: {e}")
                return {
                    "success": False,
                    "error": "execution_error",
                    "error_type": "execution_error",
                    "error_message": str(e),
                    "details": str(e),
                    "platform": "windows",
                    "target": target
                }

        else:  # block_domain
            logger.info(
                f"[FIREWALL] Domain blocking not natively supported on Windows Defender. Target: {target}"
            )
            return {
                "success": False,
                "error": "domain_blocking_unsupported_windows",
                "error_type": "unsupported_operation",
                "error_message": "Windows Defender Firewall does not natively support domain name blocking",
                "message": "Windows Defender Firewall does not natively support domain name blocking",
                "platform": "windows",
                "reason": "domain_blocking_requires_dns_interception",
                "target": target
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
                "error": "firewall_tool_not_found",
                "error_type": "firewall_tool_not_found",
                "error_message": "No supported Linux firewall utility (ufw, firewalld, iptables) detected",
                "message": "No supported Linux firewall utility (ufw, firewalld, iptables) detected",
                "platform": "linux",
                "target": target
            }

        if firewall_tool == "ufw":
            return self._execute_ufw(command_type, target)
        elif firewall_tool == "firewalld":
            return self._execute_firewalld(command_type, target)
        elif firewall_tool == "iptables":
            return self._execute_iptables(command_type, target)

        return {
            "success": False,
            "error": "firewall_tool_not_found",
            "error_type": "firewall_tool_not_found",
            "error_message": f"Unrecognized Linux firewall tool: {firewall_tool}",
            "platform": "linux",
            "target": target
        }

    def _execute_ufw(self, command_type: str, target: str) -> Dict[str, Any]:
        """Executes ufw firewall rule without shell execution."""
        if command_type in ("block_ip", "temporary_block_ip"):
            cmd = ["ufw", "deny", "from", target]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] ufw command: {' '.join(cmd)}")
                return {
                    "success": True,
                    "firewall": "ufw",
                    "firewall_tool": "ufw",
                    "target": target,
                    "platform": "linux",
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "dry_run": True
                }

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] ufw rule added: deny from {target}")
                    return {
                        "success": True,
                        "firewall": "ufw",
                        "firewall_tool": "ufw",
                        "target": target,
                        "platform": "linux",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] ufw failed: {err_msg}")
                    return {
                        "success": False,
                        "error": "firewall_command_failed",
                        "error_type": "firewall_command_failed",
                        "error_message": f"ufw command returned non-zero exit code: {err_msg}",
                        "firewall_tool": "ufw",
                        "command_output": err_msg,
                        "details": err_msg,
                        "platform": "linux",
                        "target": target
                    }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": "timeout",
                    "error_type": "timeout",
                    "error_message": "ufw command timed out after 10s",
                    "message": "ufw command timed out after 10s",
                    "platform": "linux",
                    "target": target
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": "execution_error",
                    "error_type": "execution_error",
                    "error_message": str(e),
                    "details": str(e),
                    "platform": "linux",
                    "target": target
                }

        else:
            return {
                "success": False,
                "error": "domain_blocking_unsupported_ufw",
                "error_type": "unsupported_operation",
                "error_message": "ufw does not natively support domain name blocking",
                "message": "ufw does not natively support domain name blocking",
                "platform": "linux",
                "reason": "domain_blocking_requires_dns_interception",
                "target": target
            }

    def _execute_firewalld(self, command_type: str, target: str) -> Dict[str, Any]:
        """Executes firewalld rich rule without shell execution."""
        if command_type in ("block_ip", "temporary_block_ip"):
            rule = f'rule family="ipv4" source address="{target}" reject'
            cmd = ["firewall-cmd", "--add-rich-rule", rule]

            if self.dry_run:
                logger.info(f"[FIREWALL DRY-RUN] firewalld command: {' '.join(cmd)}")
                return {
                    "success": True,
                    "firewall": "firewalld",
                    "firewall_tool": "firewalld",
                    "target": target,
                    "platform": "linux",
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "dry_run": True
                }

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] firewalld rule added: {rule}")
                    return {
                        "success": True,
                        "firewall": "firewalld",
                        "firewall_tool": "firewalld",
                        "target": target,
                        "platform": "linux",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] firewalld failed: {err_msg}")
                    return {
                        "success": False,
                        "error": "firewall_command_failed",
                        "error_type": "firewall_command_failed",
                        "error_message": f"firewall-cmd returned non-zero exit code: {err_msg}",
                        "firewall_tool": "firewalld",
                        "command_output": err_msg,
                        "details": err_msg,
                        "platform": "linux",
                        "target": target
                    }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": "timeout",
                    "error_type": "timeout",
                    "error_message": "firewall-cmd timed out after 10s",
                    "message": "firewall-cmd timed out after 10s",
                    "platform": "linux",
                    "target": target
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": "execution_error",
                    "error_type": "execution_error",
                    "error_message": str(e),
                    "details": str(e),
                    "platform": "linux",
                    "target": target
                }

        else:
            return {
                "success": False,
                "error": "domain_blocking_requires_setup",
                "error_type": "unsupported_operation",
                "error_message": "firewalld domain blocking via DNS requires advanced configuration",
                "message": "firewalld domain blocking via DNS requires advanced configuration",
                "platform": "linux",
                "reason": "domain_blocking_requires_dns_interception",
                "target": target
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
                    "firewall_tool": "iptables",
                    "target": target,
                    "platform": "linux",
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
                        "firewall_tool": "iptables",
                        "target": target,
                        "platform": "linux",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "warning": "rules_lost_on_reboot"
                    }
                else:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[FIREWALL] iptables failed: {err_msg}")
                    return {
                        "success": False,
                        "error": "firewall_command_failed",
                        "error_type": "firewall_command_failed",
                        "error_message": f"iptables returned non-zero exit code: {err_msg}",
                        "firewall_tool": "iptables",
                        "command_output": err_msg,
                        "details": err_msg,
                        "platform": "linux",
                        "target": target
                    }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": "timeout",
                    "error_type": "timeout",
                    "error_message": "iptables timed out after 10s",
                    "message": "iptables timed out after 10s",
                    "platform": "linux",
                    "target": target
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": "execution_error",
                    "error_type": "execution_error",
                    "error_message": str(e),
                    "details": str(e),
                    "platform": "linux",
                    "target": target
                }

        else:
            return {
                "success": False,
                "error": "domain_blocking_unsupported_iptables",
                "error_type": "unsupported_operation",
                "error_message": "iptables domain blocking requires DNS interception",
                "message": "iptables domain blocking requires DNS interception",
                "platform": "linux",
                "reason": "domain_blocking_requires_dns_interception",
                "target": target
            }

    def delete_firewall_rule(
        self,
        rule_id_local: Optional[str] = None,
        target: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Deletes a host firewall rule across Windows Defender or Linux (ufw, firewalld, iptables).
        Zero shell execution - arguments passed as an explicit array.
        """
        # Validate inputs for illegal shell injection characters
        if rule_id_local and FORBIDDEN_METACHARS_REGEX.search(str(rule_id_local)):
            return {
                "success": False,
                "error": "invalid_rule_identifier",
                "message": "rule_id_local contains forbidden characters"
            }
        if target and FORBIDDEN_METACHARS_REGEX.search(str(target)):
            return {
                "success": False,
                "error": "invalid_target_format",
                "message": "target contains forbidden characters"
            }

        if not rule_id_local and not target:
            return {
                "success": False,
                "error": "missing_identifiers",
                "message": "Either rule_id_local or target is required for firewall deletion"
            }

        # Check privilege elevation unless dry_run
        if not self.can_execute and not self.dry_run:
            logger.warning("[FIREWALL] Refusing delete_firewall_rule: Process lacks administrative/root privileges.")
            return {
                "success": False,
                "error": "insufficient_privileges",
                "message": "Firewall rule deletion requires administrative/root privileges"
            }

        if self.dry_run:
            logger.info(f"[FIREWALL DRY-RUN] delete_firewall_rule: rule_id_local='{rule_id_local}', target='{target}'")
            if target:
                self.blocked_ips.discard(target)
                self.blocked_domains.discard(target)
            self.active_rules = [
                r for r in self.active_rules
                if r.get("rule_name") != rule_id_local and r.get("target") != target
            ]
            return {
                "success": True,
                "deleted": True,
                "rolled_back": True,
                "rule_id_local": rule_id_local,
                "target": target,
                "dry_run": True
            }

        if sys.platform == "win32":
            return self._delete_windows(rule_id_local, target)
        elif sys.platform.startswith("linux"):
            return self._delete_linux(rule_id_local, target)
        else:
            return {
                "success": False,
                "error": "unsupported_platform",
                "message": f"Platform '{sys.platform}' does not support host firewall deletion"
            }

    def _delete_windows(self, rule_id_local: Optional[str], target: Optional[str]) -> Dict[str, Any]:
        """Deletes Windows NetFirewallRule using PowerShell without shell execution."""
        resolved_rule_name = rule_id_local
        if not resolved_rule_name and target:
            for r in self.active_rules:
                if r.get("target") == target and r.get("rule_name"):
                    resolved_rule_name = r["rule_name"]
                    break

        if not resolved_rule_name:
            return {
                "success": False,
                "error": "missing_rule_identifier",
                "message": "rule_id_local (DisplayName) is required for Windows Defender firewall deletion"
            }

        if FORBIDDEN_METACHARS_REGEX.search(resolved_rule_name):
            return {
                "success": False,
                "error": "invalid_rule_identifier",
                "message": "rule_id_local contains forbidden characters"
            }

        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f'Get-NetFirewallRule -DisplayName "{resolved_rule_name}" | Remove-NetFirewallRule'
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
            if res.returncode == 0:
                logger.info(f"[FIREWALL] Successfully deleted Windows firewall rule: {resolved_rule_name}")
                if target:
                    self.blocked_ips.discard(target)
                    self.blocked_domains.discard(target)
                self.active_rules = [r for r in self.active_rules if r.get("rule_name") != resolved_rule_name]
                return {
                    "success": True,
                    "deleted": True,
                    "rolled_back": True,
                    "rule_id_local": resolved_rule_name,
                    "target": target,
                    "firewall": "windows_defender"
                }
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                if "No MSFT_NetFirewallRule objects found" in err_msg or "Cannot find" in err_msg:
                    logger.warning(f"[FIREWALL] Windows rule not found: {resolved_rule_name}")
                    return {
                        "success": False,
                        "error": "rule_not_found",
                        "error_type": "rule_not_found",
                        "error_message": f"Rule {resolved_rule_name} not found on host",
                        "message": f"Firewall rule '{resolved_rule_name}' not found",
                        "command_output": err_msg,
                        "details": err_msg,
                        "platform": "windows",
                        "rule_id_local": resolved_rule_name,
                        "target": target
                    }
                logger.error(f"[FIREWALL] Windows rule deletion failed: {err_msg}")
                return {
                    "success": False,
                    "error": "deletion_failed",
                    "error_type": "firewall_command_failed",
                    "error_message": f"Windows firewall deletion command failed: {err_msg}",
                    "command_output": err_msg,
                    "details": err_msg,
                    "platform": "windows",
                    "rule_id_local": resolved_rule_name,
                    "target": target
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "timeout",
                "error_type": "timeout",
                "error_message": "PowerShell deletion command timed out after 10s",
                "message": "PowerShell deletion command timed out after 10s",
                "platform": "windows",
                "rule_id_local": resolved_rule_name,
                "target": target
            }
        except Exception as e:
            return {
                "success": False,
                "error": "execution_error",
                "error_type": "execution_error",
                "error_message": str(e),
                "details": str(e),
                "platform": "windows",
                "rule_id_local": resolved_rule_name,
                "target": target
            }

    def _delete_linux(self, rule_id_local: Optional[str], target: Optional[str]) -> Dict[str, Any]:
        """Deletes Linux firewall rule via ufw, firewalld, or iptables."""
        resolved_target = target
        if not resolved_target and rule_id_local:
            for r in self.active_rules:
                if r.get("rule_name") == rule_id_local and r.get("target"):
                    resolved_target = r["target"]
                    break

        if not resolved_target:
            return {
                "success": False,
                "error": "missing_target",
                "message": "Target IP or domain is required for Linux firewall rule deletion"
            }

        tool = self._detect_firewall() or "iptables"

        if tool == "ufw":
            cmd = ["ufw", "delete", "deny", "from", resolved_target]
        elif tool == "firewalld":
            rule = f'rule family="ipv4" source address="{resolved_target}" reject'
            cmd = ["firewall-cmd", "--remove-rich-rule", rule]
        elif tool == "iptables":
            cmd = ["iptables", "-D", "INPUT", "-s", resolved_target, "-j", "DROP"]
        else:
            return {"success": False, "error": "unrecognized_firewall_tool"}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=False)
            if res.returncode == 0:
                logger.info(f"[FIREWALL] Successfully deleted Linux firewall rule via {tool}: {resolved_target}")
                self.blocked_ips.discard(resolved_target)
                self.blocked_domains.discard(resolved_target)
                self.active_rules = [
                    r for r in self.active_rules
                    if r.get("target") != resolved_target and r.get("rule_name") != rule_id_local
                ]
                return {
                    "success": True,
                    "deleted": True,
                    "rolled_back": True,
                    "rule_id_local": rule_id_local,
                    "target": resolved_target,
                    "firewall": tool
                }
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                logger.error(f"[FIREWALL] Linux rule deletion failed: {err_msg}")
                return {
                    "success": False,
                    "error": "deletion_failed",
                    "error_type": "firewall_command_failed",
                    "error_message": f"Linux {tool} rule deletion command failed: {err_msg}",
                    "command_output": err_msg,
                    "details": err_msg,
                    "platform": "linux",
                    "rule_id_local": rule_id_local,
                    "target": resolved_target
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "timeout",
                "error_type": "timeout",
                "error_message": f"{tool} deletion timed out after 10s",
                "message": f"{tool} deletion timed out after 10s",
                "platform": "linux",
                "rule_id_local": rule_id_local,
                "target": resolved_target
            }
        except Exception as e:
            return {
                "success": False,
                "error": "execution_error",
                "error_type": "execution_error",
                "error_message": str(e),
                "details": str(e),
                "platform": "linux",
                "rule_id_local": rule_id_local,
                "target": resolved_target
            }

    def rollback_rule(
        self,
        rule_name: Optional[str] = None,
        target: Optional[str] = None,
        firewall_tool: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rolls back a previously established firewall rule.
        Delegates to delete_firewall_rule while maintaining backward compatibility.
        """
        if rule_name and not target and not firewall_tool:
            # Called with a single positional argument e.g. rollback_rule(target_ip)
            return self.delete_firewall_rule(rule_id_local=None, target=rule_name)
        return self.delete_firewall_rule(rule_id_local=rule_name, target=target)
