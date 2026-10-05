"""
CYBERGUARD Enterprise Agent — OS Telemetry Collector
Safely gathers non-intrusive operating system, process, and network telemetry.
Strictly adheres to safety constraints: NO process killing, NO file dumping, NO credential access.
"""

import os
import sys
import socket
import platform
import getpass
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List
import psutil

from logger import get_logger

logger = get_logger()


def get_current_user() -> str:
    """Safely resolves current operating system user identity."""
    try:
        return os.getlogin()
    except Exception:
        try:
            return getpass.getuser()
        except Exception:
            return "unknown-user"


def get_host_ip_addresses() -> List[str]:
    """Resolves local host IP addresses to prevent self-containment/lockout."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            ips.add(ip)
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    return sorted(list(ips))


def get_network_connection_count() -> int:
    """
    Safely counts open network sockets without exposing remote hosts or sensitive socket data.
    Gracefully handles restricted permissions across Linux/Windows/macOS.
    """
    try:
        connections = psutil.net_connections(kind="inet")
        return len(connections)
    except (psutil.AccessDenied, PermissionError, ProcessLookupError):
        # Non-admin or restricted privilege environment
        logger.debug("Permission restricted reading network connections; defaulting to 0")
        return 0
    except Exception as e:
        logger.debug(f"Network connection query exception: {e}")
        return 0


def get_top_processes(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Gathers top processes sorted by CPU and memory usage.
    Captures only PID, PPID, process name, and resource percentages.
    NEVER accesses command lines with passwords, file descriptors, or process memory.
    Gracefully handles PermissionError and ProcessLookupError.
    """
    processes = []

    try:
        proc_iter = psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 'memory_percent'])
    except (psutil.AccessDenied, PermissionError, ProcessLookupError, Exception) as e:
        logger.debug(f"Failed to initialize process_iter: {e}")
        return []

    # Prime CPU percent measurement for accurate instantaneous or interval reads
    for proc in proc_iter:
        try:
            info = proc.info
            name = info.get('name') or 'unknown'
            pid = info.get('pid') or 0
            ppid = info.get('ppid') or 0
            cpu_pct = round(info.get('cpu_percent') or 0.0, 1)
            mem_pct = round(info.get('memory_percent') or 0.0, 1)

            processes.append({
                "name": name,
                "pid": pid,
                "ppid": ppid,
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, PermissionError, ProcessLookupError):
            continue
        except Exception:
            continue

    try:
        # Sort descending by CPU percentage, secondary sort by Memory percentage
        processes.sort(key=lambda p: (p["cpu_pct"], p["mem_pct"]), reverse=True)
        return processes[:limit]
    except Exception as e:
        logger.debug(f"Error sorting top processes: {e}")
        return processes[:limit]



# Allowed well-known UDP service ports for Attack Surface Discovery (Phase A)
ALLOWED_UDP_SERVICE_PORTS = {53, 67, 68, 69, 123, 161, 162, 514}


def classify_exposure_scope(bind_address: str) -> str:
    """
    Classifies an IP bind address into 'loopback', 'private', 'public', or 'unknown'.
    - 127.0.0.1 / ::1 -> loopback
    - RFC1918 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) -> private
    - IPv6 private (fc00::/7, fd00::/8, fe80::/10) -> private
    - 0.0.0.0 / :: -> public
    - otherwise -> unknown
    """
    if not bind_address or not isinstance(bind_address, str):
        return "unknown"

    clean_ip = bind_address.strip().lower()

    if clean_ip in ("127.0.0.1", "::1", "localhost"):
        return "loopback"

    if clean_ip in ("0.0.0.0", "::", "*"):
        return "public"

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_loopback:
            return "loopback"

        # Explicit RFC 1918 private IPv4 subnets
        rfc1918_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if any(ip_obj in net for net in rfc1918_networks):
            return "private"

        # Explicit IPv6 Private / ULA / Link-Local subnets
        ipv6_private_subnets = (
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fd00::/8"),
            ipaddress.ip_network("fe80::/10"),
        )
        if any(ip_obj in net for net in ipv6_private_subnets) or getattr(ip_obj, "is_link_local", False):
            return "private"

        return "unknown"
    except ValueError:
        return "unknown"


def collect_listening_ports(max_ports: int = 100) -> List[Dict[str, Any]]:
    """
    Safely gathers listening TCP sockets and allowed UDP service sockets.
    - Collects only TCP sockets with status == psutil.CONN_LISTEN.
    - Collects only UDP sockets matching ALLOWED_UDP_SERVICE_PORTS without remote addr.
    - All ephemeral UDP client sockets (DNS/NTP/WebRTC clients) are ignored.
    - NEVER collects established outbound connections.
    - NEVER collects command-line arguments or environment variables.
    - Normalizes file paths to POSIX slashes ('/').
    - Gracefully handles AccessDenied, NoSuchProcess, and restricted environments.
    - Capped at max_ports (default 100).
    """
    listening_ports = []
    seen = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, ProcessLookupError) as e:
        logger.debug(f"Permission restricted reading listening connections: {e}")
        return []
    except Exception as e:
        logger.debug(f"Exception querying net_connections: {e}")
        return []

    listen_status = getattr(psutil, "CONN_LISTEN", "LISTEN")

    for conn in connections:
        if len(listening_ports) >= max_ports:
            break

        try:
            if not conn.laddr or not hasattr(conn.laddr, "port"):
                continue

            port = int(conn.laddr.port)
            if port <= 0 or port > 65535:
                continue

            # Check for LISTEN state (TCP) or allowed well-known UDP service socket
            is_tcp_listen = (conn.type == socket.SOCK_STREAM and conn.status == listen_status)
            is_udp_listen = (
                conn.type == socket.SOCK_DGRAM
                and not conn.raddr
                and port in ALLOWED_UDP_SERVICE_PORTS
            )

            if not (is_tcp_listen or is_udp_listen):
                continue

            bind_addr = str(conn.laddr.ip) if hasattr(conn.laddr, "ip") else "0.0.0.0"
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"

            dedup_key = (port, proto, bind_addr)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            scope = classify_exposure_scope(bind_addr)

            pid = conn.pid
            process_name = None
            process_path = None

            if pid:
                try:
                    proc = psutil.Process(pid)
                    try:
                        process_name = proc.name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, Exception):
                        process_name = None

                    try:
                        exe_path = proc.exe()
                        if exe_path:
                            # Normalize Windows backslashes to forward slashes
                            exe_path = exe_path.replace("\\", "/")
                            if len(exe_path) > 255:
                                exe_path = exe_path[:255]
                        process_path = exe_path
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, Exception):
                        process_path = None
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception):
                    process_name = None
                    process_path = None

            listening_ports.append({
                "port": port,
                "protocol": proto,
                "bind_address": bind_addr,
                "exposure_scope": scope,
                "pid": pid,
                "process_name": process_name,
                "process_path": process_path,
            })
        except Exception as conn_err:
            logger.debug(f"Skipping listening socket entry due to error: {conn_err}")
            continue

    return listening_ports


def collect_system_telemetry() -> Dict[str, Any]:
    """
    Gathers the complete OS telemetry snapshot payload.
    Gracefully falls back to safe defaults if any system or psutil call raises an exception.
    """
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown-host"

    try:
        os_sys = platform.system() or "Unknown"
        os_detail = f"{os_sys} {platform.release()}"
    except Exception:
        os_detail = "Unknown OS"

    client_platform = sys.platform or "unknown"

    try:
        user = get_current_user()
    except Exception:
        user = "unknown-user"

    try:
        conn_count = get_network_connection_count()
    except Exception:
        conn_count = 0

    try:
        top_procs = get_top_processes(limit=10)
    except Exception:
        top_procs = []

    try:
        listening_ports = collect_listening_ports(max_ports=100)
    except Exception as e:
        logger.debug(f"Error collecting listening ports: {e}")
        listening_ports = []

    now_iso = datetime.now(timezone.utc).isoformat()

    telemetry = {
        "hostname": hostname,
        "platform": client_platform,
        "os": os_detail,
        "network_conn_count": conn_count,
        "top_processes": top_procs,
        "user": user,
        "timestamp": now_iso,
        "attack_surface": {
            "listening_ports": listening_ports
        }
    }

    logger.debug(
        f"Collected telemetry: host={hostname}, conns={conn_count}, procs={len(top_procs)}, "
        f"listening_ports={len(listening_ports)}"
    )
    return telemetry

