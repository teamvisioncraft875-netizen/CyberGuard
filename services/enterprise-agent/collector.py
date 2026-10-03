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

    now_iso = datetime.now(timezone.utc).isoformat()

    telemetry = {
        "hostname": hostname,
        "platform": client_platform,
        "os": os_detail,
        "network_conn_count": conn_count,
        "top_processes": top_procs,
        "user": user,
        "timestamp": now_iso,
    }

    logger.debug(
        f"Collected telemetry: host={hostname}, conns={conn_count}, procs={len(top_procs)}"
    )
    return telemetry
