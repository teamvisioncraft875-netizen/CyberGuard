"""
CYBERGUARD — OS-Level Real Network Flow Collector

Lightweight, safe host network flow telemetry collector.
Captures real operating-system socket activity and I/O metrics using psutil:
- Delta byte and packet volumes across sampling interval
- Dominant active protocol (TCP / UDP)
- Source and destination port attribution from active socket tables
- Safe fallback when permissions are restricted (AccessDenied / PermissionError)
- Non-blocking, rate-limited execution suitable for background daemon operation
- Converts captured traffic into the EXACT format expected by the CYBERGUARD telemetry pipeline
"""

import time
import socket
from typing import Dict, Any, Optional, List
import psutil

try:
    from .telemetry_adapter import adapt_sensor_telemetry
except (ImportError, ValueError):
    from telemetry_adapter import adapt_sensor_telemetry


class CollectorError(Exception):
    """Raised when the network collector encounters an unrecoverable operating system error."""
    pass


class NetworkFlowCollector:
    """
    Host network flow sensor.
    Polls operating-system socket state and interface counters over a sampling window
    to produce calibrated network flow telemetry records.
    """

    def __init__(
        self,
        default_interval: float = 1.0,
        interface: Optional[str] = None,
        simulate: bool = False,
    ):
        self.default_interval = max(0.01, float(default_interval))
        self.interface = interface
        self.simulate = simulate

    def _get_io_counters(self) -> Any:
        """Retrieves raw OS net I/O counters, per interface if specified."""
        try:
            if self.interface:
                per_nic = psutil.net_io_counters(pernic=True)
                if self.interface in per_nic:
                    return per_nic[self.interface]
            return psutil.net_io_counters(pernic=False)
        except Exception as e:
            raise CollectorError(f"Failed to read OS network interface counters: {e}")

    def _get_active_connections(self) -> List[Any]:
        """
        Safely inspects OS socket table.
        Gracefully handles permission boundaries (e.g. non-root/non-admin restricted views).
        """
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Non-admin users on Windows/Linux may not inspect foreign PIDs;
            # fall back gracefully to empty connection list
            return []
        except Exception:
            return []

    def _attribute_flow_connection(self, connections: List[Any]) -> Dict[str, Any]:
        """
        Analyzes active connection list to attribute representative protocol and ports.
        Prioritizes active established outbound connections over loopback/listening.
        """
        # Look for active external connections
        for conn in connections:
            if conn.raddr and len(conn.raddr) >= 2:
                r_ip, r_port = conn.raddr[0], conn.raddr[1]
                # Filter out standard localhost
                if r_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    l_port = conn.laddr.port if conn.laddr else 0
                    return {
                        "protocol": proto,
                        "source_port": int(l_port),
                        "destination_port": int(r_port),
                        "direction": "outbound",
                    }

        # Fallback to listening or local sockets if no active remote flow
        if connections:
            first = connections[0]
            proto = "tcp" if first.type == socket.SOCK_STREAM else "udp"
            l_port = first.laddr.port if first.laddr else 0
            r_port = first.raddr.port if first.raddr and len(first.raddr) >= 2 else 0
            return {
                "protocol": proto,
                "source_port": int(l_port),
                "destination_port": int(r_port),
                "direction": "outbound" if r_port > 0 else "inbound",
            }

        # Default standard safe baseline when socket table is completely empty/restricted
        return {
            "protocol": "tcp",
            "source_port": 0,
            "destination_port": 0,
            "direction": "outbound",
        }

    def capture_flow(self, interval: Optional[float] = None) -> Dict[str, Any]:
        """
        Captures a single real network flow sample across the specified interval.
        Returns exact dictionary matching adapt_sensor_telemetry schema.
        """
        if self.simulate:
            return self._generate_simulated_flow()

        sample_window = float(interval) if interval is not None else self.default_interval
        sample_window = max(0.01, sample_window)

        # Snapshot T0
        t0 = time.time()
        io_start = self._get_io_counters()

        # Wait sample interval
        time.sleep(sample_window)

        # Snapshot T1
        io_end = self._get_io_counters()
        t1 = time.time()

        actual_duration = max(0.001, t1 - t0)

        # Calculate deltas (guaranteed non-negative)
        bytes_sent = max(0, io_end.bytes_sent - io_start.bytes_sent)
        bytes_recv = max(0, io_end.bytes_recv - io_start.bytes_recv)
        pkts_sent = max(0, io_end.packets_sent - io_start.packets_sent)
        pkts_recv = max(0, io_end.packets_recv - io_start.packets_recv)

        total_bytes = bytes_sent + bytes_recv
        total_packets = max(1, pkts_sent + pkts_recv)  # At least 1 to represent the sample window flow

        # Attribute socket metadata
        conns = self._get_active_connections()
        flow_meta = self._attribute_flow_connection(conns)

        raw_telemetry = {
            "duration": actual_duration,
            "packet_count": float(total_packets),
            "total_bytes": float(total_bytes),
            "source_bytes": float(bytes_sent),
            "protocol": flow_meta["protocol"],
            "source_port": flow_meta["source_port"],
            "destination_port": flow_meta["destination_port"],
            "direction": flow_meta["direction"],
        }

        # Adapt through standardized schema contract
        return adapt_sensor_telemetry(raw_telemetry)

    def _generate_simulated_flow(self) -> Dict[str, Any]:
        """Preserves existing simulated baseline for controlled testing environments."""
        raw = {
            "duration": 1.0,
            "packet_count": 15.0,
            "total_bytes": 2048.0,
            "source_bytes": 768.0,
            "protocol": "tcp",
            "source_port": 52100,
            "destination_port": 443,
            "direction": "outbound",
        }
        return adapt_sensor_telemetry(raw)
