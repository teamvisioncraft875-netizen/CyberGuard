"""
CYBERGUARD — Guard App Network Flow Collector Unit Tests

Tests:
1. Standard flow capture with mocked OS counters and socket table
2. Simulation mode behavior
3. PermissionError / AccessDenied resilience
4. Interface / OS I/O counter failure handling (raises CollectorError, never false Safe)
5. Schema compliance against adapt_sensor_telemetry contract
"""

import sys
import socket
from pathlib import Path
from collections import namedtuple
from unittest.mock import patch, MagicMock
import pytest

_GUARD_DIR = str(Path(__file__).resolve().parent)
if _GUARD_DIR not in sys.path:
    sys.path.insert(0, _GUARD_DIR)

from collector import NetworkFlowCollector, CollectorError

IOCounters = namedtuple("IOCounters", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv"])
Connection = namedtuple("Connection", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
Addr = namedtuple("Addr", ["ip", "port"])


def test_collector_simulated_mode():
    """Verify simulation mode produces contract-compliant telemetry without OS polling."""
    collector = NetworkFlowCollector(simulate=True)
    flow = collector.capture_flow()

    assert isinstance(flow, dict)
    assert flow["duration"] == 1.0
    assert flow["protocol"] == "tcp"
    assert flow["destination_port"] == 443
    assert flow["total_bytes"] == 2048.0
    assert flow["direction"] == "outbound"


def test_collector_mocked_os_flow_capture():
    """Verify real capture pipeline with mocked psutil I/O counters and connection tables."""
    collector = NetworkFlowCollector(default_interval=0.01)

    io_t0 = IOCounters(bytes_sent=1000, bytes_recv=2000, packets_sent=10, packets_recv=20)
    io_t1 = IOCounters(bytes_sent=2500, bytes_recv=4000, packets_sent=25, packets_recv=45)

    mock_conn = Connection(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=Addr(ip="10.0.0.5", port=54321),
        raddr=Addr(ip="93.184.216.34", port=443),
        status="ESTABLISHED",
        pid=1234,
    )

    with patch.object(collector, "_get_io_counters", side_effect=[io_t0, io_t1]), \
         patch.object(collector, "_get_active_connections", return_value=[mock_conn]), \
         patch("time.sleep", return_value=None):

        flow = collector.capture_flow(interval=0.01)

        assert flow["protocol"] == "tcp"
        assert flow["source_port"] == 54321
        assert flow["destination_port"] == 443
        assert flow["direction"] == "outbound"
        assert flow["source_bytes"] == 1500.0  # 2500 - 1000
        assert flow["total_bytes"] == 3500.0   # (2500-1000) + (4000-2000)
        assert flow["packet_count"] == 40.0    # (25-10) + (45-20)


def test_collector_permission_denied_resilience():
    """Verify that socket permission denial does not crash the collector and attributes safe fallback."""
    import psutil
    collector = NetworkFlowCollector(default_interval=0.01)

    io_t0 = IOCounters(bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0)
    io_t1 = IOCounters(bytes_sent=500, bytes_recv=500, packets_sent=5, packets_recv=5)

    with patch.object(collector, "_get_io_counters", side_effect=[io_t0, io_t1]), \
         patch("psutil.net_connections", side_effect=psutil.AccessDenied()), \
         patch("time.sleep", return_value=None):

        flow = collector.capture_flow(interval=0.01)

        assert isinstance(flow, dict)
        assert flow["total_bytes"] == 1000.0
        assert flow["packet_count"] == 10.0
        assert flow["protocol"] == "tcp"
        assert flow["source_port"] == 0
        assert flow["destination_port"] == 0


def test_collector_os_counter_failure_raises_collector_error():
    """Verify that unrecoverable OS counter read failure raises CollectorError, never false Safe."""
    collector = NetworkFlowCollector(default_interval=0.01)

    with patch("psutil.net_io_counters", side_effect=RuntimeError("Kernel interface read failed")):
        with pytest.raises(CollectorError):
            collector.capture_flow()


def test_collector_live_capture_smoke():
    """Executes a real 0.05-second capture on the active system to verify live compatibility."""
    collector = NetworkFlowCollector(default_interval=0.05)
    flow = collector.capture_flow()

    assert isinstance(flow, dict)
    assert flow["duration"] >= 0.04
    assert flow["packet_count"] >= 1.0
    assert flow["protocol"] in ["tcp", "udp", "icmp"]
    assert isinstance(flow["source_port"], int)
    assert isinstance(flow["destination_port"], int)


def test_collector_zero_delta_idle_flow():
    """Verify that an idle window with 0 delta bytes/packets produces safe finite metrics without zero division."""
    collector = NetworkFlowCollector(default_interval=0.01)

    io_t0 = IOCounters(bytes_sent=10000, bytes_recv=10000, packets_sent=100, packets_recv=100)
    io_t1 = IOCounters(bytes_sent=10000, bytes_recv=10000, packets_sent=100, packets_recv=100)

    with patch.object(collector, "_get_io_counters", side_effect=[io_t0, io_t1]), \
         patch.object(collector, "_get_active_connections", return_value=[]), \
         patch("time.sleep", return_value=None):

        flow = collector.capture_flow(interval=0.01)

        assert flow["total_bytes"] == 0.0
        assert flow["source_bytes"] == 0.0
        assert flow["packet_count"] >= 1.0
        assert flow["duration"] >= 0.001
        assert flow["protocol"] == "tcp"
        assert flow["source_port"] == 0
        assert flow["destination_port"] == 0
