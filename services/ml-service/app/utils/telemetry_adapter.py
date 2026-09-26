"""
CYBERGUARD — Guard App Telemetry Adapter (Phase 4.7)

Transforms raw endpoint and network sensor telemetry produced by Guard App
into the standardized 14-dimensional numerical feature matrix expected by
the System & Network Threat Engine (system_engine.py and NetworkThreatModel).

Guarantees:
- Safe numeric type casting with fallback defaults.
- Zero-division safety on rate and ratio calculations.
- Handling of missing, null, or malformed fields without exceptions.
- Protocol and port one-hot encoding according to CTU-13 conventions.
"""

from typing import Dict, Any, Optional

WELL_KNOWN_PORTS = range(1, 1024)


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely converts arbitrary value to finite float."""
    if val is None:
        return default
    try:
        f = float(val)
        return default if (f != f or f == float("inf") or f == float("-inf")) else f
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely converts arbitrary value to integer."""
    if val is None:
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def transform_guard_telemetry(raw_telemetry: Optional[Dict[str, Any]]) -> Dict[str, float]:
    """
    Transforms Guard App sensor telemetry dictionary into exact FEATURE_COLUMNS format.

    Supported input field aliases:
    - duration: 'duration', 'dur', 'duration_seconds'
    - packet count: 'packet_count', 'tot_pkts', 'packets', 'total_packets'
    - total bytes: 'total_bytes', 'tot_bytes', 'bytes', 'outbound_bytes'
    - source bytes: 'source_bytes', 'src_bytes', 'bytes_sent'
    - protocol: 'protocol', 'proto', 'protocol_name'
    - source port: 'source_port', 'sport', 'src_port'
    - destination port: 'destination_port', 'dest_port', 'dport', 'remote_port'
    - direction: 'direction', 'dir', 'traffic_direction'
    """
    if not raw_telemetry or not isinstance(raw_telemetry, dict):
        raw_telemetry = {}

    dur = max(0.0, _safe_float(
        raw_telemetry.get("duration",
        raw_telemetry.get("dur",
        raw_telemetry.get("duration_seconds", 0.0)))
    ))

    tot_pkts = max(0.0, _safe_float(
        raw_telemetry.get("packet_count",
        raw_telemetry.get("tot_pkts",
        raw_telemetry.get("packets",
        raw_telemetry.get("total_packets", 1.0))))
    ))

    tot_bytes = max(0.0, _safe_float(
        raw_telemetry.get("total_bytes",
        raw_telemetry.get("tot_bytes",
        raw_telemetry.get("bytes",
        raw_telemetry.get("outbound_bytes", 0.0))))
    ))

    src_bytes = max(0.0, _safe_float(
        raw_telemetry.get("source_bytes",
        raw_telemetry.get("src_bytes",
        raw_telemetry.get("bytes_sent", tot_bytes)))
    ))

    # Derived rates and ratios
    dur_divisor = max(dur, 0.0001)
    packet_rate = tot_pkts / dur_divisor
    byte_rate = tot_bytes / dur_divisor
    avg_packet_size = tot_bytes / max(tot_pkts, 1.0)
    src_byte_ratio = min(1.0, max(0.0, src_bytes / max(tot_bytes, 1.0)))

    # Protocol flags
    raw_proto = str(raw_telemetry.get("protocol", raw_telemetry.get("proto", "tcp"))).lower().strip()
    proto_tcp = 1.0 if ("tcp" in raw_proto or raw_proto == "6") else 0.0
    proto_udp = 1.0 if ("udp" in raw_proto or raw_proto == "17") else 0.0
    proto_icmp = 1.0 if ("icmp" in raw_proto or raw_proto == "1") else 0.0
    proto_other = 1.0 if (proto_tcp == 0.0 and proto_udp == 0.0 and proto_icmp == 0.0) else 0.0

    # Destination Port
    dport = _safe_int(
        raw_telemetry.get("destination_port",
        raw_telemetry.get("dest_port",
        raw_telemetry.get("dport",
        raw_telemetry.get("remote_port", 0))))
    )
    is_well_known_dport = 1.0 if dport in WELL_KNOWN_PORTS else 0.0

    # Direction
    raw_dir = str(raw_telemetry.get("direction", raw_telemetry.get("dir", ""))).lower().strip()
    is_bidirectional = 1.0 if (
        "<->" in raw_dir
        or "bidirectional" in raw_dir
        or "both" in raw_dir
        or (src_bytes > 0 and tot_bytes > src_bytes)
    ) else 0.0

    return {
        "dur": float(dur),
        "tot_pkts": float(tot_pkts),
        "tot_bytes": float(tot_bytes),
        "src_bytes": float(src_bytes),
        "packet_rate": float(round(packet_rate, 4)),
        "byte_rate": float(round(byte_rate, 4)),
        "avg_packet_size": float(round(avg_packet_size, 4)),
        "src_byte_ratio": float(round(src_byte_ratio, 4)),
        "proto_tcp": float(proto_tcp),
        "proto_udp": float(proto_udp),
        "proto_icmp": float(proto_icmp),
        "proto_other": float(proto_other),
        "is_well_known_dport": float(is_well_known_dport),
        "is_bidirectional": float(is_bidirectional),
    }
