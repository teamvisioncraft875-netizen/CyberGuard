"""
CYBERGUARD — Guard App Endpoint Telemetry Collector Adapter

Standardizes sensor telemetry collected on endpoints before dispatching
to the CYBERGUARD API Gateway (/api/v1/telemetry/system-event).
"""

from typing import Dict, Any, Optional

WELL_KNOWN_PORTS = range(1, 1024)


def adapt_sensor_telemetry(sensor_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Standardizes sensor telemetry for network event ingestion.
    """
    if not sensor_data:
        sensor_data = {}

    return {
        "duration": float(sensor_data.get("duration", sensor_data.get("dur", 0.0))),
        "packet_count": float(sensor_data.get("packet_count", sensor_data.get("tot_pkts", 1.0))),
        "total_bytes": float(sensor_data.get("total_bytes", sensor_data.get("tot_bytes", 0.0))),
        "source_bytes": float(sensor_data.get("source_bytes", sensor_data.get("src_bytes", 0.0))),
        "protocol": str(sensor_data.get("protocol", sensor_data.get("proto", "tcp"))).lower(),
        "source_port": int(sensor_data.get("source_port", sensor_data.get("sport", 0))),
        "destination_port": int(sensor_data.get("destination_port", sensor_data.get("dport", 0))),
        "direction": str(sensor_data.get("direction", sensor_data.get("dir", "outbound"))),
    }
