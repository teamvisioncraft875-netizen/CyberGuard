"""
CYBERGUARD — Guard App Endpoint Telemetry Agent
Real OS-Level Host Network Flow Collector and Telemetry Adapter
"""

try:
    from .telemetry_adapter import adapt_sensor_telemetry
except (ImportError, ValueError):
    from telemetry_adapter import adapt_sensor_telemetry

__all__ = ["adapt_sensor_telemetry"]
