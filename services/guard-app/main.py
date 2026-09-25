"""
CYBERGUARD — Guard App Endpoint Sensor Daemon & CLI

Real OS-level network telemetry collection command for developers and background sensors.
Polls host sockets and interface counters, converts them to the exact CYBERGUARD
telemetry format, and optionally analyzes them directly or forwards them to the API Gateway.

Usage:
  # Capture 1 real network flow from local OS and print telemetry:
  python services/guard-app/main.py --once

  # Capture real flows and directly evaluate via ML Engine:
  python services/guard-app/main.py --count 3 --analyze

  # Run in simulated telemetry mode (for test runners without socket permissions):
  python services/guard-app/main.py --once --simulate

  # Forward continuous telemetry to the Express Gateway (requires JWT):
  python services/guard-app/main.py --gateway http://localhost:5000 --token <JWT>

OS Permissions:
  - Standard user: Can read global interface counters and user-owned sockets.
  - Administrator/Root: Optional. Enables full visibility into sockets owned by other system processes.
"""

import sys
import time
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

# Add guard-app to sys.path so local imports work when run as script
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from collector import NetworkFlowCollector, CollectorError


def send_to_ml_engine(telemetry: dict, ml_url: str = "http://127.0.0.1:8000") -> dict:
    """Dispatches flow telemetry directly to the FastAPI ML system analysis endpoint."""
    endpoint = f"{ml_url.rstrip('/')}/api/v1/analyze/system"
    payload = {
        "user_id": "guard_sensor_agent",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "network_flow_telemetry",
        "details": telemetry,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def send_to_gateway(telemetry: dict, gateway_url: str, token: str) -> dict:
    """Dispatches flow telemetry to the Node.js Express Gateway."""
    endpoint = f"{gateway_url.rstrip('/')}/api/telemetry/system-event"
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "network_flow_telemetry",
        "details": telemetry,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(
        description="CYBERGUARD Guard App — Real OS Network Flow Collector",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Capture a single flow and exit",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of flows to capture before stopping (default: continuous)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Sampling window duration in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Use simulated telemetry instead of live OS socket capture",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Send captured telemetry to local ML Engine (http://127.0.0.1:8000) for real-time threat scoring",
    )
    parser.add_argument(
        "--ml-url",
        type=str,
        default="http://127.0.0.1:8000",
        help="Base URL of CYBERGUARD ML Service",
    )
    parser.add_argument(
        "--gateway",
        type=str,
        default=None,
        help="Base URL of CYBERGUARD Express Gateway to forward telemetry",
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="JWT token for Express Gateway authentication",
    )

    args = parser.parse_args()

    mode_label = "SIMULATED" if args.simulate else "REAL OS-LEVEL CAPTURE"
    print("\n" + "=" * 65)
    print(f"  CYBERGUARD Guard App — Network Flow Collector ({mode_label})")
    print(f"  Sampling Interval: {args.interval}s")
    print("=" * 65)

    collector = NetworkFlowCollector(default_interval=args.interval, simulate=args.simulate)

    max_iterations = 1 if args.once else args.count
    iteration = 0

    try:
        while True:
            iteration += 1
            print(f"\n[Sample #{iteration}] Capturing host network flow ({args.interval}s window)...")
            flow = collector.capture_flow()

            print(f"  Protocol:        {flow['protocol'].upper()}")
            print(f"  Direction:       {flow['direction']}")
            print(f"  Source Port:     {flow['source_port']}")
            print(f"  Dest Port:       {flow['destination_port']}")
            print(f"  Total Bytes:     {flow['total_bytes']:.0f} bytes ({flow['source_bytes']:.0f} sent)")
            print(f"  Packet Count:    {flow['packet_count']:.0f} packets")
            print(f"  Duration:        {flow['duration']:.3f}s")

            if args.analyze:
                try:
                    res = send_to_ml_engine(flow, args.ml_url)
                    print(f"  [ML Engine] Risk Level: {res.get('risk_level')} (Score: {res.get('risk_score')}/100)")
                    print(f"  [ML Engine] Detector:   {res.get('signals', {}).get('detector_triggered')}")
                    print(f"  [ML Engine] Action:     {res.get('recommended_actions', ['None'])[0]}")
                except Exception as e:
                    print(f"  [ML Engine Error] Failed to evaluate flow: {e}")

            if args.gateway and args.token:
                try:
                    gw_res = send_to_gateway(flow, args.gateway, args.token)
                    print(f"  [Gateway] Status: {gw_res.get('status')} | Anomaly: {gw_res.get('anomaly_detected')}")
                except Exception as e:
                    print(f"  [Gateway Error] Failed to forward to gateway: {e}")

            if max_iterations is not None and iteration >= max_iterations:
                break

    except KeyboardInterrupt:
        print("\n[Guard App] Collector stopped by user.")
    except CollectorError as ce:
        print(f"\n[Guard App Fatal Collector Error] {ce}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[Guard App Error] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 65 + "\n")


if __name__ == "__main__":
    main()
