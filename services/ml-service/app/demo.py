"""
CYBERGUARD — Phase 6.9 Standalone Engine Demonstration CLI

Developer-facing local demonstration tool for both CYBERGUARD detection engines:
1. URL & Phishing Threat Engine (Heuristic + Brand-Lookalike matcher)
2. System & Network Threat Engine (Hybrid HistGradientBoosting + IsolationForest)

Usage:
  python -m app.demo                # Runs comprehensive demo across both engines
  python -m app.demo --url <URL>    # Analyzes a specific URL
  python -m app.demo --network      # Runs representative network telemetry flows
"""

import sys
import json
import argparse
from typing import Optional

from app.schemas.analyze import (
    UrlAnalyzeRequest,
    SystemAnalyzeRequest,
)
from app.services.url_engine import analyze_url
from app.services.system_engine import analyze_system


SAMPLE_URLS = [
    ("Safe Portal", "https://cyberguard.io/documentation/architecture"),
    ("Credential Phish", "http://sl83684.pro/loading.php?user=amazon_account_update"),
    ("Brand Impersonation", "https://paypal-security-verification.com/login"),
    ("Raw IP Host", "http://192.168.1.105:8080/admin/panel"),
    ("Suspicious TLD", "https://corporate-support-portal.xyz/download"),
]

SAMPLE_FLOWS = [
    (
        "Normal Web HTTPS",
        {
            "dur": 1.25,
            "proto": "tcp",
            "sport": 54210,
            "dport": 443,
            "tot_pkts": 12,
            "tot_bytes": 1820,
            "src_bytes": 620,
            "dir": "out",
        },
    ),
    (
        "Outbound Surge Exfiltration",
        {
            "dur": 45.0,
            "proto": "tcp",
            "sport": 49152,
            "dport": 8080,
            "tot_pkts": 8500,
            "tot_bytes": 10485760,
            "src_bytes": 9800000,
            "dir": "out",
        },
    ),
    (
        "High-Frequency UDP Burst",
        {
            "dur": 0.05,
            "proto": "udp",
            "sport": 61234,
            "dport": 5353,
            "tot_pkts": 1200,
            "tot_bytes": 960000,
            "src_bytes": 960000,
            "dir": "out",
        },
    ),
]


def run_url_demo(specific_url: Optional[str] = None):
    print("\n" + "=" * 70)
    print("  CYBERGUARD — URL & Phishing Threat Engine Demonstration")
    print("  (Deterministic Heuristic Rule-Set + Brand-Lookalike Matching)")
    print("=" * 70)

    items = [("Custom URL", specific_url)] if specific_url else SAMPLE_URLS
    for label, target_url in items:
        req = UrlAnalyzeRequest(url=target_url)
        res = analyze_url(req)
        print(f"\n[Scenario: {label}]")
        print(f"  Target URL:    {target_url}")
        print(f"  Risk Level:    {res.risk_level.value}")
        print(f"  Risk Score:    {res.risk_score} / 100")
        print(f"  Target Brand:  {res.signals.get('target_brand')}")
        print(f"  Key Signals:   Keyword={res.signals.get('has_suspicious_keyword')}, TLD={res.signals.get('is_suspicious_tld')}, RawIP={res.signals.get('has_ip_address')}")
        print(f"  Explanation:   {res.explanation}")
        print(f"  Action:        {res.recommended_actions[0] if res.recommended_actions else 'N/A'}")


def run_network_demo():
    print("\n" + "=" * 70)
    print("  CYBERGUARD — System & Network Threat Engine Demonstration")
    print("  (Hybrid HistGradientBoosting [Supervised] + IsolationForest [Anomaly])")
    print("=" * 70)

    for label, flow_data in SAMPLE_FLOWS:
        req = SystemAnalyzeRequest(
            user_id="developer_demo",
            timestamp="2026-09-25T12:00:00Z",
            event_type="network_flow_telemetry",
            details=flow_data,
        )
        res = analyze_system(req)
        sig = res.signals
        print(f"\n[Scenario: {label}]")
        print(f"  Protocol/Bytes: {sig.get('protocol')} | {sig.get('total_bytes')} bytes | {sig.get('duration_seconds')}s")
        print(f"  Supervised P:   {sig.get('supervised_threat_probability')}")
        print(f"  Anomaly Score:  {sig.get('anomaly_score')}")
        print(f"  Detector:       {sig.get('detector_triggered')}")
        print(f"  Final Risk:     {res.risk_level.value} (Score: {res.risk_score} / 100)")
        print(f"  Explanation:    {res.explanation}")
        print(f"  Action:         {res.recommended_actions[0] if res.recommended_actions else 'N/A'}")


def main():
    parser = argparse.ArgumentParser(description="CYBERGUARD Standalone Detection Engine Demonstration")
    parser.add_argument("--url", type=str, help="Specific URL string to analyze")
    parser.add_argument("--network", action="store_true", help="Run only the network telemetry demo")
    args = parser.parse_args()

    if args.url:
        run_url_demo(args.url)
    elif args.network:
        run_network_demo()
    else:
        run_url_demo()
        run_network_demo()
    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    main()
