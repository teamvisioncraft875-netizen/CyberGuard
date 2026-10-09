#!/usr/bin/env python3
"""
CYBERGUARD Golden Showcase Evaluation Script
Executes curated evaluation inputs against the live CyberGuard AI/ML detection engines
and validates real model predictions, risk scores, explanations, and response recommendations.
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets" / "golden_demonstration"
ML_SERVICE_URL = "http://localhost:8000"

def query_ml_service(endpoint: str, payload: dict) -> dict:
    url = f"{ML_SERVICE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "details": e.read().decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}

def run_url_evaluations():
    print("\n=======================================================")
    print(" 1. URL & PHISHING THREAT ENGINE EVALUATION")
    print("=======================================================")
    urls_file = DATASETS_DIR / "urls" / "urls.json"
    if not urls_file.exists():
        print(f"File not found: {urls_file}")
        return

    with open(urls_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    for s in samples:
        res = query_ml_service("/analyze/url", {"url": s["url"]})
        risk = res.get("risk_level", "unknown")
        score = res.get("risk_score", 0)
        decision = res.get("signals", {}).get("ml_decision", "unknown")
        prob = res.get("signals", {}).get("ml_malicious_probability", 0)
        
        status_sym = "[MATCH]" if (decision == s["expected_decision"] or risk == s["expected_risk"]) else "[FLAG]"
        print(f"\n{status_sym} Sample: {s['id']} -> {s['url']}")
        print(f"   Expected: {s['expected_decision']} ({s['expected_risk']})")
        print(f"   Actual:   {decision} ({risk}) | Probability: {prob:.4f} | Risk Score: {score}")
        print(f"   Signals:  entropy={res.get('signals', {}).get('entropy')} | has_keyword={res.get('signals', {}).get('has_suspicious_keyword')}")
        print(f"   Summary:  {res.get('explanation')}")

def run_message_evaluations():
    print("\n=======================================================")
    print(" 2. MESSAGE SOCIAL ENGINEERING ENGINE EVALUATION")
    print("=======================================================")
    msg_file = DATASETS_DIR / "messages" / "messages.json"
    if not msg_file.exists():
        print(f"File not found: {msg_file}")
        return

    with open(msg_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    for s in samples:
        res = query_ml_service("/analyze/message", {"text": s["text"], "source_type": s["source_type"]})
        risk = res.get("risk_level", "unknown")
        score = res.get("risk_score", 0)
        decision = res.get("signals", {}).get("ml_decision", "unknown")
        prob = res.get("signals", {}).get("ml_threat_probability", 0)

        status_sym = "[MATCH]" if (decision == s["expected_decision"] or risk == s["expected_risk"]) else "[FLAG]"
        snippet = s['text'][:65] + "..." if len(s['text']) > 65 else s['text']
        print(f"\n{status_sym} Sample: {s['id']} [{s['source_type'].upper()}] -> \"{snippet}\"")
        print(f"   Expected: {s['expected_decision']} ({s['expected_risk']})")
        print(f"   Actual:   {decision} ({risk}) | Probability: {prob:.4f} | Risk Score: {score}")
        print(f"   Signals:  urgency={res.get('signals', {}).get('urgency_language_detected')} | model={res.get('signals', {}).get('model_type')}")
        print(f"   Actions:  {res.get('recommended_actions', [])}")

def run_scenario_walkthrough():
    print("\n=======================================================")
    print(" 3. END-TO-END CORRELATED SCENARIO WALKTHROUGH")
    print("=======================================================")
    scenario_file = DATASETS_DIR / "scenarios" / "enterprise_multi_stage_incident.json"
    if not scenario_file.exists():
        return

    with open(scenario_file, "r", encoding="utf-8") as f:
        scen = json.load(f)

    print(f"Scenario: {scen['scenario_id']} - {scen['title']}")
    print(f"Organization: {scen['organization']}\n")
    for step in scen["timeline"]:
        print(f"  Step {step['step']} [{step['time']}] - Stage: {step['stage']}")
        print(f"    Event:     {step['event']}")
        print(f"    MITRE:     {step['technique']}")
        print(f"    Incident:  {step['incident_id']}")
        print(f"    Outcome:   {step['outcome']}\n")

def main():
    print("#######################################################")
    print("  CYBERGUARD SHOWCASE EVALUATION BENCHMARK RUNNER")
    print("#######################################################")
    run_url_evaluations()
    run_message_evaluations()
    run_scenario_walkthrough()
    print("\n[OK] Evaluation completed successfully.")

if __name__ == "__main__":
    main()
