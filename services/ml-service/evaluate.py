"""
CyberGuard ML Service - Login Anomaly Engine Comprehensive Evaluation & Audit Benchmark
Evaluates the Isolation Forest behavioral engine on unseen realistic telemetry,
including legitimate borderline cases (new devices, travel, typos, nocturnal logins, weak signals)
and active injected threat scenarios.
"""

import json
import time
from typing import Any, Dict, List
import numpy as np

from app.services.login_anomaly import (
    LoginAnomalyEngine,
    LoginEvent,
    SyntheticTelemetryGenerator,
)


def run_evaluation():
    print("=" * 80)
    print("CYBERGUARD — Login & Behavioral Anomaly Engine: Comprehensive Evaluation")
    print("=" * 80)

    # 1. Initialize engine with baseline normal training data
    init_start = time.perf_counter()
    engine = LoginAnomalyEngine(random_state=42, auto_bootstrap=True)
    init_duration = (time.perf_counter() - init_start) * 1000
    print(f"[*] Baseline Model: IsolationForest fitted on 600 benign training events in {init_duration:.2f} ms")

    # 2. Generate unseen realistic evaluation benchmark with distinct seed
    eval_seed = 2026
    generator = SyntheticTelemetryGenerator(random_state=eval_seed)
    n_routine = 200
    n_borderline = 160
    n_threats = 100
    events, meta_list = generator.generate_realistic_benchmark(
        n_routine=n_routine,
        n_borderline=n_borderline,
        n_threats=n_threats,
    )
    total_samples = len(events)
    print(f"[*] Generated {total_samples} unseen test events (Random Seed: {eval_seed}):")
    print(f"    - Routine Benign Normal : {n_routine:3d} samples")
    print(f"    - Borderline Legitimate : {n_borderline:3d} samples (new device, travel, typos, night, weak signals)")
    print(f"    - Injected Active Threat: {n_threats:3d} samples (credential stuffing, ATO, nocturnal brute force)")

    # 3. Run predictions and measure latency
    latencies: List[float] = []
    results: List[Dict[str, Any]] = []

    for ev in events:
        t0 = time.perf_counter()
        res = engine.predict(ev)
        latencies.append((time.perf_counter() - t0) * 1000)
        results.append(res)

    # 4. Triage Mapping
    # In SOC operations:
    # Actionable Alert (Positive): High or Critical (triggers proactive alert / read-aloud / session revocation)
    # Non-Alert (Negative): Safe, Low, or Medium (informational logging or advisory MFA challenge, no false lockout)
    y_true_threat = np.array([1 if m["is_threat"] else 0 for m in meta_list], dtype=int)
    y_pred_alert = np.array([1 if r["risk_level"] in ("High", "Critical") else 0 for r in results], dtype=int)

    tp = int(np.sum((y_true_threat == 1) & (y_pred_alert == 1)))
    fp = int(np.sum((y_true_threat == 0) & (y_pred_alert == 1)))
    tn = int(np.sum((y_true_threat == 0) & (y_pred_alert == 0)))
    fn = int(np.sum((y_true_threat == 1) & (y_pred_alert == 0)))

    accuracy = (tp + tn) / total_samples
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "-" * 80)
    print("1. PRIMARY SOC TRIAGE METRICS (Actionable Alert: High / Critical)")
    print("-" * 80)
    print(f"Total Test Samples   : {total_samples}")
    print(f"True Positives (TP)  : {tp:3d}  (Threats correctly escalated to High/Critical)")
    print(f"False Positives (FP) : {fp:3d}  (Benign/borderline falsely escalated to High/Critical)")
    print(f"True Negatives (TN)  : {tn:3d}  (Benign/borderline kept Safe/Low/Medium, avoiding lockouts)")
    print(f"False Negatives (FN) : {fn:3d}  (Threats missed as Safe/Low/Medium)")
    print(f"Overall Accuracy     : {accuracy:.2%}")
    print(f"Precision            : {precision:.2%}")
    print(f"Recall (Sensitivity) : {recall:.2%}")
    print(f"Specificity          : {specificity:.2%}")
    print(f"F1-Score             : {f1:.4f}")
    print(f"Inference Latency    : {np.mean(latencies):.3f} ms avg | {np.percentile(latencies, 95):.3f} ms p95")

    # 5. Confusion Matrix Table
    print("\n" + "-" * 80)
    print("2. CONFUSION MATRIX (SOC Actionable Alert Boundary)")
    print("-" * 80)
    print("                         Predicted Non-Alert (Safe/Low/Med) | Predicted Alert (High/Crit)")
    print(f"Actual Benign / Borderline:              {tn:3d}                       |           {fp:3d}")
    print(f"Actual Active Threat      :              {fn:3d}                       |           {tp:3d}")

    # 6. 5-Tier Cross-Tabulation Matrix
    print("\n" + "-" * 80)
    print("3. CYBERGUARD 5-TIER RISK DISTRIBUTION")
    print("-" * 80)
    categories = ["benign_routine", "benign_borderline", "active_threat"]
    cat_names = {
        "benign_routine": "Routine Benign Logins",
        "benign_borderline": "Borderline Benign (Travel, Typos, New Dev, Night)",
        "active_threat": "Injected Threat Attacks (Brute Force, ATO)",
    }

    print(f"{'Data Category':50s} | {'Safe':5s} | {'Low':5s} | {'Med':5s} | {'High':5s} | {'Crit':5s}")
    print("-" * 80)

    for cat in categories:
        indices = [i for i, m in enumerate(meta_list) if m["category"] == cat]
        tier_counts = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for idx in indices:
            tier_counts[results[idx]["risk_level"]] += 1
        label = cat_names[cat]
        print(
            f"{label:50s} | {tier_counts['Safe']:5d} | {tier_counts['Low']:5d} | "
            f"{tier_counts['Medium']:5d} | {tier_counts['High']:5d} | {tier_counts['Critical']:5d}"
        )

    # 7. Granular Per-Scenario Breakdown
    print("\n" + "-" * 80)
    print("4. GRANULAR PER-SCENARIO BREAKDOWN")
    print("-" * 80)
    scenario_order = [
        "routine_normal",
        "legitimate_new_device",
        "legitimate_travel",
        "occasional_password_typo",
        "unusual_legitimate_hour",
        "multiple_weak_signals",
        "credential_stuffing",
        "impossible_travel_ato",
        "nocturnal_brute_force",
    ]

    print(f"{'Scenario Name':26s} | {'Count':5s} | {'Mean':5s} | {'Range':8s} | {'Safe':4s} | {'Low':4s} | {'Med':4s} | {'High':4s} | {'Crit':4s} | {'Alert%':6s}")
    print("-" * 92)

    for sc in scenario_order:
        sc_indices = [i for i, m in enumerate(meta_list) if m["scenario"] == sc]
        sc_results = [results[i] for i in sc_indices]
        sc_scores = [r["risk_score"] for r in sc_results]
        sc_tiers = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for r in sc_results:
            sc_tiers[r["risk_level"]] += 1

        alert_count = sc_tiers["High"] + sc_tiers["Critical"]
        alert_rate = (alert_count / len(sc_indices)) * 100 if sc_indices else 0.0
        score_range = f"{min(sc_scores)}-{max(sc_scores)}"

        print(
            f"{sc:26s} | {len(sc_indices):5d} | {np.mean(sc_scores):5.1f} | {score_range:8s} | "
            f"{sc_tiers['Safe']:4d} | {sc_tiers['Low']:4d} | {sc_tiers['Medium']:4d} | "
            f"{sc_tiers['High']:4d} | {sc_tiers['Critical']:4d} | {alert_rate:5.1f}%"
        )

    # 8. Sample Unified Output Payloads
    print("\n" + "=" * 80)
    print("5. SAMPLE UNIFIED DETECTION RESULTS (Representing Borderline & Threat Cases)")
    print("=" * 80)

    sample_cases = [
        ("Routine Benign Login", LoginEvent(login_hour=14, is_new_device=False, is_new_location=False, failed_attempts=0)),
        ("Borderline: Legitimate New Phone", LoginEvent(login_hour=15, is_new_device=True, is_new_location=False, failed_attempts=0)),
        ("Borderline: Legitimate Travel (New City)", LoginEvent(login_hour=11, is_new_device=False, is_new_location=True, failed_attempts=1)),
        ("Borderline: Password Typos (3 Attempts)", LoginEvent(login_hour=14, is_new_device=False, is_new_location=False, failed_attempts=3)),
        ("Borderline: Nocturnal Home Login", LoginEvent(login_hour=3, is_new_device=False, is_new_location=False, failed_attempts=0)),
        ("Compound: Multiple Weak Signals", LoginEvent(login_hour=22, is_new_device=True, is_new_location=True, failed_attempts=2)),
        ("Active Threat: Credential Stuffing", LoginEvent(login_hour=14, is_new_device=True, is_new_location=False, failed_attempts=8)),
        ("Active Threat: Account Takeover (Impossible Travel)", LoginEvent(login_hour=2, is_new_device=True, is_new_location=True, failed_attempts=1, impossible_travel=True)),
        ("Active Threat: Nocturnal Brute Force Probe", LoginEvent(login_hour=3, is_new_device=True, is_new_location=True, failed_attempts=6)),
    ]

    for title, ev in sample_cases:
        sample_res = engine.predict(ev)
        print(f"\n[Case: {title}]")
        print(json.dumps(sample_res, indent=2))

    print("\n" + "=" * 80)
    print("EVALUATION BENCHMARK COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    run_evaluation()
