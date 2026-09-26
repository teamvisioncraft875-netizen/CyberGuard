"""
CYBERGUARD — Network Threat Model Training & Evaluation Benchmark

Trains NetworkThreatModel on Scenarios 42, 43, 44 (train_features.parquet)
Evaluates strictly on held-out Scenario 45 (test_features.parquet)
Measures and reports actual metrics: Confusion Matrix, Precision, Recall, F1, FPR, and Latency.
Serializes model checkpoint to app/models/network_threat_model.joblib.
"""

import sys
import time
from pathlib import Path

# Ensure ml-service root is in sys.path
ml_service_dir = Path(__file__).resolve().parents[2]
if str(ml_service_dir) not in sys.path:
    sys.path.insert(0, str(ml_service_dir))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    accuracy_score,
)

from app.services.network_anomaly.model import NetworkThreatModel
from app.utils.ctu13_preprocessor import FEATURE_COLUMNS


def train_and_evaluate_network_model(
    train_parquet_path: Path,
    test_parquet_path: Path,
    model_save_path: Optional_Path = None,
    random_state: int = 42,
) -> dict:
    print("================================================================================")
    print("      CYBERGUARD — SYSTEM & NETWORK THREAT ENGINE EVALUATION BENCHMARK          ")
    print("================================================================================")
    print(f"[*] Training Data:   {train_parquet_path}")
    print(f"[*] Evaluation Data: {test_parquet_path}")

    # 1. Load Data
    print("\n[1/5] Loading Parquet datasets...")
    df_train = pd.read_parquet(train_parquet_path)
    df_test = pd.read_parquet(test_parquet_path)

    X_train = df_train[FEATURE_COLUMNS]
    y_train = df_train["is_threat"].astype(int)

    X_test = df_test[FEATURE_COLUMNS]
    y_test = df_test["is_threat"].astype(int)

    n_train_threats = int((y_train == 1).sum())
    n_train_benign = int((y_train == 0).sum())
    n_test_threats = int((y_test == 1).sum())
    n_test_benign = int((y_test == 0).sum())

    print(f"    - Train Samples (Scenarios 42, 43, 44): {len(df_train):,} total ({n_train_threats:,} botnet, {n_train_benign:,} benign)")
    print(f"    - Held-out Test Samples (Scenario 45) : {len(df_test):,} total ({n_test_threats:,} botnet, {n_test_benign:,} benign)")

    # 2. Train Model
    print("\n[2/5] Training HistGradientBoosting NetworkThreatModel...")
    model = NetworkThreatModel(
        random_state=random_state,
        max_iter=100,
        min_samples_leaf=20,
        l2_regularization=0.1,
    )
    t0_train = time.perf_counter()
    model.fit(X_train, y_train)
    train_duration = time.perf_counter() - t0_train
    print(f"    - Model fitted successfully in {train_duration:.2f}s")

    # 3. Inference on Held-out Scenario 45
    print("\n[3/5] Evaluating on held-out Scenario 45...")
    y_pred_proba = model.predict_proba(X_test)
    y_pred = (y_pred_proba >= 0.5).astype(int)

    # 4. Measure Actual Metrics
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    fpr = fp / max(fp + tn, 1)

    # 5. Measure Latency
    print("\n[4/5] Measuring inference latency (1,000 single-flow predictions)...")
    latency_samples = X_test.iloc[:1000]
    latencies = []
    for i in range(len(latency_samples)):
        t_start = time.perf_counter()
        _ = model.predict_proba(latency_samples.iloc[[i]])
        latencies.append((time.perf_counter() - t_start) * 1000.0)  # ms

    avg_latency_ms = float(np.mean(latencies))
    p95_latency_ms = float(np.percentile(latencies, 95))

    # 6. Save Model Checkpoint
    if model_save_path:
        print(f"\n[5/5] Serializing model to {model_save_path}...")
        model.save(model_save_path)
        file_size_mb = model_save_path.stat().st_size / (1024 * 1024)
        print(f"    - Saved checkpoint: {model_save_path} ({file_size_mb:.2f} MB)")

    # Print Clean Report
    print("\n================================================================================")
    print("                        ACTUAL MEASURED BENCHMARK RESULTS                       ")
    print("================================================================================")
    print(f"  Test Scenario:             CTU-13 Scenario 45 (100% Held-out)")
    print(f"  Total Test Samples:        {len(df_test):,}")
    print(f"    - Actual Benign Flows:   {n_test_benign:,}")
    print(f"    - Actual Botnet Flows:   {n_test_threats:,}")
    print("--------------------------------------------------------------------------------")
    print(f"  Confusion Matrix:          [[TN={tn:6d},  FP={fp:6d}],")
    print(f"                              [FN={fn:6d},  TP={tp:6d}]]")
    print(f"  Accuracy:                  {accuracy * 100:.2f}%")
    print(f"  Precision:                 {precision * 100:.2f}%")
    print(f"  Recall (Detection Rate):   {recall * 100:.2f}%")
    print(f"  F1 Score:                  {f1 * 100:.2f}%")
    print(f"  False Positive Rate (FPR): {fpr * 100:.2f}%")
    print(f"  ROC-AUC:                   {roc_auc:.4f}")
    print(f"  Avg Inference Latency:     {avg_latency_ms:.3f} ms / flow")
    print(f"  P95 Inference Latency:     {p95_latency_ms:.3f} ms / flow")
    print("================================================================================\n")

    return {
        "train_samples": len(df_train),
        "test_samples": len(df_test),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "roc_auc": float(roc_auc),
        "avg_latency_ms": avg_latency_ms,
        "p95_latency_ms": p95_latency_ms,
    }


if __name__ == "__main__":
    from typing import Optional as Optional_Path
    data_dir = ml_service_dir / "data" / "ctu13"
    train_file = data_dir / "train_features.parquet"
    test_file = data_dir / "test_features.parquet"
    models_dir = ml_service_dir / "app" / "models"
    save_path = models_dir / "network_threat_model.joblib"

    train_and_evaluate_network_model(train_file, test_file, save_path)
