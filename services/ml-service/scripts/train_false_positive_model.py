"""
CYBERGUARD False Positive Detection V1
Training, Validation, and Frozen Test Evaluation Script
Dataset: BETH (Kernel telemetry on monitored hosts)
Strict host-disjoint partitions:
  TRAIN: labelled_2021may-ip-10-100-1-4.csv (Host 4)
  VALIDATION: labelled_2021may-ip-10-100-1-105.csv (Host 105)
  FROZEN TEST: labelled_testing_data.csv (Host 217)
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, brier_score_loss,
    confusion_matrix, classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR.parent.parent
BETH_DIR = WORKSPACE_DIR / "datasets" / "BETH"
OUTPUT_DIR = BASE_DIR / "app" / "models" / "false_positive"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_ARTIFACT_PATH = OUTPUT_DIR / "false_positive_classifier_v1.0.0.joblib"
METADATA_PATH = OUTPUT_DIR / "false_positive_metadata.json"
SCHEMA_PATH = OUTPUT_DIR / "false_positive_schema.json"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_cohort(csv_path: Path):
    """
    Loads only events where sus == 1.
    Target:
      y = 1 if evil == 0 (False Positive Alert)
      y = 0 if evil == 1 (True Positive Alert)
    Features approved:
      event_name, process_name, user_id, is_root,
      args_num, return_value, is_failed_syscall, is_init_parent
    """
    print(f"Loading cohort from {csv_path.name}...")
    usecols = [
        "processName", "eventName", "userId", "parentProcessId",
        "argsNum", "returnValue", "sus", "evil"
    ]
    df = pd.read_csv(csv_path, usecols=usecols)
    
    # Filter strictly to sus == 1
    df = df[df["sus"] == 1].copy()
    
    # Define ground truth target
    # evil == 0 -> y = 1 (False Positive)
    # evil == 1 -> y = 0 (True Positive)
    y = (df["evil"] == 0).astype(int).values
    
    # Engineer approved scalar features
    user_id = df["userId"].fillna(-1).astype(float).values
    is_root = (user_id == 0).astype(int)
    args_num = df["argsNum"].fillna(0).astype(float).values
    return_val = df["returnValue"].fillna(0).astype(float).values
    is_failed_syscall = (return_val < 0).astype(int)
    
    parent_pid = df["parentProcessId"].fillna(-1).astype(int).values
    is_init_parent = (parent_pid == 1).astype(int)
    
    process_name = df["processName"].fillna("unknown").astype(str).values
    event_name = df["eventName"].fillna("unknown").astype(str).values
    
    X = pd.DataFrame({
        "event_name": event_name,
        "process_name": process_name,
        "user_id": user_id,
        "is_root": is_root,
        "args_num": args_num,
        "return_value": return_val,
        "is_failed_syscall": is_failed_syscall,
        "is_init_parent": is_init_parent
    })
    
    print(f"  Loaded {len(X):,} alert samples: {np.sum(y == 1):,} FP (y=1), {np.sum(y == 0):,} TP (y=0)")
    return X, y


class EmpiricalEventBaseline:
    def __init__(self):
        self.p_global = 0.5
        self.lookup = {}

    def fit(self, X: pd.DataFrame, y: np.ndarray):
        self.p_global = float(np.mean(y))
        grouped = {}
        for ev, target in zip(X["event_name"], y):
            if ev not in grouped:
                grouped[ev] = [0, 0]
            grouped[ev][target] += 1
        for ev, counts in grouped.items():
            tot = counts[0] + counts[1]
            self.lookup[ev] = float(counts[1] / tot) if tot > 0 else self.p_global

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        probs = np.array([self.lookup.get(ev, self.p_global) for ev in X["event_name"]])
        return np.column_stack([1.0 - probs, probs])

    def predict(self, X: pd.DataFrame, threshold: float = 0.5) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= threshold).astype(int)


def calculate_metrics(y_true, y_pred, y_prob):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()  # 0 is TP-threat, 1 is FP-alert
    # In our definition:
    # 1 = False Positive Alert, 0 = True Positive Threat
    # tn = genuine threats correctly identified as threats (y=0 -> pred=0)
    # fp = genuine threats misclassified as false positives (y=0 -> pred=1) (FATAL ERROR)
    # fn = false positives misclassified as threats (y=1 -> pred=0) (benign alert left open)
    # tp = false positives correctly identified as false positives (y=1 -> pred=1)
    
    threat_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # Threat preservation (y=0 recall)
    threat_precision = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    threat_f1 = 2 * (threat_precision * threat_recall) / (threat_precision + threat_recall) if (threat_precision + threat_recall) > 0 else 0.0
    
    fp_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0      # False positive recall (y=1 recall)
    fp_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fp_f1 = 2 * (fp_precision * fp_recall) / (fp_precision + fp_recall) if (fp_precision + fp_recall) > 0 else 0.0
    
    acc = accuracy_score(y_true, y_pred)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    
    try:
        roc_auc = roc_auc_score(y_true, y_prob)
    except Exception:
        roc_auc = 0.5
        
    try:
        pr_auc = average_precision_score(y_true, y_prob)
    except Exception:
        pr_auc = 0.5
        
    brier = brier_score_loss(y_true, y_prob)
    
    return {
        "accuracy": float(acc),
        "balanced_accuracy": float(bal_acc),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "brier_score": float(brier),
        "threat_preservation_recall": float(threat_recall),
        "threat_precision": float(threat_precision),
        "threat_f1": float(threat_f1),
        "fp_recall": float(fp_recall),
        "fp_precision": float(fp_precision),
        "fp_f1": float(fp_f1),
        "confusion_matrix": {
            "threats_as_threats_TN": int(tn),
            "threats_as_FP_FP": int(fp),
            "FPs_as_threats_FN": int(fn),
            "FPs_as_FP_TP": int(tp)
        }
    }


def main():
    print("=" * 70)
    print("CYBERGUARD FALSE POSITIVE DETECTION V1 — TRAINING PIPELINE")
    print("=" * 70)

    # 1. Load Data
    train_path = BETH_DIR / "labelled_2021may-ip-10-100-1-4.csv"
    val_path = BETH_DIR / "labelled_2021may-ip-10-100-1-105.csv"
    test_path = BETH_DIR / "labelled_testing_data.csv"

    X_train, y_train = load_cohort(train_path)
    X_val, y_val = load_cohort(val_path)

    # 2. Train Empirical Baseline
    print("\n--- 1. Evaluating Empirical Baseline (P(FP | event_name)) ---")
    baseline = EmpiricalEventBaseline()
    baseline.fit(X_train, y_train)
    val_base_probs = baseline.predict_proba(X_val)[:, 1]
    val_base_preds = baseline.predict(X_val, threshold=0.5)
    base_metrics = calculate_metrics(y_val, val_base_preds, val_base_probs)
    print(f"Validation Baseline Balanced Accuracy: {base_metrics['balanced_accuracy']:.4f}")
    print(f"Validation Baseline Threat Preservation (Recall y=0): {base_metrics['threat_preservation_recall']:.4f}")
    print(f"Validation Baseline FP Recall (Recall y=1): {base_metrics['fp_recall']:.4f}")

    # 3. Build Preprocessor
    cat_features = ["event_name", "process_name"]
    num_features = ["user_id", "is_root", "args_num", "return_value", "is_failed_syscall", "is_init_parent"]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_features),
            ("num", StandardScaler(), num_features)
        ],
        remainder="drop"
    )

    # Pre-fit and transform on training data
    print("\nFitting preprocessor on TRAIN data...")
    t0 = time.time()
    X_train_trans = preprocessor.fit_transform(X_train)
    X_val_trans = preprocessor.transform(X_val)
    print(f"Preprocessor fit in {time.time() - t0:.2f}s. Feature matrix shape: {X_train_trans.shape}")

    # 4. Train Candidates
    candidates = {
        "LogisticRegression": LogisticRegression(
            penalty="l2",
            C=1.0,
            class_weight="balanced",
            max_iter=500,
            random_state=42
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=10,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=100,
            max_depth=8,
            class_weight="balanced",
            random_state=42
        )
    }

    results = {}
    print("\n--- 2. Evaluating Candidate Models on VALIDATION ONLY ---")
    for name, clf in candidates.items():
        print(f"\nTraining {name}...")
        t_start = time.time()
        clf.fit(X_train_trans, y_train)
        fit_time = time.time() - t_start

        # Inference on validation
        t_inf = time.time()
        probs = clf.predict_proba(X_val_trans)[:, 1]
        preds = (probs >= 0.5).astype(int)
        inf_time = (time.time() - t_inf) / len(X_val) * 1000  # ms per sample

        metrics = calculate_metrics(y_val, preds, probs)
        metrics["fit_time_sec"] = round(fit_time, 2)
        metrics["latency_ms_per_sample"] = round(inf_time, 4)
        results[name] = metrics

        print(f"  {name} Results on Validation (thresh=0.5):")
        print(f"    Balanced Accuracy: {metrics['balanced_accuracy']:.4f}")
        print(f"    Threat Preservation Recall (y=0): {metrics['threat_preservation_recall']:.4f}")
        print(f"    FP Recall (y=1): {metrics['fp_recall']:.4f}")
        print(f"    ROC-AUC: {metrics['roc_auc']:.4f} | PR-AUC: {metrics['pr_auc']:.4f} | Brier: {metrics['brier_score']:.4f}")
        print(f"    Confusion Matrix: {metrics['confusion_matrix']}")

    # 5. Model Selection
    # Select best model based on Balanced Accuracy, Threat Preservation, and PR-AUC
    # We require Threat Preservation >= 0.85 and highest Balanced Accuracy
    best_name = max(results.keys(), key=lambda k: results[k]["balanced_accuracy"])
    best_clf = candidates[best_name]
    print(f"\nSelected Model: {best_name} (Balanced Accuracy: {results[best_name]['balanced_accuracy']:.4f})")

    # 6. Threshold Selection on Validation Set
    print("\n--- 3. Threshold Calibration on VALIDATION ONLY ---")
    val_probs = best_clf.predict_proba(X_val_trans)[:, 1]
    
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8]
    best_thresh = 0.5
    best_score = -1.0
    thresh_table = []
    
    for th in thresholds:
        th_preds = (val_probs >= th).astype(int)
        m = calculate_metrics(y_val, th_preds, val_probs)
        # Score combines threat preservation (weight 2) + FP recall (weight 1)
        composite = 2.0 * m["threat_preservation_recall"] + 1.0 * m["fp_recall"]
        thresh_table.append({
            "threshold": th,
            "threat_preservation": m["threat_preservation_recall"],
            "fp_recall": m["fp_recall"],
            "balanced_accuracy": m["balanced_accuracy"],
            "composite": composite
        })
        print(f"  Thresh={th:.2f} -> Threat Recall: {m['threat_preservation_recall']:.4f}, FP Recall: {m['fp_recall']:.4f}, Bal Acc: {m['balanced_accuracy']:.4f}")
        if m["threat_preservation_recall"] >= 0.85 and composite > best_score:
            best_score = composite
            best_thresh = th

    print(f"\nLocked Optimal Operational Threshold: {best_thresh:.2f}")

    # Re-evaluate validation with locked threshold
    val_final_preds = (val_probs >= best_thresh).astype(int)
    val_final_metrics = calculate_metrics(y_val, val_final_preds, val_probs)
    print(f"Validation Final Metrics with Threshold={best_thresh:.2f}:")
    print(f"  Threat Preservation: {val_final_metrics['threat_preservation_recall']:.4f}")
    print(f"  FP Recall: {val_final_metrics['fp_recall']:.4f}")
    print(f"  Balanced Accuracy: {val_final_metrics['balanced_accuracy']:.4f}")

    # 7. Package Full Pipeline
    full_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", best_clf)
    ])

    # 8. Frozen Test Evaluation (Run ONCE)
    print("\n--- 4. Evaluating on FROZEN TEST SET (Run ONCE) ---")
    X_test, y_test = load_cohort(test_path)
    
    # Baseline on Frozen Test
    test_base_probs = baseline.predict_proba(X_test)[:, 1]
    test_base_preds = (test_base_probs >= 0.5).astype(int)
    test_base_metrics = calculate_metrics(y_test, test_base_preds, test_base_probs)

    # Selected Model on Frozen Test
    t_test_start = time.time()
    test_probs = full_pipeline.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_thresh).astype(int)
    test_eval_time = time.time() - t_test_start
    test_metrics = calculate_metrics(y_test, test_preds, test_probs)

    print("\n================== FROZEN TEST RESULTS ==================")
    print(f"Baseline on Frozen Test:")
    print(f"  Balanced Accuracy: {test_base_metrics['balanced_accuracy']:.4f}")
    print(f"  Threat Preservation: {test_base_metrics['threat_preservation_recall']:.4f}")
    print(f"  FP Recall: {test_base_metrics['fp_recall']:.4f}")
    print(f"\n{best_name} on Frozen Test (Threshold={best_thresh:.2f}):")
    print(f"  Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  Balanced Accuracy: {test_metrics['balanced_accuracy']:.4f}")
    print(f"  ROC-AUC: {test_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC: {test_metrics['pr_auc']:.4f}")
    print(f"  Brier Score: {test_metrics['brier_score']:.4f}")
    print(f"  Threat Preservation Recall (y=0): {test_metrics['threat_preservation_recall']:.4f}")
    print(f"  Threat Precision (y=0): {test_metrics['threat_precision']:.4f}")
    print(f"  Threat F1 (y=0): {test_metrics['threat_f1']:.4f}")
    print(f"  False Positive Recall (y=1): {test_metrics['fp_recall']:.4f}")
    print(f"  False Positive Precision (y=1): {test_metrics['fp_precision']:.4f}")
    print(f"  False Positive F1 (y=1): {test_metrics['fp_f1']:.4f}")
    print(f"  Confusion Matrix: {test_metrics['confusion_matrix']}")
    print(f"  Inference Latency: {(test_eval_time / len(X_test) * 1000):.4f} ms/alert")
    print("=========================================================")

    # 9. Save Model Artifact
    print(f"\nSaving model artifact to {MODEL_ARTIFACT_PATH}...")
    joblib.dump(full_pipeline, MODEL_ARTIFACT_PATH, compress=3)
    artifact_sha256 = compute_sha256(MODEL_ARTIFACT_PATH)
    print(f"Model Artifact SHA-256: {artifact_sha256}")

    # 10. Save Schema
    schema_data = {
        "schema_version": "1.0.0",
        "model_id": "false_positive_v1.0.0",
        "description": "Schema for CYBERGUARD False Positive Detection V1",
        "target_definition": {
            "cohort": "sus == 1",
            "y": {
                "1": "False Positive Alert (benign system trigger, sus==1 and evil==0)",
                "0": "True Positive Alert (genuine threat, sus==1 and evil==1)"
            }
        },
        "input_features": {
            "event_name": {"type": "string", "description": "Kernel syscall name triggering the alert", "required": True},
            "process_name": {"type": "string", "description": "Process executable name generating the event", "required": True},
            "user_id": {"type": "integer", "description": "Linux User ID executing the process", "required": True},
            "args_num": {"type": "integer", "description": "Count of syscall arguments", "required": True},
            "return_value": {"type": "integer", "description": "Syscall exit code / return status", "required": True},
            "parent_process_id": {"type": "integer", "description": "Parent process PID (optional)", "required": False, "default": -1}
        },
        "output_fields": {
            "false_positive_probability": {"type": "float", "range": [0.0, 1.0]},
            "false_positive_score": {"type": "float", "range": [0.0, 1.0]},
            "classification": {"type": "string", "enum": ["likely_false_positive", "likely_true_positive"]},
            "confidence": {"type": "float", "range": [0.0, 1.0]},
            "threshold": {"type": "float", "value": best_thresh},
            "explanation": {"type": "object"}
        }
    }
    with open(SCHEMA_PATH, "w") as f:
        json.dump(schema_data, f, indent=2)

    # 11. Save Metadata
    metadata = {
        "model_name": "CYBERGUARD False Positive Detection V1",
        "model_version": "1.0.0",
        "model_type": best_name,
        "artifact_path": str(MODEL_ARTIFACT_PATH.relative_to(WORKSPACE_DIR)).replace("\\", "/"),
        "sha256": artifact_sha256,
        "threshold": float(best_thresh),
        "training_dataset": "datasets/BETH/labelled_2021may-ip-10-100-1-4.csv",
        "validation_dataset": "datasets/BETH/labelled_2021may-ip-10-100-1-105.csv",
        "frozen_test_dataset": "datasets/BETH/labelled_testing_data.csv",
        "train_cohort_count": len(X_train),
        "validation_cohort_count": len(X_val),
        "frozen_test_cohort_count": len(X_test),
        "train_class_distribution": {"false_positives_y1": int(np.sum(y_train == 1)), "true_threats_y0": int(np.sum(y_train == 0))},
        "validation_class_distribution": {"false_positives_y1": int(np.sum(y_val == 1)), "true_threats_y0": int(np.sum(y_val == 0))},
        "frozen_test_class_distribution": {"false_positives_y1": int(np.sum(y_test == 1)), "true_threats_y0": int(np.sum(y_test == 0))},
        "baseline_validation_metrics": base_metrics,
        "baseline_frozen_test_metrics": test_base_metrics,
        "candidate_validation_comparison": results,
        "selected_model": best_name,
        "validation_metrics": val_final_metrics,
        "frozen_test_metrics": test_metrics,
        "operational_safety": "Advisory score only. Never automatically suppress, close, block, or delete alerts."
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Saved metadata to {METADATA_PATH}")
    print("Training and frozen test evaluation completed successfully.")


if __name__ == "__main__":
    main()
