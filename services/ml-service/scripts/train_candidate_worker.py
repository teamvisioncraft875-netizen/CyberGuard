"""
Phase 4 / Step 2: Isolated Subprocess Worker for Training a Single Candidate Model.

Trains an approved LightGBM candidate against train_480k.bin and evaluates on val_120k.bin.
Zero synthetic data. Official test set (test_features.jsonl) remains strictly frozen.
Runs with active memory monitoring and aborts safely if RAM drops below 2.0 GB.
"""

import os
import sys
import time
import json
import argparse
import psutil
import threading
import numpy as np
import lightgbm as lgb
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "datasets", "malware", "ember_cache_600k")
TEST_JSONL = os.path.join(REPO_ROOT, "datasets", "malware", "ember2018", "test_features.jsonl")
PROD_MODEL = os.path.join(REPO_ROOT, "services", "ml-service", "app", "models", "malware", "ember_model_2018.txt")

TRAIN_BIN_FILE = os.path.join(CACHE_DIR, "train_480k.bin")
VAL_BIN_FILE = os.path.join(CACHE_DIR, "val_120k.bin")
VAL_FEATURES_FILE = os.path.join(CACHE_DIR, "features_val_120k.dat")
VAL_LABELS_FILE = os.path.join(CACHE_DIR, "labels_val_120k.npy")

TEST_EXPECTED_SIZE = 1869447260
TEST_EXPECTED_MTIME = 1562791761.0
PROD_EXPECTED_SIZE = 127284141

N_TRAIN = 480000
N_VAL = 120000
D_FEAT = 2381
SAFETY_RAM_FLOOR_GB = 2.0

CANDIDATE_CONFIGS = {
    "CANDIDATE_A": {
        "id": "CANDIDATE_A",
        "name": "Baseline GBDT (1000 trees, 2048 leaves, max_depth=15, lr=0.05, feat_frac=0.5)",
        "params": {
            "boosting_type": "gbdt",
            "objective": "binary",
            "metric": "binary_logloss",
            "num_iterations": 1000,
            "num_leaves": 2048,
            "max_depth": 15,
            "learning_rate": 0.05,
            "feature_fraction": 0.5,
            "data_random_seed": 1,
            "min_data_in_bin": 5,
            "histogram_pool_size": 1024,
            "num_threads": 4,
            "verbose": -1
        }
    },
    "CANDIDATE_B": {
        "id": "CANDIDATE_B",
        "name": "Regularized GBDT (1000 trees, 1024 leaves, max_depth=15, L1=0.1, L2=1.0, min_child=50)",
        "params": {
            "boosting_type": "gbdt",
            "objective": "binary",
            "metric": "binary_logloss",
            "num_iterations": 1000,
            "num_leaves": 1024,
            "max_depth": 15,
            "learning_rate": 0.05,
            "lambda_l1": 0.1,
            "lambda_l2": 1.0,
            "min_child_samples": 50,
            "min_data_in_bin": 5,
            "histogram_pool_size": 1024,
            "num_threads": 4,
            "verbose": -1
        }
    },
    "CANDIDATE_C": {
        "id": "CANDIDATE_C",
        "name": "Conservative GBDT (1000 trees, 512 leaves, max_depth=12, feat_frac=0.7, min_child=100)",
        "params": {
            "boosting_type": "gbdt",
            "objective": "binary",
            "metric": "binary_logloss",
            "num_iterations": 1000,
            "num_leaves": 512,
            "max_depth": 12,
            "learning_rate": 0.05,
            "feature_fraction": 0.7,
            "min_child_samples": 100,
            "min_data_in_bin": 5,
            "histogram_pool_size": 1024,
            "num_threads": 4,
            "verbose": -1
        }
    }
}


def check_frozen():
    test_stat = os.stat(TEST_JSONL)
    assert test_stat.st_size == TEST_EXPECTED_SIZE, "Test file size altered!"
    assert abs(test_stat.st_mtime - TEST_EXPECTED_MTIME) < 2.0, "Test file mtime altered!"
    prod_stat = os.stat(PROD_MODEL)
    assert prod_stat.st_size == PROD_EXPECTED_SIZE, "Production model altered!"
    print(f"[VERIFIED] test_features.jsonl and ember_model_2018.txt are 100% frozen.", flush=True)


def evaluate_predictions(y_true, y_prob):
    roc_auc = float(roc_auc_score(y_true, y_prob))
    pr_auc = float(average_precision_score(y_true, y_prob))

    # Evaluate across fine-grained threshold grid
    thresholds = np.linspace(0.005, 0.995, 991)
    best_f1 = -1.0
    best_thresh_f1 = 0.50
    best_metrics_f1 = {}

    best_recall_low_fpr = -1.0
    best_thresh_low_fpr = 0.50
    best_metrics_low_fpr = {}

    metrics_at_050 = None

    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        acc = float(accuracy_score(y_true, y_pred))
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
        bal_acc = (rec + spec) / 2.0
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0

        metrics_obj = {
            "threshold": round(float(t), 4),
            "accuracy": round(acc, 6),
            "balanced_accuracy": round(bal_acc, 6),
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "specificity": round(spec, 6),
            "f1": round(f1, 6),
            "fpr": round(fpr, 6),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }

        if abs(t - 0.50) < 0.001 and metrics_at_050 is None:
            metrics_at_050 = metrics_obj

        if f1 > best_f1:
            best_f1 = f1
            best_thresh_f1 = t
            best_metrics_f1 = metrics_obj

        # Enterprise Low-FPR operating point (FPR <= 0.0100 with maximal recall)
        if fpr <= 0.0100 and rec > best_recall_low_fpr:
            best_recall_low_fpr = rec
            best_thresh_low_fpr = t
            best_metrics_low_fpr = metrics_obj

    if not best_metrics_low_fpr:
        # Fallback if no point has <= 0.0100
        best_metrics_low_fpr = best_metrics_f1

    return {
        "roc_auc": round(roc_auc, 8),
        "pr_auc": round(pr_auc, 8),
        "operating_point_low_fpr": best_metrics_low_fpr,
        "operating_point_max_f1": best_metrics_f1,
        "operating_point_050": metrics_at_050
    }


def run_worker(candidate_id, output_json, experiment_dir):
    check_frozen()

    if candidate_id not in CANDIDATE_CONFIGS:
        raise ValueError(f"Unknown candidate_id: {candidate_id}")

    cand_info = CANDIDATE_CONFIGS[candidate_id]
    cand_name = cand_info["name"]
    params = cand_info["params"]

    print("=" * 80, flush=True)
    print(f"ISOLATED WORKER PROCESS: {candidate_id}", flush=True)
    print(f"Name: {cand_name}", flush=True)
    print(f"PID: {os.getpid()}", flush=True)
    print("=" * 80, flush=True)

    proc_init = psutil.Process()
    mem_init = psutil.virtual_memory()
    print(f"Initial State: Avail RAM = {mem_init.available / 1024**3:.2f} GB | RSS = {proc_init.memory_info().rss / 1024**2:.2f} MB", flush=True)

    # Active memory safety monitor
    min_ram = mem_init.available / (1024**3)
    peak_rss = proc_init.memory_info().rss / (1024**2)

    stop_watcher = threading.Event()
    def watcher_fn():
        nonlocal min_ram, peak_rss
        proc = psutil.Process()
        while not stop_watcher.is_set():
            try:
                avail = psutil.virtual_memory().available / (1024**3)
                rss = proc.memory_info().rss / (1024**2)
                if avail < min_ram:
                    min_ram = avail
                if rss > peak_rss:
                    peak_rss = rss
                if avail < SAFETY_RAM_FLOOR_GB:
                    print(f"\n[CRITICAL SAFETY ABORT] RAM dropped below {SAFETY_RAM_FLOOR_GB} GB! Avail: {avail:.2f} GB", flush=True)
                    os._exit(101)
            except Exception:
                pass
            time.sleep(0.1)

    watcher = threading.Thread(target=watcher_fn, daemon=True)
    watcher.start()

    # Load binary datasets
    print("Loading pre-binned LightGBM datasets...", flush=True)
    t_load0 = time.time()
    train_data = lgb.Dataset(TRAIN_BIN_FILE, params={"min_data_in_bin": 5}).construct()
    val_data = lgb.Dataset(VAL_BIN_FILE, reference=train_data, params={"min_data_in_bin": 5}).construct()
    t_load = time.time() - t_load0
    print(f"Datasets loaded in {t_load:.2f}s (Train: {train_data.num_data():,}, Val: {val_data.num_data():,})", flush=True)

    # Train
    num_trees = params.get("num_iterations", 1000)
    print(f"Starting LightGBM train ({num_trees} trees)...", flush=True)
    t_train0 = time.time()
    booster = lgb.train(
        params,
        train_data,
        num_boost_round=num_trees,
        valid_sets=[val_data],
        valid_names=["val"]
    )
    t_train = time.time() - t_train0
    print(f"Training completed in {t_train:.2f}s ({t_train/60:.2f} min)!", flush=True)
    print(f"Peak RSS during train: {peak_rss:.2f} MB | Min Available RAM: {min_ram:.2f} GB", flush=True)

    # Save model artifact
    cand_dir = os.path.join(experiment_dir, candidate_id.lower())
    os.makedirs(cand_dir, exist_ok=True)
    model_artifact_path = os.path.join(cand_dir, "model.txt")
    booster.save_model(model_artifact_path)
    model_size_bytes = os.path.getsize(model_artifact_path)
    model_size_mb = model_size_bytes / (1024**2)
    print(f"Model artifact saved: {model_artifact_path} ({model_size_mb:.2f} MB, {model_size_bytes:,} bytes)", flush=True)

    # Validation Inference - Pass 1
    print("Running validation inference (Pass 1 via chunked binary read)...", flush=True)
    t_inf0 = time.time()
    batch_size = 10000
    y_prob_pass1 = np.empty(N_VAL, dtype=np.float32)
    with open(VAL_FEATURES_FILE, "rb") as f_val:
        for b_start in range(0, N_VAL, batch_size):
            b_end = min(b_start + batch_size, N_VAL)
            count = b_end - b_start
            b_bytes = f_val.read(count * D_FEAT * 4)
            b_arr = np.frombuffer(b_bytes, dtype=np.float32).reshape(count, D_FEAT)
            y_prob_pass1[b_start:b_end] = booster.predict(b_arr, num_threads=4)
            del b_bytes, b_arr
    t_inf_pass1 = time.time() - t_inf0
    latency_per_sample_ms = (t_inf_pass1 / N_VAL) * 1000.0
    print(f"Validation inference completed in {t_inf_pass1:.2f}s ({latency_per_sample_ms:.3f} ms/sample)", flush=True)

    # Validation Inference - Pass 2 (Reproducibility Verification)
    print("Running validation inference (Pass 2 - Bitwise Reproducibility Check)...", flush=True)
    y_prob_pass2 = np.empty(N_VAL, dtype=np.float32)
    with open(VAL_FEATURES_FILE, "rb") as f_val:
        for b_start in range(0, N_VAL, batch_size):
            b_end = min(b_start + batch_size, N_VAL)
            count = b_end - b_start
            b_bytes = f_val.read(count * D_FEAT * 4)
            b_arr = np.frombuffer(b_bytes, dtype=np.float32).reshape(count, D_FEAT)
            y_prob_pass2[b_start:b_end] = booster.predict(b_arr, num_threads=4)
            del b_bytes, b_arr

    is_identical = np.array_equal(y_prob_pass1, y_prob_pass2)
    max_prob_diff = float(np.max(np.abs(y_prob_pass1 - y_prob_pass2)))
    print(f"Reproducibility verification: Identical={is_identical}, Max Abs Diff={max_prob_diff}", flush=True)
    assert max_prob_diff < 1e-6, f"Inference determinism failed! Max diff: {max_prob_diff}"

    # Load validation labels
    val_labels = np.load(VAL_LABELS_FILE)
    assert len(val_labels) == N_VAL, "Val labels mismatch!"

    # Evaluate metrics
    print("Evaluating validation metrics and selecting thresholds...", flush=True)
    metrics_report = evaluate_predictions(val_labels, y_prob_pass1)

    # Save predictions
    preds_path = os.path.join(cand_dir, "val_predictions.npy")
    np.save(preds_path, y_prob_pass1)

    stop_watcher.set()
    watcher.join(timeout=1.0)

    result = {
        "candidate_id": candidate_id,
        "name": cand_name,
        "parameters": params,
        "training_time_seconds": round(t_train, 2),
        "inference_time_seconds": round(t_inf_pass1, 2),
        "latency_per_sample_ms": round(latency_per_sample_ms, 4),
        "model_size_mb": round(model_size_mb, 2),
        "model_size_bytes": model_size_bytes,
        "model_artifact_path": model_artifact_path,
        "predictions_artifact_path": preds_path,
        "peak_rss_mb": round(peak_rss, 2),
        "min_available_ram_gb": round(min_ram, 2),
        "reproducibility": {
            "identical_pass1_pass2": bool(is_identical),
            "max_abs_diff": max_prob_diff
        },
        "metrics": metrics_report
    }

    with open(output_json, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Worker {candidate_id} completed successfully! Result written to {output_json}", flush=True)
    check_frozen()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, choices=["CANDIDATE_A", "CANDIDATE_B", "CANDIDATE_C"])
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--experiment-dir", required=True)
    args = parser.parse_args()

    run_worker(args.candidate, args.output_json, args.experiment_dir)
