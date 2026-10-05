"""
Stage 3: Full 480k Real-Data Candidate Model Training Pipeline via LightGBM Avenue 2 (two_round=True).

Pipeline Steps:
1. Streaming TSV generation in 5,000-row chunks for train (480k) and val (120k).
2. Binary dataset compilation (train_480k.bin and val_120k.bin) with two_round=True.
3. Strict verification of binary datasets, followed by deletion of temporary TSVs.
4. Isolated training of Candidates A, B, and C with num_threads=4 and real-time RAM monitoring.
5. Rigorous validation evaluation on 120,000 genuine validation records (zero test set access).
6. Deterministic inference repetition for reproducibility verification.
7. Verification that official test set (test_features.jsonl) remains 100% frozen.
"""

import os
import sys
import time
import json
import psutil
import hashlib
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

TRAIN_FEATURES_FILE = os.path.join(CACHE_DIR, "features_train_480k.dat")
VAL_FEATURES_FILE = os.path.join(CACHE_DIR, "features_val_120k.dat")
TRAIN_LABELS_FILE = os.path.join(CACHE_DIR, "labels_train_480k.npy")
VAL_LABELS_FILE = os.path.join(CACHE_DIR, "labels_val_120k.npy")

TRAIN_TSV_FILE = os.path.join(CACHE_DIR, "train_480k_temp.tsv")
VAL_TSV_FILE = os.path.join(CACHE_DIR, "val_120k_temp.tsv")

TRAIN_BIN_FILE = os.path.join(CACHE_DIR, "train_480k.bin")
VAL_BIN_FILE = os.path.join(CACHE_DIR, "val_120k.bin")

EXPERIMENT_TIMESTAMP = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
EXPERIMENT_DIR = os.path.join(REPO_ROOT, "services", "ml-service", "experiments", f"malware_candidates_{EXPERIMENT_TIMESTAMP}")

TEST_EXPECTED_SIZE = 1869447260
TEST_EXPECTED_MTIME = 1562791761.0
PROD_EXPECTED_SIZE = 127284141

N_TRAIN = 480000
N_VAL = 120000
D_FEAT = 2381
SAFETY_RAM_FLOOR_GB = 2.0
CHUNK_ROWS = 5000


def check_ram_and_disk(desc="checkpoint"):
    mem = psutil.virtual_memory()
    proc = psutil.Process()
    disk = psutil.disk_usage(REPO_ROOT[:2])
    avail_ram = mem.available / (1024**3)
    rss_mb = proc.memory_info().rss / (1024**2)
    free_disk = disk.free / (1024**3)
    if avail_ram < SAFETY_RAM_FLOOR_GB:
        print(f"\n[SAFETY ABORT] At {desc}: Available RAM {avail_ram:.2f} GB < {SAFETY_RAM_FLOOR_GB} GB!", flush=True)
        sys.exit(101)
    return avail_ram, rss_mb, free_disk


def verify_frozen_artifacts():
    test_stat = os.stat(TEST_JSONL)
    assert test_stat.st_size == TEST_EXPECTED_SIZE, f"Test file size altered! {test_stat.st_size}"
    assert abs(test_stat.st_mtime - TEST_EXPECTED_MTIME) < 2.0, f"Test file mtime altered! {test_stat.st_mtime}"
    
    prod_stat = os.stat(PROD_MODEL)
    assert prod_stat.st_size == PROD_EXPECTED_SIZE, f"Prod model size altered! {prod_stat.st_size}"
    print(f"[VERIFIED] Test file and production model are 100% frozen and untouched.", flush=True)


def stream_to_tsv(features_dat_path, labels_npy_path, out_tsv_path, n_rows, desc="train"):
    if os.path.exists(out_tsv_path):
        print(f"[{desc.upper()}] TSV file already exists at {out_tsv_path} ({os.path.getsize(out_tsv_path):,} bytes). Skipping stream.", flush=True)
        return

    print(f"[{desc.upper()}] Streaming {n_rows:,} records to {out_tsv_path} via sequential binary read in chunks of {CHUNK_ROWS:,}...", flush=True)
    t0 = time.time()
    labels = np.load(labels_npy_path)

    with open(features_dat_path, "rb") as f_in, open(out_tsv_path, "w") as f_out:
        # Write TSV header
        f_out.write("label\t" + "\t".join([f"f{i}" for i in range(D_FEAT)]) + "\n")
        
        for offset in range(0, n_rows, CHUNK_ROWS):
            end = min(offset + CHUNK_ROWS, n_rows)
            count = end - offset
            
            chunk_bytes = f_in.read(count * D_FEAT * 4)
            chunk_feat = np.frombuffer(chunk_bytes, dtype=np.float32).reshape(count, D_FEAT)
            chunk_lbl = labels[offset:end].reshape(-1, 1).astype(np.float32)
            chunk_combined = np.hstack([chunk_lbl, chunk_feat])
            
            np.savetxt(f_out, chunk_combined, fmt="%.4g", delimiter="\t")
            del chunk_bytes, chunk_feat, chunk_lbl, chunk_combined
            
            if (end % 50000 == 0) or (end == n_rows):
                avail_ram, rss_mb, free_disk = check_ram_and_disk(f"{desc}_streaming_{end}")
                print(f"  Processed {end:,}/{n_rows:,} rows (RAM: {avail_ram:.2f} GB avail, RSS: {rss_mb:.1f} MB, Free Disk: {free_disk:.1f} GB)", flush=True)

    t1 = time.time()
    tsv_size_mb = os.path.getsize(out_tsv_path) / (1024**2)
    print(f"[{desc.upper()}] TSV streamed in {t1-t0:.2f}s. Size on disk: {tsv_size_mb:.2f} MB ({tsv_size_mb/1024:.2f} GB).", flush=True)


def compile_binary_with_two_round(tsv_path, out_bin_path, ref_bin_path=None, desc="train"):
    if os.path.exists(out_bin_path):
        print(f"[{desc.upper()}] Binary already exists: {out_bin_path} ({os.path.getsize(out_bin_path):,} bytes). Skipping compile.", flush=True)
        return

    print(f"\n[{desc.upper()}] Compiling binary dataset via two_round=True from {tsv_path}...", flush=True)
    t0 = time.time()
    avail_ram_start, rss_start, _ = check_ram_and_disk(f"before_{desc}_compile")
    
    params = {
        "two_round": True,
        "header": True,
        "label_column": 0,
        "num_threads": 4,
        "max_bin": 255,
        "min_data_in_bin": 5,
        "verbose": 1
    }

    ref_ds = None
    if ref_bin_path is not None:
        print(f"  Loading reference binary dataset from {ref_bin_path}...", flush=True)
        ref_ds = lgb.Dataset(ref_bin_path, params={"min_data_in_bin": 5}).construct()

    ds = lgb.Dataset(tsv_path, reference=ref_ds, params=params)
    ds.construct()
    t_construct = time.time() - t0
    
    avail_ram_post, rss_post, _ = check_ram_and_disk(f"after_{desc}_construct")
    print(f"[{desc.upper()}] Constructed in {t_construct:.2f}s! Avail RAM: {avail_ram_post:.2f} GB | RSS: {rss_post:.2f} MB", flush=True)
    print(f"  Delta RSS: {rss_post - rss_start:.2f} MB | Delta Avail RAM: {avail_ram_start - avail_ram_post:.2f} GB", flush=True)

    print(f"[{desc.upper()}] Saving binary dataset to {out_bin_path}...", flush=True)
    ds.save_binary(out_bin_path)
    bin_size_mb = os.path.getsize(out_bin_path) / (1024**2)
    print(f"[{desc.upper()}] Binary saved: {bin_size_mb:.2f} MB ({bin_size_mb/1024:.2f} GB).", flush=True)
    del ds
    if ref_ds is not None:
        del ref_ds


def evaluate_predictions(y_true, y_prob):
    roc_auc = float(roc_auc_score(y_true, y_prob))
    pr_auc = float(average_precision_score(y_true, y_prob))
    
    # 1. Search optimal threshold on validation set (max F1)
    thresholds = np.linspace(0.01, 0.99, 197)
    best_f1 = -1.0
    best_thresh_f1 = 0.50
    best_metrics_f1 = {}
    
    # 2. Search threshold for target FPR <= 1.0% (strict low-FPR malware engine criteria)
    best_thresh_low_fpr = 0.50
    best_recall_low_fpr = -1.0
    best_metrics_low_fpr = {}

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

        if f1 > best_f1:
            best_f1 = f1
            best_thresh_f1 = t
            best_metrics_f1 = metrics_obj

        if fpr <= 0.0100 and rec > best_recall_low_fpr:
            best_recall_low_fpr = rec
            best_thresh_low_fpr = t
            best_metrics_low_fpr = metrics_obj

    # Default to low-FPR operating point if found, else max F1
    chosen_op = best_metrics_low_fpr if best_metrics_low_fpr else best_metrics_f1

    return {
        "roc_auc": round(roc_auc, 8),
        "pr_auc": round(pr_auc, 8),
        "operating_point_low_fpr": best_metrics_low_fpr,
        "operating_point_max_f1": best_metrics_f1,
        "primary_operating_point": chosen_op
    }


def train_and_eval_candidate(candidate_id, candidate_name, params, train_bin_path, val_bin_path, val_labels):
    print("\n" + "=" * 80, flush=True)
    print(f"TRAINING {candidate_id}: {candidate_name}", flush=True)
    print(f"Parameters: {params}", flush=True)
    print("=" * 80, flush=True)

    avail_ram_start, rss_start, free_disk = check_ram_and_disk(f"start_{candidate_id}")
    print(f"Initial State: Avail RAM = {avail_ram_start:.2f} GB | RSS = {rss_start:.2f} MB | Free Disk = {free_disk:.2f} GB", flush=True)

    # Load binary datasets
    print("Loading pre-binned LightGBM datasets...", flush=True)
    t_load0 = time.time()
    train_data = lgb.Dataset(train_bin_path).construct()
    val_data = lgb.Dataset(val_bin_path, reference=train_data).construct()
    t_load = time.time() - t_load0
    print(f"Datasets loaded in {t_load:.2f}s (Train: {train_data.num_data():,}, Val: {val_data.num_data():,})", flush=True)

    min_ram_during_train = psutil.virtual_memory().available / (1024**3)
    peak_rss_during_train = psutil.Process().memory_info().rss / (1024**2)

    # Monitor training in background
    stop_train_watcher = threading.Event()
    def train_watcher():
        nonlocal min_ram_during_train, peak_rss_during_train
        proc = psutil.Process()
        while not stop_train_watcher.is_set():
            avail = psutil.virtual_memory().available / (1024**3)
            rss = proc.memory_info().rss / (1024**2)
            if avail < min_ram_during_train:
                min_ram_during_train = avail
            if rss > peak_rss_during_train:
                peak_rss_during_train = rss
            if avail < SAFETY_RAM_FLOOR_GB:
                print(f"\n[CRITICAL SAFETY ABORT] RAM dropped below {SAFETY_RAM_FLOOR_GB} GB during training! Avail: {avail:.2f} GB", flush=True)
                os._exit(101)
            time.sleep(0.1)

    watcher_t = threading.Thread(target=train_watcher, daemon=True)
    watcher_t.start()

    print(f"Starting LightGBM train ({params.get('num_iterations', 1000)} trees)...", flush=True)
    t_train0 = time.time()
    booster = lgb.train(
        params,
        train_data,
        num_boost_round=params.get("num_iterations", 1000),
        valid_sets=[val_data],
        valid_names=["val"]
    )
    t_train = time.time() - t_train0
    stop_train_watcher.set()
    watcher_t.join(timeout=1.0)

    print(f"\nTraining completed in {t_train:.2f}s ({t_train/60:.2f} min)!", flush=True)
    print(f"Peak RSS during train: {peak_rss_during_train:.2f} MB | Min Available RAM: {min_ram_during_train:.2f} GB", flush=True)

    # Save model artifact
    model_artifact_path = os.path.join(EXPERIMENT_DIR, f"{candidate_id.lower()}_model.txt")
    booster.save_model(model_artifact_path)
    model_size_mb = os.path.getsize(model_artifact_path) / (1024**2)
    print(f"Model artifact saved: {model_artifact_path} ({model_size_mb:.2f} MB)", flush=True)

    # 1. Validation Inference - Pass 1
    print("Running validation inference (Pass 1)...", flush=True)
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

    # 2. Validation Inference - Pass 2 (Reproducibility Verification)
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

    # Evaluate validation metrics
    print("Evaluating validation metrics and selecting thresholds...", flush=True)
    metrics_report = evaluate_predictions(val_labels, y_prob_pass1)

    # Save predictions
    preds_path = os.path.join(EXPERIMENT_DIR, f"{candidate_id.lower()}_val_preds.npy")
    np.save(preds_path, y_prob_pass1)

    result = {
        "candidate_id": candidate_id,
        "name": candidate_name,
        "parameters": params,
        "training_time_seconds": round(t_train, 2),
        "inference_time_seconds": round(t_inf_pass1, 2),
        "latency_per_sample_ms": round(latency_per_sample_ms, 4),
        "model_size_mb": round(model_size_mb, 2),
        "model_artifact_path": model_artifact_path,
        "predictions_artifact_path": preds_path,
        "peak_rss_mb": round(peak_rss_during_train, 2),
        "min_available_ram_gb": round(min_ram_during_train, 2),
        "reproducibility": {
            "identical_pass1_pass2": is_identical,
            "max_abs_diff": max_prob_diff
        },
        "metrics": metrics_report
    }

    del booster, train_data, val_data, val_mm, y_prob_pass1, y_prob_pass2
    return result


def main():
    print("=" * 80, flush=True)
    print("PHASE 4 / STEP 2: FULL 480K CANDIDATE TRAINING & COMPARISON PIPELINE", flush=True)
    print(f"Experiment Directory: {EXPERIMENT_DIR}", flush=True)
    print("=" * 80, flush=True)

    os.makedirs(EXPERIMENT_DIR, exist_ok=True)

    # 1. Initial integrity checks
    verify_frozen_artifacts()
    avail_ram_init, rss_init, free_disk_init = check_ram_and_disk("INITIAL_START")
    print(f"Host State: Avail RAM: {avail_ram_init:.2f} GB | Free Disk: {free_disk_init:.2f} GB\n", flush=True)

    # 2. Stream Train & Val to TSV
    stream_to_tsv(TRAIN_FEATURES_FILE, TRAIN_LABELS_FILE, TRAIN_TSV_FILE, N_TRAIN, desc="train")
    stream_to_tsv(VAL_FEATURES_FILE, VAL_LABELS_FILE, VAL_TSV_FILE, N_VAL, desc="val")

    # 3. Compile Train & Val to Binary via two_round=True
    compile_binary_with_two_round(TRAIN_TSV_FILE, TRAIN_BIN_FILE, ref_bin_path=None, desc="train")
    compile_binary_with_two_round(VAL_TSV_FILE, VAL_BIN_FILE, ref_bin_path=TRAIN_BIN_FILE, desc="val")

    # 4. Strict Binary Verification
    print("\n--- Verifying Compiled Binary Datasets ---", flush=True)
    t_v0 = time.time()
    ds_tr = lgb.Dataset(TRAIN_BIN_FILE).construct()
    ds_va = lgb.Dataset(VAL_BIN_FILE).construct()
    print(f"Train Binary: {ds_tr.num_data():,} rows, {ds_tr.num_feature():,} features (Expected: 480,000 x 2,381)", flush=True)
    print(f"Val Binary:   {ds_va.num_data():,} rows, {ds_va.num_feature():,} features (Expected: 120,000 x 2,381)", flush=True)
    assert ds_tr.num_data() == N_TRAIN and ds_tr.num_feature() == D_FEAT, "Train binary verification failed!"
    assert ds_va.num_data() == N_VAL and ds_va.num_feature() == D_FEAT, "Val binary verification failed!"
    print(f"Binary verification successful in {time.time()-t_v0:.2f}s!", flush=True)
    del ds_tr, ds_va

    # 5. Clean up temporary TSV files to preserve disk space
    print("\n--- Reclaiming Disk Space: Deleting Temporary TSV Files ---", flush=True)
    for tsv_f in [TRAIN_TSV_FILE, VAL_TSV_FILE]:
        if os.path.exists(tsv_f):
            sz_mb = os.path.getsize(tsv_f) / (1024**2)
            os.remove(tsv_f)
            print(f"Deleted temporary TSV: {tsv_f} (Freed {sz_mb:.2f} MB)", flush=True)
    
    _, _, free_disk_post_clean = check_ram_and_disk("POST_TSV_CLEANUP")
    print(f"Free Disk Space after TSV cleanup: {free_disk_post_clean:.2f} GB\n", flush=True)

    # 6. Load Validation Labels
    val_labels = np.load(VAL_LABELS_FILE)
    assert len(val_labels) == N_VAL, "Val labels length mismatch!"

    # 7. Candidate Model Configurations
    candidates = [
        {
            "id": "CANDIDATE_A",
            "name": "Baseline GBDT (1000 trees, 2048 leaves, max_depth=15, feature_fraction=0.5)",
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
                "num_threads": 4,
                "verbose": -1
            }
        },
        {
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
                "num_threads": 4,
                "verbose": -1
            }
        },
        {
            "id": "CANDIDATE_C",
            "name": "Conservative GBDT (1000 trees, 512 leaves, max_depth=12, feature_fraction=0.7, min_child=100)",
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
                "num_threads": 4,
                "verbose": -1
            }
        }
    ]

    candidate_results = []
    for cand in candidates:
        res = train_and_eval_candidate(
            cand["id"],
            cand["name"],
            cand["params"],
            TRAIN_BIN_FILE,
            VAL_BIN_FILE,
            val_labels
        )
        candidate_results.append(res)

    # 8. Re-verify frozen files at the very end
    verify_frozen_artifacts()

    # 9. Save master comparison manifest
    master_manifest_path = os.path.join(EXPERIMENT_DIR, "candidate_comparison_manifest.json")
    final_mem = psutil.virtual_memory()
    final_disk = psutil.disk_usage(REPO_ROOT[:2])

    summary_manifest = {
        "stage": "PHASE_4_STEP_2_CANDIDATE_COMPARISON",
        "status": "COMPLETE_AWAITING_APPROVAL",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_metadata": {
            "training_samples": N_TRAIN,
            "validation_samples": N_VAL,
            "feature_dimension": D_FEAT,
            "synthetic_samples": 0,
            "test_partition_status": "FROZEN_UNTOUCHED"
        },
        "system_resources": {
            "initial_avail_ram_gb": round(avail_ram_init, 2),
            "final_avail_ram_gb": round(final_mem.available / (1024**3), 2),
            "final_free_disk_gb": round(final_disk.free / (1024**3), 2),
            "safety_floor_gb": SAFETY_RAM_FLOOR_GB,
            "safety_floor_maintained": True
        },
        "candidates": candidate_results
    }

    with open(master_manifest_path, "w") as f:
        json.dump(summary_manifest, f, indent=2)
    print(f"\n[SAVED] Candidate comparison manifest: {master_manifest_path}", flush=True)

    print("\n" + "=" * 80, flush=True)
    print("PHASE 4 / STEP 2 CANDIDATE TRAINING & VALIDATION COMPLETE (PASS)", flush=True)
    print("=" * 80, flush=True)


if __name__ == "__main__":
    main()
