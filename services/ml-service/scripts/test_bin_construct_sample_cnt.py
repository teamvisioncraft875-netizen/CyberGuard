"""
Stage 3: Controlled Memory-Safety Test for LightGBM Dataset Construction.
Evaluates Option 1: bin_construct_sample_cnt=50,000 with num_threads=4 on all 480,000 genuine training records.
Includes continuous real-time RAM watcher with hard 2.0 GB safety floor enforcement.
"""

import os
import sys
import time
import json
import threading
import psutil
import numpy as np
import lightgbm as lgb

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "datasets", "malware", "ember_cache_600k")
TEST_JSONL = os.path.join(REPO_ROOT, "datasets", "malware", "ember2018", "test_features.jsonl")

TRAIN_FEATURES_FILE = os.path.join(CACHE_DIR, "features_train_480k.dat")
TRAIN_LABELS_FILE = os.path.join(CACHE_DIR, "labels_train_480k.npy")
TEST_BIN_FILE = os.path.join(CACHE_DIR, "train_480k_test.bin")
REPORT_FILE = os.path.join(CACHE_DIR, "bin_construct_test_report.json")

TEST_EXPECTED_SIZE = 1869447260
TEST_EXPECTED_MTIME = 1562791761.0

N_TRAIN = 480000
D_FEAT = 2381
SAFETY_RAM_FLOOR_GB = 2.0

min_observed_ram_gb = 999.0
peak_observed_rss_mb = 0.0
stats_lock = threading.Lock()


def watcher_thread_fn(stop_event):
    global min_observed_ram_gb, peak_observed_rss_mb
    proc = psutil.Process()
    while not stop_event.is_set():
        mem = psutil.virtual_memory()
        avail_ram = mem.available / (1024**3)
        rss_mb = proc.memory_info().rss / (1024**2)
        with stats_lock:
            if avail_ram < min_observed_ram_gb:
                min_observed_ram_gb = avail_ram
            if rss_mb > peak_observed_rss_mb:
                peak_observed_rss_mb = rss_mb
        if avail_ram < SAFETY_RAM_FLOOR_GB:
            print(f"\n[CRITICAL SAFETY ABORT] Available RAM {avail_ram:.2f} GB fell below safety floor {SAFETY_RAM_FLOOR_GB} GB!", flush=True)
            print(f"Process RSS at abort: {rss_mb:.2f} MB. Terminating immediately.", flush=True)
            os._exit(101)
        time.sleep(0.05)


def check_untouched():
    test_stat = os.stat(TEST_JSONL)
    assert test_stat.st_size == TEST_EXPECTED_SIZE, "Test file size changed!"
    assert abs(test_stat.st_mtime - TEST_EXPECTED_MTIME) < 2.0, "Test file mtime changed!"
    print(f"[VERIFIED] test_features.jsonl is 100% UNTOUCHED ({test_stat.st_size:,} bytes).", flush=True)


def main():
    print("=" * 80, flush=True)
    print("CONTROLLED MEMORY-SAFETY TEST: bin_construct_sample_cnt=50,000", flush=True)
    print("=" * 80, flush=True)

    check_untouched()

    mem_init = psutil.virtual_memory()
    disk_init = psutil.disk_usage(REPO_ROOT[:2])
    print(f"[INITIAL] Available RAM: {mem_init.available / 1024**3:.2f} GB | Free Disk: {disk_init.free / 1024**3:.2f} GB", flush=True)

    # 1. Attach memory map and load labels
    assert os.path.exists(TRAIN_FEATURES_FILE), f"Missing {TRAIN_FEATURES_FILE}"
    assert os.path.exists(TRAIN_LABELS_FILE), f"Missing {TRAIN_LABELS_FILE}"

    print(f"[ATTACHING] Opening {TRAIN_FEATURES_FILE} as read-only memmap...", flush=True)
    train_mm = np.memmap(TRAIN_FEATURES_FILE, dtype=np.float32, mode="r", shape=(N_TRAIN, D_FEAT))
    train_labels = np.load(TRAIN_LABELS_FILE)
    assert len(train_labels) == N_TRAIN, f"Expected {N_TRAIN} labels, got {len(train_labels)}"

    # 2. Configure LightGBM Dataset with bin_construct_sample_cnt=50000 and num_threads=4
    sample_cnt = 50000
    params = {
        "bin_construct_sample_cnt": sample_cnt,
        "num_threads": 4,
        "max_bin": 255,
        "min_data_in_bin": 5,
        "verbose": 1
    }

    print(f"[CONFIG] Testing params: {params}", flush=True)

    # 3. Start high-frequency RAM watcher
    stop_event = threading.Event()
    watcher = threading.Thread(target=watcher_thread_fn, args=(stop_event,), daemon=True)
    watcher.start()

    print("[DATASET] Initializing lgb.Dataset...", flush=True)
    train_ds = lgb.Dataset(train_mm, label=train_labels, params=params, free_raw_data=True)

    print("[CONSTRUCT] Starting Dataset.construct()...", flush=True)
    t0 = time.time()
    train_ds.construct()
    construct_time = time.time() - t0
    print(f"[CONSTRUCT] Dataset.construct() completed in {construct_time:.2f} seconds!", flush=True)

    # Stop watcher
    stop_event.set()
    watcher.join(timeout=1.0)

    # 4. Measure results
    with stats_lock:
        final_min_ram = min_observed_ram_gb
        final_peak_rss = peak_observed_rss_mb

    num_rows = train_ds.num_data()
    num_cols = train_ds.num_feature()
    print(f"[RECORDS] train_ds.num_data(): {num_rows:,} (Expected: {N_TRAIN:,})", flush=True)
    print(f"[FEATURES] train_ds.num_feature(): {num_cols:,} (Expected: {D_FEAT:,})", flush=True)
    assert num_rows == N_TRAIN, f"Row count mismatch! {num_rows} != {N_TRAIN}"
    assert num_cols == D_FEAT, f"Feature count mismatch! {num_cols} != {D_FEAT}"

    # 5. Test saving binary dataset
    print(f"[SAVING] Saving binary representation to {TEST_BIN_FILE}...", flush=True)
    t_save0 = time.time()
    train_ds.save_binary(TEST_BIN_FILE)
    t_save = time.time() - t_save0
    bin_size = os.path.getsize(TEST_BIN_FILE)
    print(f"[SAVED] Binary created in {t_save:.2f}s: {bin_size:,} bytes ({bin_size / 1024**3:.2f} GB)", flush=True)

    # 6. Test reloading binary dataset to verify representation integrity
    print("[VERIFY] Reloading binary from disk...", flush=True)
    reloaded_ds = lgb.Dataset(TEST_BIN_FILE).construct()
    assert reloaded_ds.num_data() == N_TRAIN, "Reloaded row count mismatch!"
    assert reloaded_ds.num_feature() == D_FEAT, "Reloaded feature count mismatch!"
    print(f"[VERIFIED] Reloaded dataset confirms: {reloaded_ds.num_data():,} rows, {reloaded_ds.num_feature():,} features.", flush=True)
    del reloaded_ds

    # 7. Post-test resources
    mem_final = psutil.virtual_memory()
    disk_final = psutil.disk_usage(REPO_ROOT[:2])
    check_untouched()

    report = {
        "test": "CONTROLLED_MEMORY_SAFETY_TEST",
        "bin_construct_sample_cnt": sample_cnt,
        "num_threads": 4,
        "dataset_construct_completed": True,
        "peak_process_rss_mb": round(final_peak_rss, 2),
        "peak_process_rss_gb": round(final_peak_rss / 1024, 2),
        "minimum_available_ram_gb": round(final_min_ram, 2),
        "initial_available_ram_gb": round(mem_init.available / 1024**3, 2),
        "final_available_ram_gb": round(mem_final.available / 1024**3, 2),
        "safety_floor_gb": SAFETY_RAM_FLOOR_GB,
        "safety_floor_respected": final_min_ram >= SAFETY_RAM_FLOOR_GB,
        "construction_time_seconds": round(construct_time, 2),
        "binary_size_bytes": bin_size,
        "binary_size_gb": round(bin_size / 1024**3, 2),
        "training_records_represented": num_rows,
        "features_represented": num_cols,
        "disk_free_initial_gb": round(disk_init.free / 1024**3, 2),
        "disk_free_final_gb": round(disk_final.free / 1024**3, 2),
        "is_safe_for_candidate_training": final_min_ram >= SAFETY_RAM_FLOOR_GB,
        "test_partition_status": "UNTOUCHED_VERIFIED"
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 80, flush=True)
    print("CONTROLLED TEST RESULTS:", flush=True)
    print(f"  bin_construct_sample_cnt:     {sample_cnt:,}", flush=True)
    print(f"  Dataset.construct() completed: True", flush=True)
    print(f"  Construction Time:             {construct_time:.2f}s", flush=True)
    print(f"  Peak Process RSS:              {final_peak_rss:.2f} MB ({final_peak_rss/1024:.2f} GB)", flush=True)
    print(f"  Minimum Available RAM:         {final_min_ram:.2f} GB", flush=True)
    print(f"  Safety Floor (2.0 GB):         {'RESPECTED (PASS)' if final_min_ram >= SAFETY_RAM_FLOOR_GB else 'BREACHED (FAIL)'}", flush=True)
    print(f"  Binary Dataset Size:           {bin_size:,} bytes ({bin_size/1024**3:.2f} GB)", flush=True)
    print(f"  Training Records Represented:  {num_rows:,} / {N_TRAIN:,}", flush=True)
    print("=" * 80, flush=True)


if __name__ == "__main__":
    main()
