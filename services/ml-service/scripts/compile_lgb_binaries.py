"""
Stage 3 - Step 3.2: LightGBM Binary Dataset Compilation.

Compiles pre-binned representations:
- train_480k.bin (~1.14 GB)
- val_120k.bin (~0.29 GB) with train_480k.bin as reference
Monitors available RAM and process RSS continuously.
"""

import os
import sys
import time
import psutil
import numpy as np
import lightgbm as lgb

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "datasets", "malware", "ember_cache_600k")

TRAIN_FEATURES_FILE = os.path.join(CACHE_DIR, "features_train_480k.dat")
VAL_FEATURES_FILE = os.path.join(CACHE_DIR, "features_val_120k.dat")
TRAIN_LABELS_FILE = os.path.join(CACHE_DIR, "labels_train_480k.npy")
VAL_LABELS_FILE = os.path.join(CACHE_DIR, "labels_val_120k.npy")

TRAIN_BIN_FILE = os.path.join(CACHE_DIR, "train_480k.bin")
VAL_BIN_FILE = os.path.join(CACHE_DIR, "val_120k.bin")

N_TRAIN = 480000
N_VAL = 120000
D_FEAT = 2381
SAFETY_RAM_FLOOR_GB = 2.0


def check_safety(step_desc):
    mem = psutil.virtual_memory()
    proc = psutil.Process()
    avail_ram = mem.available / (1024**3)
    rss_mb = proc.memory_info().rss / (1024**2)
    print(f"[{step_desc}] Avail RAM: {avail_ram:.2f} GB | Process RSS: {rss_mb:.2f} MB")
    if avail_ram < SAFETY_RAM_FLOOR_GB:
        raise RuntimeError(f"ABORT: Available RAM {avail_ram:.2f} GB < safety floor {SAFETY_RAM_FLOOR_GB} GB!")
    return avail_ram, rss_mb


def main():
    print("=" * 80)
    print("STAGE 3: STEP 3.2 - LIGHTGBM BINARY COMPILATION")
    print("=" * 80)

    check_safety("INITIAL")

    # Check if binaries already exist and are valid
    if os.path.exists(TRAIN_BIN_FILE) and os.path.exists(VAL_BIN_FILE):
        print(f"[FOUND] Existing train binary: {TRAIN_BIN_FILE} ({os.path.getsize(TRAIN_BIN_FILE):,} bytes)")
        print(f"[FOUND] Existing val binary:   {VAL_BIN_FILE} ({os.path.getsize(VAL_BIN_FILE):,} bytes)")
        # Test loading
        t0 = time.time()
        ds_tr = lgb.Dataset(TRAIN_BIN_FILE).construct()
        ds_va = lgb.Dataset(VAL_BIN_FILE).construct()
        print(f"[VERIFIED] Binaries loaded in {time.time()-t0:.2f}s: train={ds_tr.num_data()} samples, val={ds_va.num_data()} samples.")
        return

    # 1. Compile Train Binary
    print("\n--- Compiling Train Binary (480k samples) ---")
    train_mm = np.memmap(TRAIN_FEATURES_FILE, dtype=np.float32, mode="r", shape=(N_TRAIN, D_FEAT))
    train_labels = np.load(TRAIN_LABELS_FILE)

    check_safety("BEFORE_TRAIN_DATASET_INIT")

    params = {
        "num_threads": 8,
        "max_bin": 255,
        "min_data_in_bin": 5,
        "verbose": 1
    }

    t0 = time.time()
    train_ds = lgb.Dataset(train_mm, label=train_labels, params=params, free_raw_data=True)
    check_safety("AFTER_TRAIN_DATASET_INIT")

    print("[CONSTRUCT] Constructing LightGBM train dataset inner bins...")
    train_ds.construct()
    t1 = time.time()
    check_safety(f"AFTER_TRAIN_CONSTRUCT ({t1-t0:.2f}s)")

    print(f"[SAVING] Saving train binary to {TRAIN_BIN_FILE}...")
    train_ds.save_binary(TRAIN_BIN_FILE)
    print(f"[SAVED] Train binary: {os.path.getsize(TRAIN_BIN_FILE):,} bytes ({os.path.getsize(TRAIN_BIN_FILE) / 1024**3:.2f} GB)")

    # 2. Compile Val Binary with train_ds as reference
    print("\n--- Compiling Val Binary (120k samples) with reference ---")
    val_mm = np.memmap(VAL_FEATURES_FILE, dtype=np.float32, mode="r", shape=(N_VAL, D_FEAT))
    val_labels = np.load(VAL_LABELS_FILE)

    check_safety("BEFORE_VAL_DATASET_INIT")
    val_ds = lgb.Dataset(val_mm, label=val_labels, reference=train_ds, params=params, free_raw_data=True)
    val_ds.construct()
    t2 = time.time()
    check_safety(f"AFTER_VAL_CONSTRUCT ({t2-t1:.2f}s)")

    print(f"[SAVING] Saving val binary to {VAL_BIN_FILE}...")
    val_ds.save_binary(VAL_BIN_FILE)
    print(f"[SAVED] Val binary: {os.path.getsize(VAL_BIN_FILE):,} bytes ({os.path.getsize(VAL_BIN_FILE) / 1024**3:.2f} GB)")

    check_safety("FINAL")
    print("=" * 80)
    print("LIGHTGBM BINARY COMPILATION COMPLETE (PASS)")
    print("=" * 80)


if __name__ == "__main__":
    main()
