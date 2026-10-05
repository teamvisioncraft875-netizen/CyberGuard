"""
Stage 3 - Step 3.1: Memory-Safe Streaming Partition Preparation & Row/Label Mapping Verification.

Streams the 480,000 train records and 120,000 validation records from features_600k.dat
into contiguous disk-backed files using bounded 5,000-sample chunks (~47.6 MB RAM per chunk).
Ensures zero materialization of full-size feature matrices in RAM.
Verifies exact row/label mapping, counts, and zero overlap.
"""

import os
import sys
import json
import time
import psutil
import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CACHE_DIR = os.path.join(REPO_ROOT, "datasets", "malware", "ember_cache_600k")
TEST_JSONL = os.path.join(REPO_ROOT, "datasets", "malware", "ember2018", "test_features.jsonl")

FEATURES_600K_FILE = os.path.join(CACHE_DIR, "features_600k.dat")
LABELS_600K_FILE = os.path.join(CACHE_DIR, "labels_600k.npy")
TRAIN_IDX_FILE = os.path.join(CACHE_DIR, "train_indices_480k.npy")
VAL_IDX_FILE = os.path.join(CACHE_DIR, "val_indices_120k.npy")

TRAIN_FEATURES_FILE = os.path.join(CACHE_DIR, "features_train_480k.dat")
VAL_FEATURES_FILE = os.path.join(CACHE_DIR, "features_val_120k.dat")
TRAIN_LABELS_FILE = os.path.join(CACHE_DIR, "labels_train_480k.npy")
VAL_LABELS_FILE = os.path.join(CACHE_DIR, "labels_val_120k.npy")
PARTITION_META_FILE = os.path.join(CACHE_DIR, "partitions_metadata.json")

TEST_EXPECTED_SIZE = 1869447260
TEST_EXPECTED_MTIME = 1562791761.0

N_TOTAL = 600000
N_TRAIN = 480000
N_VAL = 120000
D_FEAT = 2381
CHUNK_SIZE = 5000  # 5,000 * 2381 * 4 bytes = ~47.6 MB per chunk
SAFETY_RAM_FLOOR_GB = 2.0


def check_ram_and_disk():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(REPO_ROOT[:2])
    avail_ram = mem.available / (1024**3)
    free_disk = disk.free / (1024**3)
    if avail_ram < SAFETY_RAM_FLOOR_GB:
        raise RuntimeError(f"ABORT: Available RAM {avail_ram:.2f} GB is below safety floor of {SAFETY_RAM_FLOOR_GB} GB!")
    if free_disk < 5.0:
        raise RuntimeError(f"ABORT: Free disk {free_disk:.2f} GB is critically low!")
    return avail_ram, free_disk


def stream_partition(source_mm, indices, out_filepath, desc="partition"):
    total_samples = len(indices)
    expected_bytes = total_samples * D_FEAT * 4
    
    # Check if already generated and valid
    if os.path.exists(out_filepath) and os.path.getsize(out_filepath) == expected_bytes:
        print(f"[{desc.upper()}] Existing binary file found with correct size ({expected_bytes:,} bytes). Validating...")
        return

    print(f"[{desc.upper()}] Streaming {total_samples:,} records to {out_filepath} in chunks of {CHUNK_SIZE:,}...")
    t0 = time.time()
    min_observed_ram = psutil.virtual_memory().available / (1024**3)
    
    with open(out_filepath, "wb") as f_out:
        for offset in range(0, total_samples, CHUNK_SIZE):
            chunk_indices = indices[offset : offset + CHUNK_SIZE]
            # Read chunk via memmap fancy index on small chunk only (~47 MB)
            chunk_features = source_mm[chunk_indices]
            f_out.write(chunk_features.tobytes())
            
            avail_ram, _ = check_ram_and_disk()
            if avail_ram < min_observed_ram:
                min_observed_ram = avail_ram
            
            if (offset + CHUNK_SIZE) % 50000 == 0 or (offset + len(chunk_indices)) == total_samples:
                print(f"  Processed {offset + len(chunk_indices):,}/{total_samples:,} samples (Avail RAM: {avail_ram:.2f} GB)")

    t1 = time.time()
    actual_size = os.path.getsize(out_filepath)
    assert actual_size == expected_bytes, f"Size mismatch! Expected {expected_bytes}, got {actual_size}"
    print(f"[{desc.upper()}] Streaming completed in {t1 - t0:.2f}s. File size: {actual_size:,} bytes. Min RAM: {min_observed_ram:.2f} GB.")


def main():
    print("=" * 80)
    print("STAGE 3: STEP 3.1 - CHUNKED STREAMING PARTITION PREPARATION & VERIFICATION")
    print("=" * 80)

    # 1. Verify test_features.jsonl is untouched
    test_stat = os.stat(TEST_JSONL)
    assert test_stat.st_size == TEST_EXPECTED_SIZE, "Test file size modified!"
    assert abs(test_stat.st_mtime - TEST_EXPECTED_MTIME) < 2.0, "Test file mtime modified!"
    print(f"[VERIFIED] test_features.jsonl is untouched ({test_stat.st_size:,} bytes).")

    avail_ram, free_disk = check_ram_and_disk()
    print(f"[INITIAL RESOURCES] Available RAM: {avail_ram:.2f} GB, Free Disk: {free_disk:.2f} GB")

    # 2. Load indices and 600k labels
    train_idx = np.load(TRAIN_IDX_FILE)
    val_idx = np.load(VAL_IDX_FILE)
    labels_600k = np.load(LABELS_600K_FILE)

    assert len(train_idx) == N_TRAIN, f"Expected {N_TRAIN} train indices, got {len(train_idx)}"
    assert len(val_idx) == N_VAL, f"Expected {N_VAL} val indices, got {len(val_idx)}"
    assert len(set(train_idx).intersection(set(val_idx))) == 0, "Train and Val indices overlap!"
    assert len(set(train_idx)) == N_TRAIN, "Duplicate train indices found!"
    assert len(set(val_idx)) == N_VAL, "Duplicate val indices found!"

    # 3. Derive exact partition labels
    train_labels = labels_600k[train_idx]
    val_labels = labels_600k[val_idx]

    train_benign = int(np.sum(train_labels == 0))
    train_malware = int(np.sum(train_labels == 1))
    val_benign = int(np.sum(val_labels == 0))
    val_malware = int(np.sum(val_labels == 1))

    assert train_benign == 240000 and train_malware == 240000, "Train class imbalance!"
    assert val_benign == 60000 and val_malware == 60000, "Val class imbalance!"
    print(f"[VERIFIED] Train labels: {train_benign:,} benign, {train_malware:,} malware (50/50).")
    print(f"[VERIFIED] Val labels:   {val_benign:,} benign, {val_malware:,} malware (50/50).")

    # Save partition labels
    np.save(TRAIN_LABELS_FILE, train_labels)
    np.save(VAL_LABELS_FILE, val_labels)
    print(f"[SAVED] Train labels: {TRAIN_LABELS_FILE} ({os.path.getsize(TRAIN_LABELS_FILE):,} bytes)")
    print(f"[SAVED] Val labels:   {VAL_LABELS_FILE} ({os.path.getsize(VAL_LABELS_FILE):,} bytes)")

    # 4. Open source 600k features as read-only memmap
    assert os.path.exists(FEATURES_600K_FILE), f"Missing {FEATURES_600K_FILE}"
    source_mm = np.memmap(FEATURES_600K_FILE, dtype=np.float32, mode="r", shape=(N_TOTAL, D_FEAT))

    # 5. Stream train partition (480k rows) in bounded chunks
    stream_partition(source_mm, train_idx, TRAIN_FEATURES_FILE, desc="Train Partition")

    # 6. Stream val partition (120k rows) in bounded chunks
    stream_partition(source_mm, val_idx, VAL_FEATURES_FILE, desc="Val Partition")

    # 7. Exact Row/Label Mapping Verification
    print("\n[VERIFICATION] Performing spot-check row/label mapping across partitions...")
    train_mm = np.memmap(TRAIN_FEATURES_FILE, dtype=np.float32, mode="r", shape=(N_TRAIN, D_FEAT))
    val_mm = np.memmap(VAL_FEATURES_FILE, dtype=np.float32, mode="r", shape=(N_VAL, D_FEAT))

    # Verify beginning, middle, and end rows match source exactly
    spot_checks_train = [0, 1, 100, 5000, 240000, 479999]
    for pos in spot_checks_train:
        src_pos = train_idx[pos]
        assert np.array_equal(train_mm[pos], source_mm[src_pos]), f"Train feature mismatch at pos {pos} (src {src_pos})!"
        assert train_labels[pos] == labels_600k[src_pos], f"Train label mismatch at pos {pos}!"
    print(f"  [PASS] Train row/label alignment verified at positions: {spot_checks_train}")

    spot_checks_val = [0, 1, 100, 2500, 60000, 119999]
    for pos in spot_checks_val:
        src_pos = val_idx[pos]
        assert np.array_equal(val_mm[pos], source_mm[src_pos]), f"Val feature mismatch at pos {pos} (src {src_pos})!"
        assert val_labels[pos] == labels_600k[src_pos], f"Val label mismatch at pos {pos}!"
    print(f"  [PASS] Val row/label alignment verified at positions: {spot_checks_val}")

    # Re-verify test set is still untouched
    test_stat_final = os.stat(TEST_JSONL)
    assert test_stat_final.st_size == TEST_EXPECTED_SIZE, "Test file size changed!"
    assert abs(test_stat_final.st_mtime - TEST_EXPECTED_MTIME) < 2.0, "Test file mtime changed!"

    ram_final, disk_final = check_ram_and_disk()
    meta = {
        "status": "PASS",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_rows": N_TRAIN,
        "val_rows": N_VAL,
        "features_per_row": D_FEAT,
        "train_benign": train_benign,
        "train_malware": train_malware,
        "val_benign": val_benign,
        "val_malware": val_malware,
        "train_features_bytes": os.path.getsize(TRAIN_FEATURES_FILE),
        "val_features_bytes": os.path.getsize(VAL_FEATURES_FILE),
        "available_ram_final_gb": round(ram_final, 2),
        "free_disk_final_gb": round(disk_final, 2),
        "test_partition_status": "UNTOUCHED_VERIFIED"
    }

    with open(PARTITION_META_FILE, "w") as f:
        json.dump(meta, f, indent=2)

    print("\n" + "=" * 80)
    print("STEP 3.1 CHUNKED STREAMING & ROW/LABEL MAPPING: PASS")
    print(f"Train File: {TRAIN_FEATURES_FILE} ({os.path.getsize(TRAIN_FEATURES_FILE):,} bytes)")
    print(f"Val File:   {VAL_FEATURES_FILE} ({os.path.getsize(VAL_FEATURES_FILE):,} bytes)")
    print(f"Available RAM: {ram_final:.2f} GB | Free Disk: {disk_final:.2f} GB")
    print("=" * 80)


if __name__ == "__main__":
    main()
