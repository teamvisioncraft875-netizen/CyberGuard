"""
CYBERGUARD — Stage 1: EMBER 600,000 Labeled Record Extraction via Sequential Binary Stream
Phase 4 Step 2 / Stage 1:

Strict Requirements:
1. Zero synthetic data — extracts strictly genuine EMBER 2018 records from train shards 0 through 5.
2. Exactly 600,000 labeled records: 300,000 benign (label 0), 300,000 malware (label 1).
3. 200,000 unlabeled records (label -1) are filtered out and counted.
4. Official test set (test_features.jsonl) is strictly untouched (verified before and after).
5. Sequential Binary Streaming: Writes chunks directly via standard binary file streaming (avoiding persistent OS virtual memory map lock).
6. Memory Safety: Measures available RAM on every chunk; halts safely if available RAM < 2.0 GB.
7. Disk Safety: Halts safely if free disk space < 12.0 GB.
8. Persists cache metadata and integrity info in datasets/malware/ember_cache_600k/.
"""

import gc
import hashlib
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import psutil

# Ensure app is importable
repo_root = Path(__file__).resolve().parents[3]
ml_service_path = repo_root / "services" / "ml-service"
if str(ml_service_path) not in sys.path:
    sys.path.insert(0, str(ml_service_path))

from app.utils.ember_feature_extractor import PEFeatureExtractor, EMBER_FEATURE_DIM

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.ember_600k_stage1")

# Safety Thresholds
MIN_SAFE_RAM_BYTES = 2.0 * (1024 ** 3)   # 2.0 GB minimum available RAM
MIN_SAFE_DISK_BYTES = 12.0 * (1024 ** 3) # 12.0 GB minimum free disk space
CHUNK_SIZE = 5000

EXPECTED_LABELED_TOTAL = 600000
EXPECTED_BENIGN_TOTAL = 300000
EXPECTED_MALWARE_TOTAL = 300000
EXPECTED_UNLABELED_TOTAL = 200000
EXPECTED_BYTES_PER_SAMPLE = EMBER_FEATURE_DIM * 4  # 9,524 bytes

DATASET_DIR = repo_root / "datasets" / "malware" / "ember2018"
TEST_FILE = DATASET_DIR / "test_features.jsonl"
TRAIN_SHARDS = [DATASET_DIR / f"train_features_{i}.jsonl" for i in range(6)]

CACHE_DIR = repo_root / "datasets" / "malware" / "ember_cache_600k"
CACHE_FEATURES_FILE = CACHE_DIR / "features_600k.dat"
CACHE_LABELS_FILE = CACHE_DIR / "labels_600k.npy"
CACHE_HASHES_FILE = CACHE_DIR / "sha256_600k.txt"
METADATA_FILE = CACHE_DIR / "cache_metadata.json"


def check_system_resources() -> Tuple[float, float]:
    """Returns available RAM (GB) and free disk space (GB), raising error if thresholds violated."""
    vmem = psutil.virtual_memory()
    avail_ram = vmem.available
    disk_free = shutil.disk_usage(str(repo_root)).free

    avail_ram_gb = avail_ram / (1024 ** 3)
    disk_free_gb = disk_free / (1024 ** 3)

    if avail_ram < MIN_SAFE_RAM_BYTES:
        raise MemoryError(
            f"SAFETY ABORT: Available RAM ({avail_ram_gb:.2f} GB) fell below safe threshold "
            f"({MIN_SAFE_RAM_BYTES / (1024**3):.2f} GB)."
        )
    if disk_free < MIN_SAFE_DISK_BYTES:
        raise OSError(
            f"SAFETY ABORT: Free disk space ({disk_free_gb:.2f} GB) fell below safe threshold "
            f"({MIN_SAFE_DISK_BYTES / (1024**3):.2f} GB)."
        )

    return avail_ram_gb, disk_free_gb


def run_stage1_extraction():
    logger.info("=" * 70)
    logger.info("CYBERGUARD — STAGE 1: FULL 600,000 REAL EMBER EXTRACTION (STREAMED)")
    logger.info("=" * 70)

    # 1. Verify resource safety before starting
    init_ram_gb, init_disk_gb = check_system_resources()
    logger.info(f"Initial Resources: Available RAM = {init_ram_gb:.2f} GB | Free Disk = {init_disk_gb:.2f} GB")

    # 2. Record untouched test partition baseline
    if not TEST_FILE.exists():
        raise FileNotFoundError(f"Test partition missing at {TEST_FILE}")
    test_stat_init = TEST_FILE.stat()
    test_size_init = test_stat_init.st_size
    test_mtime_init = test_stat_init.st_mtime
    logger.info(f"Verified official test partition untouched: size={test_size_init}, mtime={test_mtime_init}")

    # 3. Verify all 6 training shards exist
    for shard in TRAIN_SHARDS:
        if not shard.exists():
            raise FileNotFoundError(f"Training shard missing: {shard}")

    # 4. Prepare clean cache directory
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if CACHE_FEATURES_FILE.exists():
        CACHE_FEATURES_FILE.unlink()
    if CACHE_LABELS_FILE.exists():
        CACHE_LABELS_FILE.unlink()
    if CACHE_HASHES_FILE.exists():
        CACHE_HASHES_FILE.unlink()

    extractor = PEFeatureExtractor()
    total_extracted = 0
    benign_count = 0
    malware_count = 0
    unlabeled_count = 0
    total_lines_scanned = 0

    chunk_features: List[np.ndarray] = []
    chunk_labels: List[int] = []
    chunk_hashes: List[str] = []

    all_labels_collector: List[int] = []
    unique_hashes_set = set()

    min_observed_ram_gb = init_ram_gb
    t_start = time.time()

    logger.info(f"Opening binary stream: {CACHE_FEATURES_FILE} for sequential chunk writes...")
    with open(CACHE_FEATURES_FILE, "wb") as f_features, open(CACHE_HASHES_FILE, "w", encoding="utf-8") as f_hashes:
        # 5. Stream and extract from all 6 training shards
        for shard_idx, shard_path in enumerate(TRAIN_SHARDS):
            logger.info(f"Processing shard {shard_idx + 1}/6: {shard_path.name}...")
            shard_lines = 0

            with open(shard_path, "r", encoding="utf-8") as f_shard:
                for line in f_shard:
                    shard_lines += 1
                    total_lines_scanned += 1

                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    lbl = obj.get("label", -1)
                    if lbl == -1 or lbl not in (0, 1):
                        unlabeled_count += 1
                        continue

                    # Extract 2,381 numeric features
                    vec = extractor.process_raw_features(obj)
                    chunk_features.append(vec)
                    chunk_labels.append(lbl)
                    h = obj.get("sha256", "")
                    chunk_hashes.append(h)
                    unique_hashes_set.add(h)

                    if lbl == 0:
                        benign_count += 1
                    elif lbl == 1:
                        malware_count += 1

                    # Flush chunk when full
                    if len(chunk_features) >= CHUNK_SIZE:
                        chunk_mat = np.vstack(chunk_features).astype(np.float32)
                        f_features.write(chunk_mat.tobytes())
                        f_features.flush()

                        f_hashes.write("\n".join(chunk_hashes) + "\n")
                        f_hashes.flush()

                        all_labels_collector.extend(chunk_labels)
                        total_extracted += len(chunk_features)

                        chunk_features.clear()
                        chunk_labels.clear()
                        chunk_hashes.clear()
                        del chunk_mat

                        gc.collect()
                        cur_ram_gb, cur_disk_gb = check_system_resources()
                        if cur_ram_gb < min_observed_ram_gb:
                            min_observed_ram_gb = cur_ram_gb

                        if total_extracted % 25000 == 0 or total_extracted == EXPECTED_LABELED_TOTAL:
                            elapsed = time.time() - t_start
                            rate = total_extracted / elapsed
                            logger.info(
                                f"Extracted {total_extracted:,}/{EXPECTED_LABELED_TOTAL:,} records "
                                f"(Benign: {benign_count:,}, Malware: {malware_count:,}, Unlabeled skipped: {unlabeled_count:,}) "
                                f"| Rate: {rate:.1f} rec/s | Avail RAM: {cur_ram_gb:.2f} GB | Free Disk: {cur_disk_gb:.2f} GB"
                            )

        # Flush final chunk if any
        if chunk_features:
            chunk_mat = np.vstack(chunk_features).astype(np.float32)
            f_features.write(chunk_mat.tobytes())
            f_features.flush()

            f_hashes.write("\n".join(chunk_hashes) + "\n")
            f_hashes.flush()

            all_labels_collector.extend(chunk_labels)
            total_extracted += len(chunk_features)

            chunk_features.clear()
            chunk_labels.clear()
            chunk_hashes.clear()
            del chunk_mat
            gc.collect()

    total_time = time.time() - t_start
    logger.info(f"Stream extraction completed in {total_time:.2f}s ({total_time/60:.2f} mins).")

    # 6. Verify Exact File Size on Disk
    expected_features_bytes = EXPECTED_LABELED_TOTAL * EXPECTED_BYTES_PER_SAMPLE  # 5,714,400,000 bytes
    actual_features_bytes = CACHE_FEATURES_FILE.stat().st_size
    logger.info(f"Binary Feature File Size: {actual_features_bytes:,} bytes (Expected: {expected_features_bytes:,})")
    if actual_features_bytes != expected_features_bytes:
        raise ValueError(
            f"Feature file size mismatch! Expected {expected_features_bytes} bytes, got {actual_features_bytes}"
        )

    # 7. Save Labels Array
    logger.info(f"Saving {len(all_labels_collector):,} labels to {CACHE_LABELS_FILE}...")
    labels_np = np.array(all_labels_collector, dtype=np.int32)
    np.save(str(CACHE_LABELS_FILE), labels_np)

    # 8. Verify Exact Counts
    logger.info("Verifying exact counts against mandated constraints...")
    logger.info(f"Total Lines Scanned: {total_lines_scanned:,} (Expected: 800,000)")
    logger.info(f"Total Labeled Extracted: {total_extracted:,} (Expected: 600,000)")
    logger.info(f"Benign Samples: {benign_count:,} (Expected: 300,000)")
    logger.info(f"Malware Samples: {malware_count:,} (Expected: 300,000)")
    logger.info(f"Unlabeled Skipped: {unlabeled_count:,} (Expected: 200,000)")
    logger.info(f"Unique SHA-256 Hashes: {len(unique_hashes_set):,} / {total_extracted:,}")

    if total_extracted != EXPECTED_LABELED_TOTAL:
        raise ValueError(f"Extracted count mismatch! Expected {EXPECTED_LABELED_TOTAL}, got {total_extracted}")
    if benign_count != EXPECTED_BENIGN_TOTAL:
        raise ValueError(f"Benign count mismatch! Expected {EXPECTED_BENIGN_TOTAL}, got {benign_count}")
    if malware_count != EXPECTED_MALWARE_TOTAL:
        raise ValueError(f"Malware count mismatch! Expected {EXPECTED_MALWARE_TOTAL}, got {malware_count}")
    if unlabeled_count != EXPECTED_UNLABELED_TOTAL:
        raise ValueError(f"Unlabeled count mismatch! Expected {EXPECTED_UNLABELED_TOTAL}, got {unlabeled_count}")

    # 9. Verify Memory-Mapped Readability
    logger.info("Validating memory-mapped read access on generated feature file...")
    mmap_reader = np.memmap(
        str(CACHE_FEATURES_FILE),
        dtype=np.float32,
        mode="r",
        shape=(EXPECTED_LABELED_TOTAL, EMBER_FEATURE_DIM),
    )
    first_row = mmap_reader[0]
    last_row = mmap_reader[-1]
    assert len(first_row) == EMBER_FEATURE_DIM, "First row dimension mismatch"
    assert len(last_row) == EMBER_FEATURE_DIM, "Last row dimension mismatch"
    assert not np.isnan(first_row).any(), "NaN detected in first row"
    assert not np.isnan(last_row).any(), "NaN detected in last row"
    del mmap_reader
    gc.collect()
    logger.info("Memory-mapped read verification PASSED.")

    # 10. Verify test partition was completely untouched
    test_stat_final = TEST_FILE.stat()
    test_size_final = test_stat_final.st_size
    test_mtime_final = test_stat_final.st_mtime
    logger.info(f"Verifying official test partition post-extraction: size={test_size_final}, mtime={test_mtime_final}")
    assert test_size_final == test_size_init, "CRITICAL ERROR: test_features.jsonl size was modified!"
    assert test_mtime_final == test_mtime_init, "CRITICAL ERROR: test_features.jsonl mtime was modified!"

    final_ram_gb, final_disk_gb = check_system_resources()
    labels_size_bytes = CACHE_LABELS_FILE.stat().st_size
    hashes_size_bytes = CACHE_HASHES_FILE.stat().st_size
    total_cache_size_bytes = actual_features_bytes + labels_size_bytes + hashes_size_bytes

    # 11. Persist Stage 1 Metadata
    metadata = {
        "stage": "STAGE_1_EXTRACTION_AND_INTEGRITY_VALIDATION",
        "status": "PASS",
        "extraction_method": "SEQUENTIAL_BINARY_STREAM",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_training_shards_scanned": 6,
        "total_lines_scanned": total_lines_scanned,
        "total_extracted_labeled_records": total_extracted,
        "class_distribution": {
            "benign_samples": benign_count,
            "malware_samples": malware_count,
            "unlabeled_skipped": unlabeled_count,
        },
        "feature_dimension": EMBER_FEATURE_DIM,
        "unique_sha256_count": len(unique_hashes_set),
        "generated_files": {
            "features_binary_file": {
                "path": str(CACHE_FEATURES_FILE),
                "size_bytes": actual_features_bytes,
                "shape": [total_extracted, EMBER_FEATURE_DIM],
                "dtype": "float32",
            },
            "labels_array": {
                "path": str(CACHE_LABELS_FILE),
                "size_bytes": labels_size_bytes,
                "shape": [total_extracted],
                "dtype": "int32",
            },
            "hashes_file": {
                "path": str(CACHE_HASHES_FILE),
                "size_bytes": hashes_size_bytes,
                "total_hash_lines": total_extracted,
            },
            "total_cache_size_bytes": total_cache_size_bytes,
            "total_cache_size_gb": round(total_cache_size_bytes / (1024 ** 3), 2),
        },
        "resource_monitoring": {
            "initial_available_ram_gb": round(init_ram_gb, 2),
            "min_observed_ram_gb": round(min_observed_ram_gb, 2),
            "final_available_ram_gb": round(final_ram_gb, 2),
            "initial_free_disk_gb": round(init_disk_gb, 2),
            "final_free_disk_gb": round(final_disk_gb, 2),
            "disk_consumed_gb": round(init_disk_gb - final_disk_gb, 2),
            "duration_seconds": round(total_time, 2),
            "duration_minutes": round(total_time / 60, 2),
            "throughput_samples_per_sec": round(total_extracted / total_time, 1),
        },
        "test_partition_protection": {
            "test_file_path": str(TEST_FILE),
            "status": "UNTOUCHED_VERIFIED",
            "initial_size": test_size_init,
            "final_size": test_size_final,
            "initial_mtime": test_mtime_init,
            "final_mtime": test_mtime_final,
        },
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved Stage 1 metadata to {METADATA_FILE}")
    logger.info("=" * 70)
    logger.info("STAGE 1 COMPLETE: STATUS PASS — READY FOR STAGE 2 APPROVAL")
    logger.info("=" * 70)


if __name__ == "__main__":
    run_stage1_extraction()
