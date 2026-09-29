"""
CYBERGUARD Deepfake Audio Dataset Ingestion, Deduplication & Leakage-Safe Manifest Generator.
Ingests samples from the official public 'garystafford/deepfake-audio-detection' benchmark (CC-BY-4.0).
Performs:
1. Strict cryptographic raw & decoded audio deduplication.
2. Near-duplicate spectral fingerprint isolation.
3. Standardized 16 kHz mono verification.
4. Source/speaker-level isolation between Train, Validation, and Test.
5. Unseen-TTS-Engine test set partition (Kokoro 'hg' and Hume AI 'hu' strictly held out in Test).
"""

import os
import csv
import json
import math
import hashlib
import numpy as np
import scipy.signal as signal
import soundfile as sf
from pathlib import Path
from typing import Dict, List, Tuple, Set

REPO_ROOT = Path(__file__).resolve().parents[3]
DATASET_DIR = REPO_ROOT / "datasets" / "deepfake-audio-detection"
RAW_DIR = DATASET_DIR / "raw"
MANIFEST_PATH = DATASET_DIR / "manifest.csv"

# Disjoint speaker sources for real audio
REAL_TRAIN_SOURCES = {"yt_0000", "yt_0001", "yt_0004", "yt_0006", "yt_0007", "yt_0010", "yt_0011", "yt_0013"}
REAL_VAL_SOURCES = {"yt_0002", "yt_0005", "yt_0012"}
REAL_TEST_SOURCES = {"yt_0003", "yt_0008", "yt_0009"}

# Target counts per split
SAMPLES_CONFIG = {
    "train": {"real": 70, "fake": 70},
    "validation": {"real": 25, "fake": 25},
    "test": {"real": 25, "fake": 25},
}


def compute_audio_hashes_and_fp(fpath: Path) -> Tuple[str, str, np.ndarray]:
    """
    Computes:
    1. Raw file SHA-256 hash.
    2. Decoded 16 kHz mono float32 PCM SHA-256 hash.
    3. Normalized 32-bin spectral envelope fingerprint for near-duplicate cross-correlation.
    """
    raw_bytes = fpath.read_bytes()
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()

    raw, sr = sf.read(str(fpath), dtype="float32")
    if raw.ndim > 1:
        raw = raw.mean(axis=1)

    if sr != 16000:
        gcd = math.gcd(sr, 16000)
        up = 16000 // gcd
        down = sr // gcd
        raw = signal.resample_poly(raw, up, down).astype(np.float32)
        sr = 16000

    raw = raw - float(np.mean(raw))
    peak = float(np.max(np.abs(raw)))
    if peak > 1e-6:
        raw = raw / peak

    # Quantize to int16 PCM for exact decoded hash comparison
    pcm16 = (np.clip(raw, -1.0, 1.0) * 32767).astype(np.int16)
    decoded_hash = hashlib.sha256(pcm16.tobytes()).hexdigest()

    # Temporal energy envelope for near-duplicate cross-correlation (20ms frames = 320 samples at 16 kHz)
    frame_sz = 320
    frames = [float(np.sum(raw[i:i + frame_sz] ** 2)) for i in range(0, len(raw) - frame_sz, frame_sz)]
    env = np.array(frames, dtype=np.float32)
    norm_val = float(np.linalg.norm(env)) + 1e-9
    env_norm = env / norm_val

    return raw_hash, decoded_hash, env_norm



def extract_source_id(filename: str) -> str:
    parts = filename.split("_")
    return f"{parts[0]}_{parts[1]}"


def get_manipulation_type(filename: str, label: str) -> str:
    if label == "genuine":
        return "none"
    prefix = filename[:2].lower()
    engines = {
        "el": "ElevenLabs Neural TTS",
        "po": "Amazon Polly Concatenative/Neural",
        "hg": "Kokoro / HuggingFace TTS",
        "hu": "Hume AI Expressive Voice",
        "lv": "Luvvoice TTS",
        "sp": "Speechify Neural Voice",
    }
    return engines.get(prefix, "Neural Voice Clone")


def build_leakage_safe_dataset():
    print("=== CYBERGUARD Deepfake Audio Ingestion & Leakage-Free Partitioning ===")
    assert RAW_DIR.exists(), f"Raw directory not found: {RAW_DIR}"

    real_files = sorted(list((RAW_DIR / "real").glob("*.flac")))
    fake_files = sorted(list((RAW_DIR / "fake").glob("*.flac")))

    print(f"Total files available locally: {len(real_files)} real, {len(fake_files)} fake")

    # Step 1: Compute hashes and deduplicate
    seen_raw_hashes: Set[str] = set()
    seen_decoded_hashes: Set[str] = set()
    unique_real: List[Tuple[Path, str, str, np.ndarray]] = []
    unique_fake: List[Tuple[Path, str, str, np.ndarray]] = []

    real_dups = 0
    for p in real_files:
        rh, dh, fp = compute_audio_hashes_and_fp(p)
        if rh in seen_raw_hashes or dh in seen_decoded_hashes:
            real_dups += 1
            continue
        seen_raw_hashes.add(rh)
        seen_decoded_hashes.add(dh)
        unique_real.append((p, rh, dh, fp))

    fake_dups = 0
    for p in fake_files:
        rh, dh, fp = compute_audio_hashes_and_fp(p)
        if rh in seen_raw_hashes or dh in seen_decoded_hashes:
            fake_dups += 1
            continue
        seen_raw_hashes.add(rh)
        seen_decoded_hashes.add(dh)
        unique_fake.append((p, rh, dh, fp))

    print(f"Deduplication complete: {real_dups} real duplicates removed, {fake_dups} fake duplicates removed.")
    print(f"Unique files remaining: {len(unique_real)} real, {len(unique_fake)} fake")

    # Step 2: Organize Real files by source
    real_by_source: Dict[str, List[Tuple[Path, str, str, np.ndarray]]] = {}
    for item in unique_real:
        sid = extract_source_id(item[0].name)
        real_by_source.setdefault(sid, []).append(item)

    # Step 3: Organize Fake files by engine and source
    # Unseen TTS Engines for Test partition strictly: Kokoro ('hg') and Hume AI ('hu')
    fake_test_pool = [item for item in unique_fake if item[0].name.startswith("hg_") or item[0].name.startswith("hu_")]
    # Seen TTS Engines for Train and Val: ElevenLabs ('el'), Amazon Polly ('po'), Luvvoice ('lv')
    fake_train_val_pool = [item for item in unique_fake if item[0].name[:2] in ("el", "po", "lv")]

    print(f"Fake pools: {len(fake_train_val_pool)} seen-engine files (el/po/lv), {len(fake_test_pool)} unseen-engine files (hg/hu)")

    # Group fake train/val by source
    fake_tv_by_source: Dict[str, List[Tuple[Path, str, str, np.ndarray]]] = {}
    for item in fake_train_val_pool:
        sid = extract_source_id(item[0].name)
        fake_tv_by_source.setdefault(sid, []).append(item)

    # Disjointly allocate fake train and val sources
    sorted_fake_tv_sources = sorted(fake_tv_by_source.keys())
    # Deterministic split of train/val sources: ~65% train sources, ~35% val sources
    split_pt = int(len(sorted_fake_tv_sources) * 0.65)
    fake_train_sources = set(sorted_fake_tv_sources[:split_pt])
    fake_val_sources = set(sorted_fake_tv_sources[split_pt:])

    # Ensure zero overlap in fake sources
    assert len(fake_train_sources & fake_val_sources) == 0, "Fake Train/Val source overlap!"

    # Allocate Real splits
    real_train_selected = []
    for sid in sorted(REAL_TRAIN_SOURCES):
        real_train_selected.extend(real_by_source.get(sid, []))
    real_train_selected = real_train_selected[:SAMPLES_CONFIG["train"]["real"]]

    real_val_selected = []
    for sid in sorted(REAL_VAL_SOURCES):
        real_val_selected.extend(real_by_source.get(sid, []))
    real_val_selected = real_val_selected[:SAMPLES_CONFIG["validation"]["real"]]

    real_test_selected = []
    for sid in sorted(REAL_TEST_SOURCES):
        real_test_selected.extend(real_by_source.get(sid, []))
    real_test_selected = real_test_selected[:SAMPLES_CONFIG["test"]["real"]]

    # Allocate Fake splits
    # Train fake: from fake_train_sources
    fake_train_selected = []
    for sid in sorted(fake_train_sources):
        fake_train_selected.extend(fake_tv_by_source.get(sid, []))
    fake_train_selected = fake_train_selected[:SAMPLES_CONFIG["train"]["fake"]]

    # Val fake: from fake_val_sources
    fake_val_selected = []
    for sid in sorted(fake_val_sources):
        fake_val_selected.extend(fake_tv_by_source.get(sid, []))
    fake_val_selected = fake_val_selected[:SAMPLES_CONFIG["validation"]["fake"]]

    # Test fake: strictly from unseen engines (Kokoro 'hg' and Hume AI 'hu')
    fake_test_selected = fake_test_pool[:SAMPLES_CONFIG["test"]["fake"]]

    # Final split dictionaries
    splits = {
        "train": {"real": real_train_selected, "fake": fake_train_selected},
        "validation": {"real": real_val_selected, "fake": fake_val_selected},
        "test": {"real": real_test_selected, "fake": fake_test_selected},
    }

    # Step 4: Verification of split isolation, hash uniqueness, and near-duplicate distance
    train_raw_hashes = {item[1] for item in splits["train"]["real"] + splits["train"]["fake"]}
    val_raw_hashes = {item[1] for item in splits["validation"]["real"] + splits["validation"]["fake"]}
    test_raw_hashes = {item[1] for item in splits["test"]["real"] + splits["test"]["fake"]}

    train_dec_hashes = {item[2] for item in splits["train"]["real"] + splits["train"]["fake"]}
    val_dec_hashes = {item[2] for item in splits["validation"]["real"] + splits["validation"]["fake"]}
    test_dec_hashes = {item[2] for item in splits["test"]["real"] + splits["test"]["fake"]}

    assert len(train_raw_hashes & val_raw_hashes) == 0, "Raw hash Train-Val leakage!"
    assert len(train_raw_hashes & test_raw_hashes) == 0, "Raw hash Train-Test leakage!"
    assert len(val_raw_hashes & test_raw_hashes) == 0, "Raw hash Val-Test leakage!"

    assert len(train_dec_hashes & val_dec_hashes) == 0, "Decoded hash Train-Val leakage!"
    assert len(train_dec_hashes & test_dec_hashes) == 0, "Decoded hash Train-Test leakage!"
    assert len(val_dec_hashes & test_dec_hashes) == 0, "Decoded hash Val-Test leakage!"

    train_sources = {extract_source_id(item[0].name) for item in splits["train"]["real"] + splits["train"]["fake"]}
    val_sources = {extract_source_id(item[0].name) for item in splits["validation"]["real"] + splits["validation"]["fake"]}
    test_sources = {extract_source_id(item[0].name) for item in splits["test"]["real"] + splits["test"]["fake"]}

    assert len(train_sources & val_sources) == 0, "Source Train-Val leakage!"
    assert len(train_sources & test_sources) == 0, "Source Train-Test leakage!"
    assert len(val_sources & test_sources) == 0, "Source Val-Test leakage!"

    # Near duplicate check: pairwise envelope cross-correlation across split boundaries
    train_envs = [item[3] for item in splits["train"]["real"] + splits["train"]["fake"]]
    val_envs = [item[3] for item in splits["validation"]["real"] + splits["validation"]["fake"]]
    test_envs = [item[3] for item in splits["test"]["real"] + splits["test"]["fake"]]

    def max_cross_corr(list_a, list_b):
        m = 0.0
        for a in list_a:
            for b in list_b:
                c = float(np.max(np.abs(signal.correlate(a, b, mode='full'))))
                if c > m:
                    m = c
        return m

    max_tv_sim = max_cross_corr(train_envs, val_envs)
    max_tt_sim = max_cross_corr(train_envs, test_envs)
    max_vt_sim = max_cross_corr(val_envs, test_envs)

    print(f"Near-duplicate check (max cross-split temporal envelope cross-correlation):")
    print(f"  Train vs Val:  {max_tv_sim:.4f} (< 0.90 threshold)")
    print(f"  Train vs Test: {max_tt_sim:.4f} (< 0.90 threshold)")
    print(f"  Val vs Test:   {max_vt_sim:.4f} (< 0.90 threshold)")
    assert max_tv_sim < 0.90 and max_tt_sim < 0.90 and max_vt_sim < 0.90, "Near duplicate detected across splits!"


    # Step 5: Write manifest.csv
    manifest_rows = []
    for split_name, categories in splits.items():
        for item in categories["real"]:
            p, rh, dh, _ = item
            manifest_rows.append({
                "sample_id": p.name.replace(".flac", ""),
                "path": str(p.relative_to(DATASET_DIR)).replace("\\", "/"),
                "label": "genuine",
                "source_id": extract_source_id(p.name),
                "video_id": extract_source_id(p.name),
                "manipulation_type": "none",
                "split": split_name,
                "raw_sha256": rh,
                "decoded_sha256": dh,
            })
        for item in categories["fake"]:
            p, rh, dh, _ = item
            manifest_rows.append({
                "sample_id": p.name.replace(".flac", ""),
                "path": str(p.relative_to(DATASET_DIR)).replace("\\", "/"),
                "label": "manipulated",
                "source_id": extract_source_id(p.name),
                "video_id": extract_source_id(p.name),
                "manipulation_type": get_manipulation_type(p.name, "manipulated"),
                "split": split_name,
                "raw_sha256": rh,
                "decoded_sha256": dh,
            })

    fieldnames = ["sample_id", "path", "label", "source_id", "video_id", "manipulation_type", "split", "raw_sha256", "decoded_sha256"]
    with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"\nManifest successfully written to: {MANIFEST_PATH}")
    print(f"Total samples: {len(manifest_rows)}")
    for s in ["train", "validation", "test"]:
        s_rows = [r for r in manifest_rows if r["split"] == s]
        real_c = sum(1 for r in s_rows if r["label"] == "genuine")
        fake_c = sum(1 for r in s_rows if r["label"] == "manipulated")
        srcs = {r["source_id"] for r in s_rows}
        engines = {r["manipulation_type"] for r in s_rows if r["label"] == "manipulated"}
        print(f"  {s.upper()}: {len(s_rows)} samples ({real_c} genuine, {fake_c} manipulated) across {len(srcs)} sources. Engines: {engines}")


if __name__ == "__main__":
    build_leakage_safe_dataset()
