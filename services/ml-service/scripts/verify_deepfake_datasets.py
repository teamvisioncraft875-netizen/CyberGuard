"""
CYBERGUARD Phase 5A: Deepfake Dataset and Feature Audit Script.
Validates tensor shapes, sample counts, class distributions, zero NaNs/Infs,
embedding statistics, SHA-256 hashes, and audio source-disjointness.
Zero synthetic data, real benchmark datasets only.
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
import torch

REPO_ROOT = Path(__file__).resolve().parents[3]
DFDC_DIR = REPO_ROOT / "datasets" / "DFDC" / "shield_2026_final_data"
AUDIO_DIR = REPO_ROOT / "datasets" / "deepfake-audio-detection"
AUDIO_MANIFEST = AUDIO_DIR / "manifest.csv"
OUTPUT_REPORT = REPO_ROOT / "services" / "ml-service" / "scripts" / "phase5_dataset_audit_report.json"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def audit_dfdc_tensors() -> Dict[str, Any]:
    print("=" * 70)
    print("AUDITING DFDC SHIELD 2026 VISUAL TENSORS")
    print("=" * 70)

    partitions = ["train", "val", "test"]
    audit_data = {}

    for split in partitions:
        x_path = DFDC_DIR / f"X_{split}.pt"
        y_path = DFDC_DIR / f"y_{split}.pt"

        assert x_path.exists(), f"Missing {x_path}"
        assert y_path.exists(), f"Missing {y_path}"

        x_sha = compute_sha256(x_path)
        y_sha = compute_sha256(y_path)
        x_size = os.path.getsize(x_path)
        y_size = os.path.getsize(y_path)

        x_t = torch.load(x_path, map_location="cpu", weights_only=True)
        y_t = torch.load(y_path, map_location="cpu", weights_only=True)

        # Assertions
        assert x_t.dim() == 3, f"Expected 3D tensor [N, 20, 1024], got {x_t.shape}"
        assert x_t.shape[1] == 20, f"Expected temporal dimension 20, got {x_t.shape[1]}"
        assert x_t.shape[2] == 1024, f"Expected feature dimension 1024, got {x_t.shape[2]}"
        assert x_t.shape[0] == y_t.shape[0], f"Sample count mismatch: {x_t.shape[0]} vs {y_t.shape[0]}"

        nan_count = int(torch.isnan(x_t).sum().item())
        inf_count = int(torch.isinf(x_t).sum().item())
        assert nan_count == 0, f"Found {nan_count} NaNs in {split}"
        assert inf_count == 0, f"Found {inf_count} Infs in {split}"

        labels = y_t.numpy().flatten().astype(int)
        genuine_count = int(np.sum(labels == 0))
        manipulated_count = int(np.sum(labels == 1))
        total_count = int(len(labels))
        assert genuine_count + manipulated_count == total_count, "Invalid class labels found"

        # Statistics
        norms = torch.norm(x_t, p=2, dim=-1)
        mean_l2 = float(norms.mean().item())
        std_l2 = float(norms.std().item())
        min_val = float(x_t.min().item())
        max_val = float(x_t.max().item())
        mean_val = float(x_t.mean().item())
        std_val = float(x_t.std().item())

        audit_data[split] = {
            "tensor_shape": list(x_t.shape),
            "sample_count": total_count,
            "genuine_count": genuine_count,
            "manipulated_count": manipulated_count,
            "genuine_percentage": round(genuine_count / total_count * 100.0, 2),
            "manipulated_percentage": round(manipulated_count / total_count * 100.0, 2),
            "nan_count": nan_count,
            "inf_count": inf_count,
            "x_file": {
                "filename": x_path.name,
                "size_bytes": x_size,
                "size_mb": round(x_size / (1024**2), 2),
                "sha256": x_sha,
            },
            "y_file": {
                "filename": y_path.name,
                "size_bytes": y_size,
                "size_mb": round(y_size / (1024**2), 2),
                "sha256": y_sha,
            },
            "statistics": {
                "min": round(min_val, 6),
                "max": round(max_val, 6),
                "mean": round(mean_val, 6),
                "std": round(std_val, 6),
                "mean_l2_norm": round(mean_l2, 6),
                "std_l2_norm": round(std_l2, 6),
            },
        }

        print(
            f"[{split.upper()}] Shape: {x_t.shape} | Samples: {total_count:,} (Real: {genuine_count:,}, Fake: {manipulated_count:,}) | NaN/Inf: 0 | Mean L2 Norm: {mean_l2:.4f}"
        )

    # Check for cross-partition exact duplicate embeddings
    print("\nVerifying cross-partition sample isolation...")
    x_train = torch.load(DFDC_DIR / "X_train.pt", map_location="cpu", weights_only=True)
    x_val = torch.load(DFDC_DIR / "X_val.pt", map_location="cpu", weights_only=True)
    x_test = torch.load(DFDC_DIR / "X_test.pt", map_location="cpu", weights_only=True)

    # Compute video-pooled mean embeddings for fast duplicate fingerprinting
    train_pooled = x_train.mean(dim=1).numpy()
    val_pooled = x_val.mean(dim=1).numpy()
    test_pooled = x_test.mean(dim=1).numpy()

    # Hash fingerprints
    def hash_rows(arr):
        return {hashlib.sha256(row.tobytes()).hexdigest() for row in arr}

    h_train = hash_rows(train_pooled)
    h_val = hash_rows(val_pooled)
    h_test = hash_rows(test_pooled)

    train_val_overlap = len(h_train.intersection(h_val))
    train_test_overlap = len(h_train.intersection(h_test))
    val_test_overlap = len(h_val.intersection(h_test))

    print(f"  Exact Pooled Vector Overlap (Train / Val): {train_val_overlap}")
    print(f"  Exact Pooled Vector Overlap (Train / Test): {train_test_overlap}")
    print(f"  Exact Pooled Vector Overlap (Val / Test): {val_test_overlap}")
    assert train_val_overlap == 0, "Data leakage between train and val!"
    assert train_test_overlap == 0, "Data leakage between train and test!"
    assert val_test_overlap == 0, "Data leakage between val and test!"

    audit_data["cross_partition_isolation"] = {
        "train_val_exact_overlap": train_val_overlap,
        "train_test_exact_overlap": train_test_overlap,
        "val_test_exact_overlap": val_test_overlap,
        "status": "STRICTLY_DISJOINT",
    }

    return audit_data


def audit_audio_dataset() -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print("AUDITING CURATED DEEPFAKE AUDIO BENCHMARK")
    print("=" * 70)

    assert AUDIO_MANIFEST.exists(), f"Missing audio manifest {AUDIO_MANIFEST}"
    df = pd.read_csv(AUDIO_MANIFEST)

    total_samples = len(df)
    splits = df["split"].value_counts().to_dict()
    labels = df["label"].value_counts().to_dict()
    unique_sources = df["source_id"].nunique()

    train_sources = set(df[df["split"] == "train"]["source_id"])
    val_sources = set(df[df["split"] == "val"]["source_id"])
    test_sources = set(df[df["split"] == "test"]["source_id"])

    tv_overlap = len(train_sources.intersection(val_sources))
    tt_overlap = len(train_sources.intersection(test_sources))
    vt_overlap = len(val_sources.intersection(test_sources))

    print(f"Total audio samples: {total_samples}")
    print(f"Splits: {splits}")
    print(f"Labels: {labels}")
    print(f"Unique speaker sources: {unique_sources}")
    print(f"Source overlaps -> Train/Val: {tv_overlap}, Train/Test: {tt_overlap}, Val/Test: {vt_overlap}")

    assert tv_overlap == 0, "Audio source leakage between train and val!"
    assert tt_overlap == 0, "Audio source leakage between train and test!"
    assert vt_overlap == 0, "Audio source leakage between val and test!"

    # Verify physical file existence
    missing_files = 0
    for _, row in df.iterrows():
        p = AUDIO_DIR / row["path"]
        if not p.exists():
            missing_files += 1

    assert missing_files == 0, f"Found {missing_files} missing audio files!"
    print(f"Verified all {total_samples} raw audio files exist on disk.")

    manifest_sha = compute_sha256(AUDIO_MANIFEST)

    return {
        "manifest_path": str(AUDIO_MANIFEST),
        "manifest_sha256": manifest_sha,
        "total_samples": total_samples,
        "splits": splits,
        "labels": labels,
        "unique_sources": unique_sources,
        "source_disjointness": {
            "train_sources_count": len(train_sources),
            "val_sources_count": len(val_sources),
            "test_sources_count": len(test_sources),
            "train_val_source_overlap": tv_overlap,
            "train_test_source_overlap": tt_overlap,
            "val_test_source_overlap": vt_overlap,
            "status": "SOURCE_DISJOINT_VERIFIED",
        },
    }


def main():
    dfdc_audit = audit_dfdc_tensors()
    audio_audit = audit_audio_dataset()

    full_report = {
        "audit_title": "CYBERGUARD Phase 5A: Deepfake Dataset and Feature Audit",
        "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "environment": {
            "python": sys.version.split()[0],
            "torch": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "cuda_device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "None",
        },
        "dfdc_visual_dataset": dfdc_audit,
        "deepfake_audio_dataset": audio_audit,
        "overall_status": "PASS",
    }

    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print("\n" + "=" * 70)
    print(f"PHASE 5A AUDIT REPORT SAVED TO: {OUTPUT_REPORT}")
    print("=" * 70)


if __name__ == "__main__":
    main()
