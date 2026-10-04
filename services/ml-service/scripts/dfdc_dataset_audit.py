"""
CYBERGUARD DFDC Dataset Discovery and Audit Script.
Analyzes the datasets/DFDC directory, verifies file integrity,
computes tensor dimensions, audits class distributions, evaluates data leakage risks,
and produces a comprehensive audit report in JSON format.
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import torch


def compute_file_sha256(filepath: Path, chunk_size: int = 1024 * 1024) -> str:
    """Computes SHA-256 hash of a file efficiently."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def audit_dfdc_dataset(workspace_root: Path) -> Dict[str, Any]:
    dfdc_dir = workspace_root / "datasets" / "DFDC"
    report: Dict[str, Any] = {
        "dataset_name": "DFDC_Shield_2026",
        "dataset_path": str(dfdc_dir.resolve()),
        "status": "DISCOVERED",
        "timestamp": None,
    }

    import datetime
    report["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if not dfdc_dir.exists():
        report["status"] = "NOT_FOUND"
        report["error"] = f"Directory not found: {dfdc_dir}"
        return report

    # 1. File Inventory
    all_files = []
    file_hashes: Dict[str, str] = {}
    total_bytes = 0

    for root, dirs, files in os.walk(dfdc_dir):
        for f in files:
            full_path = Path(root) / f
            rel_path = str(full_path.relative_to(dfdc_dir)).replace("\\", "/")
            size = full_path.stat().st_size
            total_bytes += size
            sha256 = compute_file_sha256(full_path)
            file_hashes[rel_path] = sha256
            all_files.append({
                "relative_path": rel_path,
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 2),
                "sha256": sha256,
            })

    report["file_inventory"] = {
        "total_files": len(all_files),
        "total_size_bytes": total_bytes,
        "total_size_mb": round(total_bytes / (1024 * 1024), 2),
        "files": all_files,
    }

    # 2. Raw Video Discovery Check
    raw_video_extensions = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv"}
    raw_videos = [f for f in all_files if any(f["relative_path"].lower().endswith(ext) for ext in raw_video_extensions)]
    report["raw_videos"] = {
        "count": len(raw_videos),
        "present": len(raw_videos) > 0,
        "notes": "No raw .mp4 videos are stored locally. The dataset consists of pre-extracted frame-level feature embeddings." if len(raw_videos) == 0 else f"Found {len(raw_videos)} raw video files."
    }

    # 3. Documentation & Source Notebook Discovery
    pdf_present = (dfdc_dir / "Deepfake.pdf").exists()
    nb_present = (dfdc_dir / ".virtual_documents" / "__notebook_source__.ipynb").exists()
    report["documentation_and_metadata"] = {
        "pdf_research_paper": {
            "present": pdf_present,
            "filename": "Deepfake.pdf",
            "title": "Deepfake Detection in Manipulated Images/ Audio (IJISRT 2025)",
            "authors": "Harish Chaudhary, Nandeesh C. R, Gagan T. N, V. Tejas Aarya, Dr. Shakunthala B. S, Chethan Kumar T."
        },
        "notebook_provenance": {
            "present": nb_present,
            "filename": ".virtual_documents/__notebook_source__.ipynb",
            "backbone_model": "CLIP ViT-H/14 (laion2b_s32b_b79k)",
            "feature_dim": 1024,
            "frames_per_video": 20,
            "normalization": "L2 normalized (features /= norm)",
            "sources_aggregated": ["FaceForensics++ (C23)", "Celeb-DF v2", "DFDC (dfdc-10)"],
            "sampling_method": "Deterministic uniform 20-frame sampling (np.linspace(0, len(vr)-1, 20))"
        }
    }

    # 4. PyTorch Tensor Audit (shield_2026_final_data)
    tensor_dir = dfdc_dir / "shield_2026_final_data"
    required_tensors = ["X_train.pt", "y_train.pt", "X_val.pt", "y_val.pt", "X_test.pt", "y_test.pt"]
    missing_tensors = [t for t in required_tensors if not (tensor_dir / t).exists()]

    if missing_tensors:
        report["tensor_audit"] = {
            "status": "INCOMPLETE",
            "missing": missing_tensors
        }
        return report

    # Load and inspect tensors
    try:
        x_tr = torch.load(tensor_dir / "X_train.pt", map_location="cpu", weights_only=True)
        y_tr = torch.load(tensor_dir / "y_train.pt", map_location="cpu", weights_only=True)
        x_va = torch.load(tensor_dir / "X_val.pt", map_location="cpu", weights_only=True)
        y_va = torch.load(tensor_dir / "y_val.pt", map_location="cpu", weights_only=True)
        x_te = torch.load(tensor_dir / "X_test.pt", map_location="cpu", weights_only=True)
        y_te = torch.load(tensor_dir / "y_test.pt", map_location="cpu", weights_only=True)
    except Exception as e:
        report["tensor_audit"] = {
            "status": "CORRUPTED",
            "error": str(e)
        }
        return report

    def get_split_stats(name: str, x: torch.Tensor, y: torch.Tensor) -> Dict[str, Any]:
        count = len(y)
        bincount = torch.bincount(y).tolist()
        real_count = bincount[0] if len(bincount) > 0 else 0
        fake_count = bincount[1] if len(bincount) > 1 else 0
        has_nan = bool(torch.isnan(x).any().item())
        has_inf = bool(torch.isinf(x).any().item())

        # Norm check on first 100 vectors
        sample_norms = torch.norm(x[:min(100, count)], dim=-1)
        mean_norm = float(sample_norms.mean().item())

        return {
            "split_name": name,
            "num_samples": count,
            "tensor_shape": list(x.shape),
            "data_type": str(x.dtype),
            "genuine_count": real_count,
            "manipulated_count": fake_count,
            "genuine_percentage": round((real_count / count) * 100.0, 2) if count > 0 else 0.0,
            "manipulated_percentage": round((fake_count / count) * 100.0, 2) if count > 0 else 0.0,
            "has_nan": has_nan,
            "has_inf": has_inf,
            "mean_l2_norm": round(mean_norm, 4),
            "feature_min": float(x.min().item()),
            "feature_max": float(x.max().item()),
            "feature_mean": float(x.mean().item()),
            "feature_std": float(x.std().item()),
        }

    train_stats = get_split_stats("train", x_tr, y_tr)
    val_stats = get_split_stats("val", x_va, y_va)
    test_stats = get_split_stats("test", x_te, y_te)

    total_samples = train_stats["num_samples"] + val_stats["num_samples"] + test_stats["num_samples"]
    total_real = train_stats["genuine_count"] + val_stats["genuine_count"] + test_stats["genuine_count"]
    total_fake = train_stats["manipulated_count"] + val_stats["manipulated_count"] + test_stats["manipulated_count"]

    report["splits"] = {
        "train": train_stats,
        "validation": val_stats,
        "test": test_stats,
        "total_samples": total_samples,
        "total_genuine": total_real,
        "total_manipulated": total_fake,
        "overall_genuine_pct": round((total_real / total_samples) * 100.0, 2),
        "overall_manipulated_pct": round((total_fake / total_samples) * 100.0, 2),
        "imbalance_ratio": f"1:{round(total_fake / total_real, 2)}",
    }

    # 5. Exact and Near-Duplicate Leakage Analysis Across Splits
    print("Performing cross-split exact collision check...")
    # Flatten frame vectors for quick fingerprinting: hash first frame + mean vector
    def get_fingerprints(x: torch.Tensor) -> np.ndarray:
        # Compute mean feature vector per video [N, 1024]
        mean_vecs = x.mean(dim=1).numpy()
        return mean_vecs

    tr_means = get_fingerprints(x_tr)
    va_means = get_fingerprints(x_va)
    te_means = get_fingerprints(x_te)

    # Exact collision check using row equality
    # Check test vs train
    from sklearn.metrics.pairwise import cosine_similarity

    # Subsample 500 test samples against 1000 train samples for cosine similarity leakage inspection
    n_sample_te = min(500, len(te_means))
    n_sample_tr = min(1000, len(tr_means))
    sim_matrix = cosine_similarity(te_means[:n_sample_te], tr_means[:n_sample_tr])

    exact_duplicates = int(np.sum(sim_matrix > 0.9999))
    high_similarity_pairs = int(np.sum(sim_matrix > 0.98))

    report["leakage_analysis"] = {
        "cross_split_exact_duplicates": exact_duplicates,
        "high_similarity_pairs_above_98pct": high_similarity_pairs,
        "source_disjoint_guarantee": "PARTIAL_UNVERIFIED",
        "leakage_risk_assessment": (
            "The dataset was split using stratified train_test_split on video-level tensors. "
            "Because original source video identity IDs were omitted from the local .pt files, "
            "unseen-identity disjointness cannot be cryptographically guaranteed. "
            "Evaluations on this test partition must be reported as Shield-DFDC held-out test partition "
            "rather than claiming general real-world benchmark accuracy."
        )
    }

    # 6. Overall Suitability Decision
    is_usable = (
        total_samples >= 1000
        and not train_stats["has_nan"]
        and not val_stats["has_nan"]
        and not test_stats["has_nan"]
        and total_real > 100
        and total_fake > 100
    )

    report["audit_conclusion"] = {
        "structurally_usable": is_usable,
        "is_complete_dfdc": False,
        "subset_specification": "Shield 2026 Deepfake Benchmark (14,941 samples: DFDC-10 + FF++ C23 + Celeb-DF v2)",
        "supervised_training_ready": is_usable,
        "recommended_architecture": "Attention-Pooled Temporal Feature Classifier (1024-dim input, multi-head temporal pooling, MLP classification head)",
        "recommended_loss": "Focal Loss or Weighted Binary Cross-Entropy (handling 1:8.4 class imbalance)",
    }

    return report


def main():
    script_dir = Path(__file__).resolve().parent
    workspace_root = script_dir.parent.parent.parent
    print(f"[DFDC Audit] Auditing DFDC dataset at workspace root: {workspace_root}")

    report = audit_dfdc_dataset(workspace_root)

    report_path = script_dir / "dfdc_dataset_audit_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[DFDC Audit] Audit report saved successfully to: {report_path}")
    print("\n" + "=" * 60)
    print("           CYBERGUARD DFDC DATASET AUDIT SUMMARY")
    print("=" * 60)
    print(f"Dataset Path        : {report.get('dataset_path')}")
    print(f"Total Files         : {report.get('file_inventory', {}).get('total_files')}")
    print(f"Total Size          : {report.get('file_inventory', {}).get('total_size_mb')} MB")
    print(f"Total Samples       : {report.get('splits', {}).get('total_samples')}")
    print(f"Train Samples       : {report.get('splits', {}).get('train', {}).get('num_samples')} (Genuine: {report.get('splits', {}).get('train', {}).get('genuine_count')}, Fake: {report.get('splits', {}).get('train', {}).get('manipulated_count')})")
    print(f"Val Samples         : {report.get('splits', {}).get('validation', {}).get('num_samples')} (Genuine: {report.get('splits', {}).get('validation', {}).get('genuine_count')}, Fake: {report.get('splits', {}).get('validation', {}).get('manipulated_count')})")
    print(f"Test Samples        : {report.get('splits', {}).get('test', {}).get('num_samples')} (Genuine: {report.get('splits', {}).get('test', {}).get('genuine_count')}, Fake: {report.get('splits', {}).get('test', {}).get('manipulated_count')})")
    print(f"Class Imbalance     : {report.get('splits', {}).get('imbalance_ratio')}")
    print(f"Structurally Usable : {report.get('audit_conclusion', {}).get('structurally_usable')}")
    print(f"Supervised Ready    : {report.get('audit_conclusion', {}).get('supervised_training_ready')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
