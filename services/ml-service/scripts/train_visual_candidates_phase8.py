#!/usr/bin/env python3
"""
CYBERGUARD Phase 8.2: Visual Deepfake Model Candidate Training, Validation & Final Evaluation.
Trains:
- Candidate A: AttentionPoolingVisualDetector with Corrected Class Weighting (w0=4.7023, w1=0.5595)
- Candidate B: Dual Temporal Fusion (Mean + Attention) with Unweighted BCE
- Candidate C: Dual Temporal Fusion (Mean + Attention) with Corrected Class Weighting

Training and validation strictly utilize:
  X_train.pt / y_train.pt (10,458 samples)
  X_val.pt   / y_val.pt   (2,241 samples)

The frozen test set (X_test.pt / y_test.pt, 2,242 samples) is evaluated EXACTLY ONCE
only after the winning candidate is selected and its threshold is frozen on validation data.
"""

import io
import os
import sys
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
DFDC_DIR = REPO_ROOT / "datasets" / "DFDC" / "shield_2026_final_data"
EXPERIMENT_DIR = ML_SERVICE_DIR / "experiments" / f"visual_candidates_phase8_{time.strftime('%Y%m%d_%H%M%S')}"

if str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

from app.services.media_anomaly.image_detector import AttentionPoolingVisualDetector


# ==============================================================================
# Model Architecture: Dual Temporal Fusion (Mean + Attention)
# ==============================================================================
class DualTemporalFusionVisualDetector(nn.Module):
    """
    Dual Temporal Fusion Neural Network for visual deepfake detection.
    Fuses global temporal average pooling with learned temporal attention pooling:
    z = [x_mean || x_attn] (2048 dims).
    Passes through LayerNorm and regularized MLP classifier.
    Supports single-frame images [batch, 1, 1024] and sequences [batch, 20, 1024].
    """
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.in_features = in_features
        self.hidden_dim = hidden_dim

        # Attention module
        self.attention = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )

        # Fused classifier (2048 -> 256 -> 64 -> 1)
        fused_dim = in_features * 2
        self.classifier = nn.Sequential(
            nn.LayerNorm(fused_dim),
            nn.Dropout(dropout),
            nn.Linear(fused_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(dropout * 0.7),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)

        # 1. Global temporal mean
        x_mean = x.mean(dim=1)

        # 2. Learned attention pooling
        attn_scores = self.attention(x)
        attn_weights = torch.softmax(attn_scores, dim=1)
        x_attn = (x * attn_weights).sum(dim=1)

        # 3. Concatenate representations
        fused = torch.cat([x_mean, x_attn], dim=-1)

        # 4. Classification logits
        logits = self.classifier(fused).squeeze(-1)
        return logits


# ==============================================================================
# Utilities & Metrics
# ==============================================================================
def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50) -> Dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5

    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "specificity": round(spec, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def find_best_threshold(y_val: np.ndarray, val_probs: np.ndarray) -> Tuple[float, Dict[str, Any]]:
    """
    Finds the threshold on validation that maximizes Balanced Accuracy
    while enforcing Specificity >= 80% (FPR <= 20%).
    """
    best_thresh = 0.50
    best_score = -1.0
    best_metrics = None

    for t in np.linspace(0.05, 0.95, 91):
        m = compute_metrics(y_val, val_probs, threshold=float(t))
        if m["specificity"] >= 0.80:
            score = m["balanced_accuracy"] + 0.1 * m["recall"]
            if score > best_score:
                best_score = score
                best_thresh = float(t)
                best_metrics = m

    if best_metrics is None:
        # Fallback to best balanced accuracy
        best_score = -1.0
        for t in np.linspace(0.05, 0.95, 91):
            m = compute_metrics(y_val, val_probs, threshold=float(t))
            if m["balanced_accuracy"] > best_score:
                best_score = m["balanced_accuracy"]
                best_thresh = float(t)
                best_metrics = m

    return float(best_thresh), best_metrics


def apply_training_augmentation(bx: torch.Tensor, p_jitter: float = 0.5) -> torch.Tensor:
    """
    Applies controlled training augmentation:
    - Embedding noise jitter (sigma=0.015)
    - Temporal frame random subsampling (16 of 20 frames with random offset)
    - L2 re-normalization to unit sphere
    """
    # 1. Temporal frame selection: pick 16 consecutive or random frames
    if bx.shape[1] == 20:
        start_idx = np.random.randint(0, 5)  # 0..4, leaving 16 frames
        bx = bx[:, start_idx:start_idx + 16, :]

    # 2. Additive Gaussian noise
    if np.random.rand() < p_jitter:
        noise = torch.randn_like(bx) * 0.015
        bx = bx + noise

    # 3. L2 re-normalization
    bx = bx / (torch.norm(bx, dim=-1, keepdim=True) + 1e-8)
    return bx


def measure_latency_cpu_ms(model: nn.Module, sample_tensor: torch.Tensor, iterations: int = 500) -> float:
    import copy
    model_cpu = copy.deepcopy(model).to("cpu")
    model_cpu.eval()
    sample_cpu = sample_tensor.to("cpu")
    with torch.no_grad():
        for _ in range(50):
            model_cpu(sample_cpu)
        t0 = time.perf_counter()
        for _ in range(iterations):
            model_cpu(sample_cpu)
        t1 = time.perf_counter()
    return ((t1 - t0) / iterations) * 1000.0


# ==============================================================================
# Candidate Training Loop
# ==============================================================================
def train_candidate(
    name: str,
    model: nn.Module,
    x_train: torch.Tensor,
    y_train: torch.Tensor,
    x_val: torch.Tensor,
    y_val: torch.Tensor,
    device: torch.device,
    use_class_weights: bool = False,
    epochs: int = 10,
    batch_size: int = 128,
    lr: float = 1e-4,
    weight_decay: float = 1e-3
) -> Dict[str, Any]:
    print("\n" + "-" * 70)
    print(f"TRAINING {name}")
    print(f"  Architecture: {model.__class__.__name__} | Class weights: {use_class_weights}")
    print(f"  Epochs: {epochs} | Batch size: {batch_size} | LR: {lr} | Weight decay: {weight_decay}")
    print("-" * 70)

    model = model.to(device)
    torch.manual_seed(42)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(42)

    train_dataset = TensorDataset(x_train, y_train.float())
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # Class weights if requested
    w0 = 4.7023  # genuine
    w1 = 0.5595  # manipulated

    best_val_auc = 0.0
    best_weights = None
    best_epoch = 0

    t0_train = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for bx, by in train_loader:
            bx = bx.to(device)
            by = by.to(device)

            # Apply training augmentation
            bx_aug = apply_training_augmentation(bx)

            optimizer.zero_grad()
            logits = model(bx_aug)

            if use_class_weights:
                weights = torch.where(by == 1.0, w1, w0)
                loss_unweighted = nn.functional.binary_cross_entropy_with_logits(logits, by, reduction="none")
                loss = (loss_unweighted * weights).mean()
            else:
                loss = nn.functional.binary_cross_entropy_with_logits(logits, by)

            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(by)

        scheduler.step()

        # Validation evaluation (NO AUGMENTATION)
        model.eval()
        with torch.no_grad():
            val_logits = model(x_val.to(device))
            val_probs = torch.sigmoid(val_logits).cpu().numpy()

        val_auc = roc_auc_score(y_val.numpy(), val_probs)
        val_bal = balanced_accuracy_score(y_val.numpy(), val_probs >= 0.50)
        avg_loss = total_loss / len(train_dataset)

        print(f"  Epoch {epoch:2d}/{epochs:2d}: Loss = {avg_loss:.4f} | Val ROC-AUC = {val_auc:.4f} | Val BalAcc(0.50) = {val_bal:.4f}")

        # Checkpoint selection based on validation ROC-AUC
        if val_auc > best_val_auc:
            best_val_auc = val_auc
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            best_epoch = epoch

    train_time = time.time() - t0_train

    # Restore best checkpoint
    model.load_state_dict(best_weights)
    model.eval()

    # Final validation predictions
    with torch.no_grad():
        val_logits = model(x_val.to(device))
        val_probs = torch.sigmoid(val_logits).cpu().numpy()

    best_thresh, best_metrics = find_best_threshold(y_val.numpy(), val_probs)
    print(f"  Finished {name} in {train_time:.2f}s (Best Epoch: {best_epoch})")
    print(f"  Selected Validation Threshold: tau = {best_thresh:.4f}")
    print(f"  Validation Performance: BalAcc = {best_metrics['balanced_accuracy']*100:.2f}% | Recall = {best_metrics['recall']*100:.2f}% | Spec = {best_metrics['specificity']*100:.2f}% | F1 = {best_metrics['f1']:.4f} | ROC-AUC = {best_metrics['roc_auc']:.4f}")

    # Latency & size
    lat_ms = measure_latency_cpu_ms(model, x_val[0:1])
    buf = io.BytesIO()
    torch.save(best_weights, buf)
    size_bytes = len(buf.getvalue())

    # Save candidate weights to experiment dir
    cand_path = EXPERIMENT_DIR / f"{name.lower().replace(' ', '_')}.pt"
    torch.save(best_weights, cand_path)

    return {
        "name": name,
        "model": model,
        "best_epoch": best_epoch,
        "train_time_sec": round(train_time, 2),
        "val_auc_raw": best_val_auc,
        "val_probs": val_probs,
        "best_threshold": best_thresh,
        "val_metrics": best_metrics,
        "latency_ms": round(lat_ms, 4),
        "size_bytes": size_bytes,
        "artifact_path": str(cand_path),
        "state_dict": best_weights
    }


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================
def main():
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 80)
    print("CYBERGUARD — PHASE 8.2: VISUAL DEEPFAKE MODEL TRAINING & VALIDATION")
    print(f"Output Directory: {EXPERIMENT_DIR}")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Compute Device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")

    # 1. Load Training and Validation data ONLY
    print("\nLoading DFDC Shield 2026 Training and Validation tensors...")
    x_train = torch.load(DFDC_DIR / "X_train.pt", map_location="cpu", weights_only=True)
    y_train = torch.load(DFDC_DIR / "y_train.pt", map_location="cpu", weights_only=True)
    x_val = torch.load(DFDC_DIR / "X_val.pt", map_location="cpu", weights_only=True)
    y_val = torch.load(DFDC_DIR / "y_val.pt", map_location="cpu", weights_only=True)

    print(f"  X_train: {x_train.shape}, y_train: {y_train.shape} (9,346 manip, 1,112 genuine)")
    print(f"  X_val:   {x_val.shape}, y_val: {y_val.shape} (2,003 manip, 238 genuine)")
    print("  CONFIRMATION: Frozen X_test.pt / y_test.pt remain UNTOUCHED during training.")

    # --------------------------------------------------------------------------
    # Candidate A: AttentionPoolingVisualDetector with Corrected Class Weighting
    # --------------------------------------------------------------------------
    cand_a_model = AttentionPoolingVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3)
    cand_a_res = train_candidate(
        name="Candidate A (Balanced Attention Pooling)",
        model=cand_a_model,
        x_train=x_train, y_train=y_train,
        x_val=x_val, y_val=y_val,
        device=device,
        use_class_weights=True,
        epochs=8, batch_size=128, lr=1.5e-4
    )

    # --------------------------------------------------------------------------
    # Candidate B: Dual Temporal Fusion (Mean + Attention) Unweighted
    # --------------------------------------------------------------------------
    cand_b_model = DualTemporalFusionVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3)
    cand_b_res = train_candidate(
        name="Candidate B (Dual Temporal Fusion Unweighted)",
        model=cand_b_model,
        x_train=x_train, y_train=y_train,
        x_val=x_val, y_val=y_val,
        device=device,
        use_class_weights=False,
        epochs=8, batch_size=128, lr=1.5e-4
    )

    # --------------------------------------------------------------------------
    # Candidate C: Dual Temporal Fusion (Mean + Attention) with Corrected Class Weighting
    # --------------------------------------------------------------------------
    cand_c_model = DualTemporalFusionVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3)
    cand_c_res = train_candidate(
        name="Candidate C (Dual Temporal Fusion Balanced)",
        model=cand_c_model,
        x_train=x_train, y_train=y_train,
        x_val=x_val, y_val=y_val,
        device=device,
        use_class_weights=True,
        epochs=8, batch_size=128, lr=1.5e-4
    )

    # --------------------------------------------------------------------------
    # Candidate Comparison on VALIDATION DATA ONLY
    # --------------------------------------------------------------------------
    candidates = [cand_a_res, cand_b_res, cand_c_res]

    print("\n" + "=" * 80)
    print("VALIDATION COMPARISON TABLE (Frozen Test Set NOT Touched)")
    print("=" * 80)
    header = f"| {'Candidate':<40s} | {'Thresh':>6s} | {'Acc':>7s} | {'BalAcc':>7s} | {'Prec':>7s} | {'Recall':>7s} | {'Spec':>7s} | {'F1':>7s} | {'FPR':>7s} | {'ROC-AUC':>7s} |"
    print(header)
    print("|" + "-" * 42 + "|" + "-" * 8 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|")

    for c in candidates:
        m = c["val_metrics"]
        row = f"| {c['name']:<40s} | {c['best_threshold']:>6.4f} | {m['accuracy']*100:>6.2f}% | {m['balanced_accuracy']*100:>6.2f}% | {m['precision']*100:>6.2f}% | {m['recall']*100:>6.2f}% | {m['specificity']*100:>6.2f}% | {m['f1']:>7.4f} | {m['fpr']*100:>6.2f}% | {m['roc_auc']:>7.4f} |"
        print(row)

    # Selection logic based strictly on validation:
    # 1. Highest Balanced Accuracy subject to Specificity >= 80% (FPR <= 20%)
    # 2. Tie-breaker: Highest F1 Score and Recall
    best_candidate = max(candidates, key=lambda c: (c["val_metrics"]["balanced_accuracy"] + 0.1 * c["val_metrics"]["f1"]))
    print(f"\nWINNING CANDIDATE SELECTED FROM VALIDATION: {best_candidate['name']}")
    print(f"  Validation Balanced Accuracy: {best_candidate['val_metrics']['balanced_accuracy']*100:.2f}%")
    print(f"  Validation Recall:            {best_candidate['val_metrics']['recall']*100:.2f}%")
    print(f"  Validation Specificity:       {best_candidate['val_metrics']['specificity']*100:.2f}%")
    print(f"  Validation F1 Score:          {best_candidate['val_metrics']['f1']:.4f}")
    print(f"  Operating Threshold:          tau = {best_candidate['best_threshold']:.4f}")

    # --------------------------------------------------------------------------
    # FINAL UNTOUCHED TEST EVALUATION (EXACTLY ONCE)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("FINAL TEST GATE: EVALUATING WINNING CANDIDATE ONCE ON FROZEN TEST SET")
    print(f"Evaluating {best_candidate['name']} with frozen tau = {best_candidate['best_threshold']:.4f}")
    print("=" * 80)

    x_test = torch.load(DFDC_DIR / "X_test.pt", map_location="cpu", weights_only=True)
    y_test = torch.load(DFDC_DIR / "y_test.pt", map_location="cpu", weights_only=True)
    y_test_np = y_test.numpy()

    best_model = best_candidate["model"].to(device)
    best_model.load_state_dict(best_candidate["state_dict"])
    best_model.eval()

    with torch.no_grad():
        test_logits = best_model(x_test.to(device))
        test_probs = torch.sigmoid(test_logits).cpu().numpy()

    test_metrics = compute_metrics(y_test_np, test_probs, threshold=best_candidate["best_threshold"])
    test_lat_ms = measure_latency_cpu_ms(best_model, x_test[0:1])

    # Baseline production metrics for direct comparison
    baseline_metrics = {
        "model": "AttentionPoolingVisualDetector (Baseline v1.0.0)",
        "threshold": 0.6400,
        "accuracy": 0.6503,
        "balanced_accuracy": 0.7435,
        "precision": 0.9743,
        "recall": 0.6251,
        "specificity": 0.8619,
        "fpr": 0.1381,
        "f1": 0.7616,
        "roc_auc": 0.7966,
        "pr_auc": 0.9722,
        "confusion_matrix": {"tn": 206, "fp": 33, "fn": 751, "tp": 1252},
        "latency_ms": 0.5880,
        "size_bytes": 1647761
    }

    print("\n" + "-" * 80)
    print("FINAL TEST COMPARISON: CURRENT PRODUCTION (v1.0.0) vs PROMOTABLE CANDIDATE")
    print("-" * 80)
    print(f"{'Metric':<25s} | {'Current Production (v1.0.0)':<30s} | {'Phase 8 Selected Candidate':<30s} | {'Delta':<15s}")
    print("-" * 105)

    comp_rows = [
        ("Architecture", baseline_metrics["model"], best_candidate['name'], ""),
        ("Threshold (tau)", f"{baseline_metrics['threshold']:.4f}", f"{test_metrics['threshold']:.4f}", ""),
        ("Accuracy", f"{baseline_metrics['accuracy']*100:.2f}%", f"{test_metrics['accuracy']*100:.2f}%", f"{(test_metrics['accuracy'] - baseline_metrics['accuracy'])*100:+.2f}%"),
        ("Balanced Accuracy", f"{baseline_metrics['balanced_accuracy']*100:.2f}%", f"{test_metrics['balanced_accuracy']*100:.2f}%", f"{(test_metrics['balanced_accuracy'] - baseline_metrics['balanced_accuracy'])*100:+.2f}%"),
        ("Recall", f"{baseline_metrics['recall']*100:.2f}%", f"{test_metrics['recall']*100:.2f}%", f"{(test_metrics['recall'] - baseline_metrics['recall'])*100:+.2f}%"),
        ("Precision", f"{baseline_metrics['precision']*100:.2f}%", f"{test_metrics['precision']*100:.2f}%", f"{(test_metrics['precision'] - baseline_metrics['precision'])*100:+.2f}%"),
        ("Specificity", f"{baseline_metrics['specificity']*100:.2f}%", f"{test_metrics['specificity']*100:.2f}%", f"{(test_metrics['specificity'] - baseline_metrics['specificity'])*100:+.2f}%"),
        ("F1 Score", f"{baseline_metrics['f1']:.4f}", f"{test_metrics['f1']:.4f}", f"{(test_metrics['f1'] - baseline_metrics['f1']):+.4f}"),
        ("FPR", f"{baseline_metrics['fpr']*100:.2f}%", f"{test_metrics['fpr']*100:.2f}%", f"{(test_metrics['fpr'] - baseline_metrics['fpr'])*100:+.2f}%"),
        ("ROC-AUC", f"{baseline_metrics['roc_auc']:.4f}", f"{test_metrics['roc_auc']:.4f}", f"{(test_metrics['roc_auc'] - baseline_metrics['roc_auc']):+.4f}"),
        ("PR-AUC", f"{baseline_metrics['pr_auc']:.4f}", f"{test_metrics['pr_auc']:.4f}", f"{(test_metrics['pr_auc'] - baseline_metrics['pr_auc']):+.4f}"),
        ("False Negatives", f"{baseline_metrics['confusion_matrix']['fn']:,}", f"{test_metrics['confusion_matrix']['fn']:,}", f"{test_metrics['confusion_matrix']['fn'] - baseline_metrics['confusion_matrix']['fn']:+,d}"),
        ("Inference Latency", f"{baseline_metrics['latency_ms']:.3f} ms", f"{test_lat_ms:.3f} ms", f"{test_lat_ms - baseline_metrics['latency_ms']:+.3f} ms"),
    ]

    for label, base_val, cand_val, delta in comp_rows:
        print(f"{label:<25s} | {base_val:<30s} | {cand_val:<30s} | {delta:<15s}")

    print("-" * 105)
    print(f"Confusion Matrix: TN={test_metrics['confusion_matrix']['tn']}, FP={test_metrics['confusion_matrix']['fp']}, FN={test_metrics['confusion_matrix']['fn']}, TP={test_metrics['confusion_matrix']['tp']}")

    # Check candidate artifact SHA256
    cand_sha256 = hashlib.sha256(Path(best_candidate["artifact_path"]).read_bytes()).hexdigest()
    print(f"Candidate Artifact Path:   {best_candidate['artifact_path']}")
    print(f"Candidate SHA-256 Checksum: {cand_sha256}")

    # Output experiment report JSON
    experiment_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "PHASE 8.2 — VISUAL MODEL CANDIDATE TRAINING & VALIDATION",
        "device": f"{device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})",
        "pytorch_version": torch.__version__,
        "candidates_evaluated": [
            {
                "name": c["name"],
                "best_epoch": c["best_epoch"],
                "train_time_sec": c["train_time_sec"],
                "selected_threshold": c["best_threshold"],
                "val_metrics": c["val_metrics"],
                "latency_ms": c["latency_ms"],
                "size_bytes": c["size_bytes"]
            }
            for c in candidates
        ],
        "winning_candidate": {
            "name": best_candidate["name"],
            "selected_threshold": best_candidate["best_threshold"],
            "val_metrics": best_candidate["val_metrics"],
            "final_test_metrics": test_metrics,
            "latency_ms": round(test_lat_ms, 4),
            "size_bytes": best_candidate["size_bytes"],
            "artifact_path": best_candidate["artifact_path"],
            "sha256": cand_sha256
        },
        "baseline_metrics": baseline_metrics
    }

    report_path = EXPERIMENT_DIR / "visual_candidate_evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(experiment_report, f, indent=2)

    print(f"\nExperiment report saved to: {report_path}")


if __name__ == "__main__":
    main()
