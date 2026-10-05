#!/usr/bin/env python3
"""
CYBERGUARD Phase 9: Visual Deepfake V2 Candidate Training & Validation.
Trains and compares 5 controlled visual deepfake candidates:
- Candidate A: Enhanced Attention Pooling with Balanced Focal Loss
- Candidate B: Tri-Pool Temporal Fusion (Mean + Max + Attention) with Focal Loss
- Candidate C: Temporal Delta Residual Network (Frames + Frame Differentiations) with Focal Loss
- Candidate D: Spatio-Temporal Hybrid (Tri-Pool + Temporal Deltas) with Balanced BCE
- Candidate E: Temporal Transformer Self-Attention Network with Focal Loss

Strict isolation:
- Train: 10,458 samples (X_train.pt, y_train.pt)
- Val: 2,241 samples (X_val.pt, y_val.pt)
- Frozen Test: 2,242 samples (quarantined and untouched until final gate)
"""

import os
import sys
import time
import math
import random
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score,
    recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
EXP_DIR = ML_SERVICE_DIR / "experiments" / "deepfake_v2_20261004_223500"
DATA_DIR = REPO_ROOT / "datasets" / "DFDC" / "shield_2026_final_data"

SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)
random.seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ==============================================================================
# LOSS FUNCTIONS
# ==============================================================================
class BinaryFocalLoss(nn.Module):
    def __init__(self, alpha: float = 0.5, gamma: float = 2.0, pos_weight: torch.Tensor = None):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.pos_weight = pos_weight

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none", pos_weight=self.pos_weight)
        probs = torch.sigmoid(logits)
        p_t = targets * probs + (1 - targets) * (1 - probs)
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        focal_weight = alpha_t * ((1 - p_t) ** self.gamma)
        return (focal_weight * bce).mean()


# ==============================================================================
# CANDIDATE ARCHITECTURES
# ==============================================================================
class EnhancedAttentionPooling(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.LayerNorm(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        h = self.proj(x)
        attn_scores = self.attention(h)
        attn_weights = torch.softmax(attn_scores, dim=1)
        pooled = (h * attn_weights).sum(dim=1)
        return self.classifier(pooled).squeeze(-1)


class TriPoolFusionVisualDetector(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 3, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        h = self.proj(x)
        h_mean = h.mean(dim=1)
        h_max, _ = h.max(dim=1)
        attn_weights = torch.softmax(self.attention(h), dim=1)
        h_attn = (h * attn_weights).sum(dim=1)
        fused = torch.cat([h_mean, h_max, h_attn], dim=-1)
        return self.classifier(fused).squeeze(-1)


class TemporalDeltaVisualDetector(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.frame_proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.delta_proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        total_dim = hidden_dim + (hidden_dim // 2) * 2
        self.classifier = nn.Sequential(
            nn.Linear(total_dim, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        h_frames = self.frame_proj(x)
        attn_weights = torch.softmax(self.attention(h_frames), dim=1)
        pooled_frames = (h_frames * attn_weights).sum(dim=1)

        if x.size(1) > 1:
            deltas = x[:, 1:, :] - x[:, :-1, :]
            h_deltas = self.delta_proj(deltas)
            delta_mean = h_deltas.mean(dim=1)
            delta_max, _ = h_deltas.max(dim=1)
        else:
            delta_mean = torch.zeros(x.size(0), self.delta_proj[0].out_features, device=x.device)
            delta_max = torch.zeros(x.size(0), self.delta_proj[0].out_features, device=x.device)

        fused = torch.cat([pooled_frames, delta_mean, delta_max], dim=-1)
        return self.classifier(fused).squeeze(-1)


class HybridSpatioTemporalVisualDetector(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.frame_proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.delta_proj = nn.Sequential(
            nn.Linear(in_features, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        # Tri-Pool (3 * hidden_dim) + Deltas (2 * hidden_dim // 2) = 4 * hidden_dim
        total_dim = hidden_dim * 3 + (hidden_dim // 2) * 2
        self.classifier = nn.Sequential(
            nn.Linear(total_dim, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        h_frames = self.frame_proj(x)
        h_mean = h_frames.mean(dim=1)
        h_max, _ = h_frames.max(dim=1)
        attn_weights = torch.softmax(self.attention(h_frames), dim=1)
        h_attn = (h_frames * attn_weights).sum(dim=1)

        if x.size(1) > 1:
            deltas = x[:, 1:, :] - x[:, :-1, :]
            h_deltas = self.delta_proj(deltas)
            delta_mean = h_deltas.mean(dim=1)
            delta_max, _ = h_deltas.max(dim=1)
        else:
            delta_mean = torch.zeros(x.size(0), self.delta_proj[0].out_features, device=x.device)
            delta_max = torch.zeros(x.size(0), self.delta_proj[0].out_features, device=x.device)

        fused = torch.cat([h_mean, h_max, h_attn, delta_mean, delta_max], dim=-1)
        return self.classifier(fused).squeeze(-1)


class TransformerTemporalVisualDetector(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, nhead: int = 4, num_layers: int = 2, dropout: float = 0.3):
        super().__init__()
        self.in_proj = nn.Linear(in_features, hidden_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=nhead, dim_feedforward=hidden_dim * 2,
            dropout=dropout, activation="gelu", batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.attention_pool = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 128),
            nn.LayerNorm(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        h = self.in_proj(x)
        h_trans = self.transformer(h)
        h_mean = h_trans.mean(dim=1)
        attn_weights = torch.softmax(self.attention_pool(h_trans), dim=1)
        h_attn = (h_trans * attn_weights).sum(dim=1)
        fused = torch.cat([h_mean, h_attn], dim=-1)
        return self.classifier(fused).squeeze(-1)


# ==============================================================================
# EVALUATION & THRESHOLD SELECTION
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


def find_best_threshold(y_val: np.ndarray, val_probs: np.ndarray, min_spec: float = 0.85) -> Tuple[float, Dict[str, Any]]:
    best_thresh = 0.50
    best_score = -1.0
    best_metrics = None

    for t in np.linspace(0.10, 0.90, 81):
        m = compute_metrics(y_val, val_probs, threshold=float(t))
        if m["specificity"] >= min_spec:
            score = m["balanced_accuracy"] + 0.1 * m["recall"]
            if score > best_score:
                best_score = score
                best_thresh = float(t)
                best_metrics = m

    if best_metrics is None:
        for t in np.linspace(0.10, 0.90, 81):
            m = compute_metrics(y_val, val_probs, threshold=float(t))
            if m["specificity"] >= 0.80:
                score = m["balanced_accuracy"] + 0.1 * m["recall"]
                if score > best_score:
                    best_score = score
                    best_thresh = float(t)
                    best_metrics = m

    return best_thresh, best_metrics


def main():
    print("=== CYBERGUARD Phase 9 Visual V2 Candidate Suite ===")
    X_train = torch.load(DATA_DIR / "X_train.pt", map_location="cpu")
    y_train = torch.load(DATA_DIR / "y_train.pt", map_location="cpu").float()
    X_val = torch.load(DATA_DIR / "X_val.pt", map_location="cpu")
    y_val = torch.load(DATA_DIR / "y_val.pt", map_location="cpu").numpy()

    print(f"Train: {X_train.shape}, pos: {int(y_train.sum())}/{len(y_train)}")
    print(f"Val: {X_val.shape}, pos: {int(y_val.sum())}/{len(y_val)}")

    candidates_def = [
        ("Candidate A (Enhanced Attention Pooling Focal)", EnhancedAttentionPooling(in_features=1024, hidden_dim=256, dropout=0.35), "focal", 1e-3, 6),
        ("Candidate B (Tri-Pool Temporal Fusion Focal)", TriPoolFusionVisualDetector(in_features=1024, hidden_dim=256, dropout=0.35), "focal", 1e-3, 6),
        ("Candidate C (Temporal Delta Residual Focal)", TemporalDeltaVisualDetector(in_features=1024, hidden_dim=256, dropout=0.35), "focal", 1e-3, 6),
        ("Candidate D (Hybrid Spatio-Temporal Balanced BCE)", HybridSpatioTemporalVisualDetector(in_features=1024, hidden_dim=256, dropout=0.35), "weighted_bce", 1e-3, 6),
        ("Candidate E (Temporal Transformer Self-Attention Focal)", TransformerTemporalVisualDetector(in_features=1024, hidden_dim=256, nhead=4, num_layers=2, dropout=0.35), "focal", 5e-4, 6),
    ]

    results = []
    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=128, shuffle=True, pin_memory=True)

    pos_weight = torch.tensor([1112.0 / 9346.0]).to(device)

    for name, model, loss_type, lr, epochs in candidates_def:
        print(f"\n==========================================")
        print(f"Training: {name} (loss={loss_type}, epochs={epochs}, lr={lr})")
        print(f"==========================================")
        model = model.to(device)
        optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-3)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        if loss_type == "focal":
            criterion = BinaryFocalLoss(alpha=0.5, gamma=2.0)
        elif loss_type == "weighted_bce":
            criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        else:
            criterion = nn.BCEWithLogitsLoss()

        best_val_roc = 0.0
        best_state = None
        best_metrics = None
        best_tau = 0.50
        train_start = time.time()

        for epoch in range(1, epochs + 1):
            model.train()
            total_loss = 0.0
            for bx, by in loader:
                bx, by = bx.to(device), by.to(device)
                # Training-only augmentation: subtle Gaussian noise
                noise = torch.randn_like(bx) * 0.015
                bx_aug = bx + noise

                optimizer.zero_grad()
                logits = model(bx_aug)
                loss = criterion(logits, by)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                total_loss += loss.item() * len(by)
            scheduler.step()

            # Eval on Val
            model.eval()
            with torch.no_grad():
                val_logits = model(X_val.to(device)).cpu()
                val_probs = torch.sigmoid(val_logits).numpy()

            roc = roc_auc_score(y_val, val_probs)
            tau, cur_metrics = find_best_threshold(y_val, val_probs, min_spec=0.85)
            print(f"Epoch {epoch:02d}: loss={total_loss/len(X_train):.4f} | Val ROC={roc:.4f}, BalAcc={cur_metrics['balanced_accuracy']*100:.2f}%, Rec={cur_metrics['recall']*100:.2f}%, Spec={cur_metrics['specificity']*100:.2f}% (tau={tau:.2f})")

            if roc > best_val_roc:
                best_val_roc = roc
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                best_metrics = cur_metrics
                best_tau = tau

        total_train_sec = time.time() - train_start

        # Load best weights
        model.load_state_dict(best_state)
        model.eval()

        # Latency benchmark
        single_sample = X_val[[0]].to(device)
        latencies = []
        with torch.no_grad():
            for _ in range(100):
                t0 = time.perf_counter()
                _ = model(single_sample)
                latencies.append((time.perf_counter() - t0) * 1000.0)
        p50_lat = float(np.median(latencies))

        # Save candidate artifact
        safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "").replace("-", "_")
        art_path = EXP_DIR / f"{safe_name}.pt"
        torch.save(best_state, art_path)
        art_size = art_path.stat().st_size
        sha = hashlib.sha256(art_path.read_bytes()).hexdigest()

        res = {
            "name": name,
            "architecture": model.__class__.__name__,
            "train_time_sec": round(total_train_sec, 2),
            "selected_threshold": best_tau,
            "val_metrics": best_metrics,
            "latency_ms": round(p50_lat, 4),
            "size_bytes": art_size,
            "artifact_path": str(art_path),
            "sha256": sha
        }
        results.append(res)
        print(f"\n--> Best Validation for [{name}]:")
        print(f"    Val ROC-AUC: {best_metrics['roc_auc']:.4f}, PR-AUC: {best_metrics['pr_auc']:.4f}")
        print(f"    Threshold: {best_tau:.4f}")
        print(f"    BalAcc: {best_metrics['balanced_accuracy']*100:.2f}%, Rec: {best_metrics['recall']*100:.2f}%, Spec: {best_metrics['specificity']*100:.2f}%, FPR: {best_metrics['fpr']*100:.2f}%, F1: {best_metrics['f1']:.4f}")
        print(f"    Confusion Matrix: {best_metrics['confusion_matrix']}")
        print(f"    Latency: {p50_lat:.3f} ms, Size: {art_size/(1024*1024):.2f} MB, SHA: {sha[:12]}...")

    # Write evaluation manifest
    out_file = EXP_DIR / "visual_candidate_comparison.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nVisual Candidate Comparison written to {out_file}")

if __name__ == "__main__":
    main()
