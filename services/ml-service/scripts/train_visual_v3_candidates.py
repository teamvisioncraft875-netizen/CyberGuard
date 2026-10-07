import io
import os
import sys
import time
import json
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

REPO_ROOT = Path("d:/cyberguard project  work su/CyberGuard")
DFDC_DIR = REPO_ROOT / "datasets" / "DFDC" / "shield_2026_final_data"
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
EXPERIMENT_DIR = ML_SERVICE_DIR / "experiments" / f"visual_v3_candidates_{time.strftime('%Y%m%d_%H%M%S')}"
EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)


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


def measure_latency_cpu_ms(model, sample_input, iterations: int = 500) -> float:
    model.eval()
    with torch.no_grad():
        for _ in range(30):
            model(sample_input)
        t0 = time.perf_counter()
        for _ in range(iterations):
            model(sample_input)
        t1 = time.perf_counter()
    return ((t1 - t0) / iterations) * 1000.0


# ==============================================================================
# Candidate A: Robust Temporal Statistical Pooling
# Mean + Std + Max + Attention
# ==============================================================================
class CandidateA_StatisticalPooling(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.attention = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )
        fused_dim = in_features * 4  # mean, std, max, attn
        self.proj = nn.Sequential(
            nn.Linear(fused_dim, 512),
            nn.LayerNorm(512),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        self.classifier = nn.Sequential(
            nn.Linear(512, hidden_dim),
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
        x_mean = x.mean(dim=1)
        x_std = x.std(dim=1) if x.shape[1] > 1 else torch.zeros_like(x_mean)
        x_max, _ = x.max(dim=1)

        attn_weights = torch.softmax(self.attention(x), dim=1)
        x_attn = (x * attn_weights).sum(dim=1)

        fused = torch.cat([x_mean, x_std, x_max, x_attn], dim=-1)
        feat = self.proj(fused)
        return self.classifier(feat).squeeze(-1)


# ==============================================================================
# Candidate B: Mean + Attention Fusion with Class-Balanced Regularization
# ==============================================================================
class CandidateB_BalancedFusion(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.35):
        super().__init__()
        self.attention = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )
        fused_dim = in_features * 2  # mean, attn
        self.classifier = nn.Sequential(
            nn.LayerNorm(fused_dim),
            nn.Linear(fused_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout * 0.7),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x_mean = x.mean(dim=1)
        attn_weights = torch.softmax(self.attention(x), dim=1)
        x_attn = (x * attn_weights).sum(dim=1)
        fused = torch.cat([x_mean, x_attn], dim=-1)
        return self.classifier(fused).squeeze(-1)


# ==============================================================================
# Candidate C: Temporal Conv + Attention with Embedding Noise Augmentation
# ==============================================================================
class CandidateC_TemporalConvAttention(nn.Module):
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        # 1D conv over temporal dimension (transposed: [B, C, T])
        self.temporal_conv = nn.Sequential(
            nn.Conv1d(in_features, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5)
        )
        self.attention = nn.Sequential(
            nn.Linear(256, 64),
            nn.Tanh(),
            nn.Linear(64, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(256 * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        # x is [B, T, C] -> transpose to [B, C, T]
        x_t = x.transpose(1, 2)
        conv_out = self.temporal_conv(x_t).transpose(1, 2)  # [B, T, 256]

        mean_pool = conv_out.mean(dim=1)
        attn_w = torch.softmax(self.attention(conv_out), dim=1)
        attn_pool = (conv_out * attn_w).sum(dim=1)

        fused = torch.cat([mean_pool, attn_pool], dim=-1)
        return self.classifier(fused).squeeze(-1)


def train_candidate(name, model, x_train, y_train, x_val, y_val, pos_weight_val, lr=1e-4, weight_decay=1e-3, epochs=10, noise_std=0.0):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    dataset = TensorDataset(x_train, y_train.float())
    loader = DataLoader(dataset, batch_size=128, shuffle=True)

    pos_w = torch.tensor([pos_weight_val]).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)

    y_val_np = y_val.numpy()
    best_bal_acc = 0.0
    best_weights = None
    t0 = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        for bx, by in loader:
            bx, by = bx.to(device), by.to(device)
            if noise_std > 0.0 and model.training:
                noise = torch.randn_like(bx) * noise_std
                bx = bx + noise
            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            v_logits = model(x_val.to(device))
            v_probs = torch.sigmoid(v_logits).cpu().numpy()

        # Check validation balanced accuracy across thresholds [0.3, 0.7]
        for t in np.linspace(0.30, 0.70, 21):
            m = compute_metrics(y_val_np, v_probs, threshold=float(t))
            if m["balanced_accuracy"] > best_bal_acc:
                best_bal_acc = m["balanced_accuracy"]
                best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    train_time = time.time() - t0
    model.load_state_dict(best_weights)
    model.eval()
    model = model.to("cpu")

    with torch.no_grad():
        final_val_probs = torch.sigmoid(model(x_val)).numpy()

    # Find optimal threshold on validation maximizing balanced accuracy while keeping FPR <= 0.20
    best_thresh = 0.50
    best_score = -1.0
    selected_metrics = None

    for t in np.linspace(0.20, 0.80, 61):
        m = compute_metrics(y_val_np, final_val_probs, threshold=float(t))
        # Prioritize balanced accuracy and recall while keeping FPR <= 0.20
        if m["fpr"] <= 0.20 and m["balanced_accuracy"] > best_score:
            best_score = m["balanced_accuracy"]
            best_thresh = float(t)
            selected_metrics = m

    if selected_metrics is None:
        best_thresh = 0.50
        selected_metrics = compute_metrics(y_val_np, final_val_probs, threshold=0.50)

    # Measure latency
    sample_seq = torch.randn(1, 20, 1024)
    latency_ms = measure_latency_cpu_ms(model, sample_seq)

    # Param count & size
    param_count = sum(p.numel() for p in model.parameters())
    buf = io.BytesIO()
    torch.save(model.state_dict(), buf)
    size_bytes = len(buf.getvalue())

    # Save artifact in experiment dir
    save_path = EXPERIMENT_DIR / f"{name.lower().replace(' ', '_')}.pt"
    torch.save(model.state_dict(), save_path)
    sha256 = hashlib.sha256(save_path.read_bytes()).hexdigest()

    return {
        "name": name,
        "train_time_sec": round(train_time, 2),
        "param_count": param_count,
        "size_bytes": size_bytes,
        "latency_ms": round(latency_ms, 4),
        "selected_threshold": round(best_thresh, 4),
        "val_metrics": selected_metrics,
        "artifact_path": str(save_path),
        "sha256": sha256,
        "model": model,
        "final_val_probs": final_val_probs
    }


def run_experiment():
    print(f"Loading datasets from {DFDC_DIR}...")
    x_train = torch.load(DFDC_DIR / "X_train.pt", map_location="cpu", weights_only=True)
    y_train = torch.load(DFDC_DIR / "y_train.pt", map_location="cpu", weights_only=True)
    x_val = torch.load(DFDC_DIR / "X_val.pt", map_location="cpu", weights_only=True)
    y_val = torch.load(DFDC_DIR / "y_val.pt", map_location="cpu", weights_only=True)

    n_neg = float((y_train == 0).sum().item())
    n_pos = float((y_train == 1).sum().item())
    print(f"Train genuine: {int(n_neg)}, manipulated: {int(n_pos)}")

    # Weighting options:
    # 1.0 (unweighted BCE)
    # n_neg / n_pos (~0.119 - heavily downweights positive)
    # Balanced effective weighting: sqrt(n_neg / n_pos) (~0.345) or 1.0
    # Let's test balanced loss weight ~0.5 - 1.0 so positive recall is not sacrificed
    pos_w_balanced = 0.50

    print("\n--- Training Candidate A: Statistical Pooling (Mean, Std, Max, Attention) ---")
    torch.manual_seed(42)
    cand_a = train_candidate(
        "Candidate A",
        CandidateA_StatisticalPooling(in_features=1024, hidden_dim=256, dropout=0.3),
        x_train, y_train, x_val, y_val,
        pos_weight_val=pos_w_balanced,
        lr=1e-4, weight_decay=1e-3, epochs=10
    )
    print(f"  Candidate A Val: Rec={cand_a['val_metrics']['recall']}, Spec={cand_a['val_metrics']['specificity']}, BalAcc={cand_a['val_metrics']['balanced_accuracy']}, F1={cand_a['val_metrics']['f1']}, FPR={cand_a['val_metrics']['fpr']}, AUC={cand_a['val_metrics']['roc_auc']}")

    print("\n--- Training Candidate B: Balanced Mean + Attention Fusion ---")
    torch.manual_seed(42)
    cand_b = train_candidate(
        "Candidate B",
        CandidateB_BalancedFusion(in_features=1024, hidden_dim=256, dropout=0.35),
        x_train, y_train, x_val, y_val,
        pos_weight_val=0.40,
        lr=1e-4, weight_decay=2e-3, epochs=10
    )
    print(f"  Candidate B Val: Rec={cand_b['val_metrics']['recall']}, Spec={cand_b['val_metrics']['specificity']}, BalAcc={cand_b['val_metrics']['balanced_accuracy']}, F1={cand_b['val_metrics']['f1']}, FPR={cand_b['val_metrics']['fpr']}, AUC={cand_b['val_metrics']['roc_auc']}")

    print("\n--- Training Candidate C: Temporal Conv + Attention with Noise Augmentation ---")
    torch.manual_seed(42)
    cand_c = train_candidate(
        "Candidate C",
        CandidateC_TemporalConvAttention(in_features=1024, hidden_dim=256, dropout=0.3),
        x_train, y_train, x_val, y_val,
        pos_weight_val=0.50,
        lr=1e-4, weight_decay=1e-3, epochs=10, noise_std=0.01
    )
    print(f"  Candidate C Val: Rec={cand_c['val_metrics']['recall']}, Spec={cand_c['val_metrics']['specificity']}, BalAcc={cand_c['val_metrics']['balanced_accuracy']}, F1={cand_c['val_metrics']['f1']}, FPR={cand_c['val_metrics']['fpr']}, AUC={cand_c['val_metrics']['roc_auc']}")

    # Save summary report (without model objects)
    summary = []
    for c in [cand_a, cand_b, cand_c]:
        summary.append({
            "name": c["name"],
            "train_time_sec": c["train_time_sec"],
            "param_count": c["param_count"],
            "size_bytes": c["size_bytes"],
            "latency_ms": c["latency_ms"],
            "selected_threshold": c["selected_threshold"],
            "val_metrics": c["val_metrics"],
            "artifact_path": c["artifact_path"],
            "sha256": c["sha256"],
        })

    with open(EXPERIMENT_DIR / "candidate_comparison.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nExperiment complete. Saved report to {EXPERIMENT_DIR / 'candidate_comparison.json'}")

if __name__ == "__main__":
    run_experiment()
