import os
import sys
import time
import math
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score,
    recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

# Determinism
SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)
random.seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

# Load Train and Val tensors
DATA_DIR = 'datasets/DFDC/shield_2026_final_data'
X_train = torch.load(os.path.join(DATA_DIR, 'X_train.pt'), map_location='cpu') # [10458, 20, 1024]
y_train = torch.load(os.path.join(DATA_DIR, 'y_train.pt'), map_location='cpu').float() # [10458]
X_val = torch.load(os.path.join(DATA_DIR, 'X_val.pt'), map_location='cpu') # [2241, 20, 1024]
y_val = torch.load(os.path.join(DATA_DIR, 'y_val.pt'), map_location='cpu').numpy()

print(f"Train data: {X_train.shape}, pos: {int(y_train.sum().item())}/{len(y_train)}")
print(f"Val data: {X_val.shape}, pos: {int(y_val.sum())}/{len(y_val)}")

# Focal Loss implementation
class BinaryFocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2.0, pos_weight=None):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.pos_weight = pos_weight

    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction='none', pos_weight=self.pos_weight)
        probs = torch.sigmoid(logits)
        p_t = targets * probs + (1 - targets) * (1 - probs)
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        focal_weight = alpha_t * ((1 - p_t) ** self.gamma)
        return (focal_weight * bce).mean()

# Architectures
# Candidate 1: Enhanced Attention Pooling with LayerNorm & Residual
class EnhancedAttentionPooling(nn.Module):
    def __init__(self, in_features=1024, hidden_dim=256, dropout=0.3):
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

    def forward(self, x):
        h = self.proj(x) # [B, T, hidden_dim]
        attn_scores = self.attention(h) # [B, T, 1]
        attn_weights = torch.softmax(attn_scores, dim=1)
        pooled = (h * attn_weights).sum(dim=1)
        return self.classifier(pooled).squeeze(-1)

# Candidate 2: Tri-Pool Temporal Fusion (Mean + Max + Attention)
class TriPoolFusionVisualDetector(nn.Module):
    def __init__(self, in_features=1024, hidden_dim=256, dropout=0.3):
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
        # 3 * hidden_dim
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

    def forward(self, x):
        h = self.proj(x) # [B, T, hidden_dim]
        h_mean = h.mean(dim=1)
        h_max, _ = h.max(dim=1)
        attn_weights = torch.softmax(self.attention(h), dim=1)
        h_attn = (h * attn_weights).sum(dim=1)
        fused = torch.cat([h_mean, h_max, h_attn], dim=-1)
        return self.classifier(fused).squeeze(-1)

# Candidate 3: Temporal Delta Residual Network (models frame-to-frame manipulation jumps)
class TemporalDeltaVisualDetector(nn.Module):
    def __init__(self, in_features=1024, hidden_dim=256, dropout=0.3):
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
        total_dim = hidden_dim + (hidden_dim // 2) * 2 # frame_attn + delta_mean + delta_max
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

    def forward(self, x):
        # x: [B, 20, 1024]
        h_frames = self.frame_proj(x) # [B, 20, hidden_dim]
        attn_weights = torch.softmax(self.attention(h_frames), dim=1)
        pooled_frames = (h_frames * attn_weights).sum(dim=1)

        # Delta features: [B, 19, 1024]
        deltas = x[:, 1:, :] - x[:, :-1, :]
        h_deltas = self.delta_proj(deltas) # [B, 19, hidden_dim // 2]
        delta_mean = h_deltas.mean(dim=1)
        delta_max, _ = h_deltas.max(dim=1)

        fused = torch.cat([pooled_frames, delta_mean, delta_max], dim=-1)
        return self.classifier(fused).squeeze(-1)

# Candidate 4: Temporal Transformer / Self-Attention Network
class TransformerTemporalVisualDetector(nn.Module):
    def __init__(self, in_features=1024, hidden_dim=256, nhead=4, num_layers=2, dropout=0.3):
        super().__init__()
        self.in_proj = nn.Linear(in_features, hidden_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=nhead, dim_feedforward=hidden_dim * 2,
            dropout=dropout, activation='gelu', batch_first=True
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

    def forward(self, x):
        h = self.in_proj(x) # [B, T, hidden_dim]
        h_trans = self.transformer(h) # [B, T, hidden_dim]
        h_mean = h_trans.mean(dim=1)
        attn_weights = torch.softmax(self.attention_pool(h_trans), dim=1)
        h_attn = (h_trans * attn_weights).sum(dim=1)
        fused = torch.cat([h_mean, h_attn], dim=-1)
        return self.classifier(fused).squeeze(-1)

def evaluate_model(model, X_v, y_v):
    model.eval()
    with torch.no_grad():
        X_gpu = X_v.to(device)
        logits = model(X_gpu).cpu()
        probs = torch.sigmoid(logits).numpy()

    roc = roc_auc_score(y_v, probs)
    pr = average_precision_score(y_v, probs)

    best_thresh = 0.5
    best_bal = 0.0
    best_rec = 0.0
    best_spec = 0.0
    best_f1 = 0.0
    best_fpr = 1.0

    for tau in np.linspace(0.1, 0.9, 81):
        preds = (probs >= tau).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_v, preds, labels=[0, 1]).ravel()
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0
        bal = (rec + spec) / 2
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0
        if spec >= 0.80 and bal > best_bal:
            best_bal = bal
            best_thresh = tau
            best_rec = rec
            best_spec = spec
            best_f1 = f1
            best_fpr = fp / (tn + fp)

    return {
        'roc_auc': roc, 'pr_auc': pr, 'best_thresh': best_thresh,
        'bal_acc': best_bal, 'rec': best_rec, 'spec': best_spec, 'fpr': best_fpr, 'f1': best_f1
    }

def train_candidate(name, model, loss_type='bce', epochs=12, batch_size=128, lr=1e-3, weight_decay=1e-4):
    print(f"\n==========================================")
    print(f"Training: {name} (loss={loss_type}, epochs={epochs}, lr={lr})")
    print(f"==========================================")
    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # Class weights for BCE
    pos_weight = torch.tensor([1112.0 / 9346.0]).to(device) # ~0.119
    if loss_type == 'focal':
        criterion = BinaryFocalLoss(alpha=0.5, gamma=2.0)
    elif loss_type == 'weighted_bce':
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    else:
        criterion = nn.BCEWithLogitsLoss()

    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, pin_memory=True)

    best_val_roc = 0.0
    best_metrics = None

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        start_t = time.time()
        for bx, by in loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item() * len(by)
        scheduler.step()
        train_loss = total_loss / len(X_train)

        # Eval on Val
        metrics = evaluate_model(model, X_val, y_val)
        dur = time.time() - start_t
        print(f"Epoch {epoch:02d} [{dur:.1f}s]: loss={train_loss:.4f} | Val ROC={metrics['roc_auc']:.4f}, BalAcc={metrics['bal_acc']*100:.2f}%, Rec={metrics['rec']*100:.2f}%, Spec={metrics['spec']*100:.2f}% (tau={metrics['best_thresh']:.2f})")

        if metrics['roc_auc'] > best_val_roc:
            best_val_roc = metrics['roc_auc']
            best_metrics = metrics

    print(f"--> Best Val for {name}: ROC={best_metrics['roc_auc']:.4f}, BalAcc={best_metrics['bal_acc']*100:.2f}%, Rec={best_metrics['rec']*100:.2f}%, Spec={best_metrics['spec']*100:.2f}%, F1={best_metrics['f1']:.4f} at tau={best_metrics['best_thresh']:.2f}")
    return best_metrics

if __name__ == '__main__':
    results = {}
    # 1. Enhanced Attention Pooling with Focal Loss
    results['Cand1_EnhancedAttn_Focal'] = train_candidate(
        'Cand1_EnhancedAttn_Focal',
        EnhancedAttentionPooling(in_features=1024, hidden_dim=256, dropout=0.3),
        loss_type='focal', epochs=10, lr=1e-3
    )

    # 2. TriPool with Focal Loss
    results['Cand2_TriPool_Focal'] = train_candidate(
        'Cand2_TriPool_Focal',
        TriPoolFusionVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3),
        loss_type='focal', epochs=10, lr=1e-3
    )

    # 3. TemporalDelta with Focal Loss
    results['Cand3_TemporalDelta_Focal'] = train_candidate(
        'Cand3_TemporalDelta_Focal',
        TemporalDeltaVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3),
        loss_type='focal', epochs=10, lr=1e-3
    )

    # 4. Temporal Transformer with Focal Loss
    results['Cand4_Transformer_Focal'] = train_candidate(
        'Cand4_Transformer_Focal',
        TransformerTemporalVisualDetector(in_features=1024, hidden_dim=256, nhead=4, num_layers=2, dropout=0.3),
        loss_type='focal', epochs=10, lr=5e-4
    )

    # 5. TriPool with Weighted BCE
    results['Cand5_TriPool_WeightedBCE'] = train_candidate(
        'Cand5_TriPool_WeightedBCE',
        TriPoolFusionVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3),
        loss_type='weighted_bce', epochs=10, lr=1e-3
    )
