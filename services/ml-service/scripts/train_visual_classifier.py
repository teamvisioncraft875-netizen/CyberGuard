"""
CYBERGUARD Supervised Visual Deepfake Detection Model Training and Evaluation Pipeline.
Trains visual deepfake classifier on the DFDC/Shield 2026 dataset (14,941 samples, 20 frames x 1024-dim features),
performs model selection and threshold calibration strictly on the validation partition,
freezes the selected model, evaluates exactly once on the untouched test partition,
and serializes model artifacts, metadata, and schemas.
"""

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Tuple

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader


class AttentionPoolingVisualDetector(nn.Module):
    """
    Temporal Attention-Pooled Neural Network for visual deepfake detection.
    Processes sequences of frame embeddings (e.g. 20 x 1024 dims from CLIP ViT-H/14),
    learns frame-level manipulation attention weights, and predicts manipulation probability.
    Natively supports single-frame images [batch, 1, 1024] and pooled embeddings [batch, 1024].
    """
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.in_features = in_features
        self.hidden_dim = hidden_dim
        self.attention = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        attn_scores = self.attention(x)
        attn_weights = torch.softmax(attn_scores, dim=1)
        pooled = (x * attn_weights).sum(dim=1)
        logits = self.classifier(pooled).squeeze(-1)
        return logits


def compute_binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5

    # Wilson score interval for accuracy
    n = len(y_true)
    z = 1.96  # 95% confidence
    denom = 1 + z**2 / n
    center = (acc + z**2 / (2 * n)) / denom
    margin = z * np.sqrt((acc * (1 - acc) / n) + (z**2 / (4 * n**2))) / denom
    ci_lower = max(0.0, float(center - margin))
    ci_upper = min(1.0, float(center + margin))

    return {
        "sample_count": int(n),
        "genuine_count": int(tn + fp),
        "manipulated_count": int(fn + tp),
        "threshold": round(threshold, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "precision": round(prec, 4),
        "recall_sensitivity": round(rec, 4),
        "specificity": round(spec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "accuracy_ci_95": [round(ci_lower, 4), round(ci_upper, 4)],
    }


def train_and_evaluate(workspace_root: Path) -> Dict[str, Any]:
    tensor_dir = workspace_root / "datasets" / "DFDC" / "shield_2026_final_data"
    output_models_dir = workspace_root / "services" / "ml-service" / "app" / "models"
    output_models_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Training] Loading DFDC tensors from {tensor_dir}...")
    x_train_raw = torch.load(tensor_dir / "X_train.pt", map_location="cpu", weights_only=True)
    y_train_raw = torch.load(tensor_dir / "y_train.pt", map_location="cpu", weights_only=True)
    x_val_raw = torch.load(tensor_dir / "X_val.pt", map_location="cpu", weights_only=True)
    y_val_raw = torch.load(tensor_dir / "y_val.pt", map_location="cpu", weights_only=True)
    x_test_raw = torch.load(tensor_dir / "X_test.pt", map_location="cpu", weights_only=True)
    y_test_raw = torch.load(tensor_dir / "y_test.pt", map_location="cpu", weights_only=True)

    # Calculate class weights for training: Real (0)=1112, Fake (1)=9346
    n_neg = float((y_train_raw == 0).sum().item())
    n_pos = float((y_train_raw == 1).sum().item())
    pos_weight = torch.tensor([n_neg / n_pos])  # ~0.119 to avoid fake-class bias

    # Prepare pooled representations for candidate baseline comparisons
    x_tr_pooled = x_train_raw.mean(dim=1).numpy()
    y_tr_np = y_train_raw.numpy()
    x_va_pooled = x_val_raw.mean(dim=1).numpy()
    y_va_np = y_val_raw.numpy()
    x_te_pooled = x_test_raw.mean(dim=1).numpy()
    y_te_np = y_test_raw.numpy()

    print("[Training] Evaluating Candidate 1: Balanced LogisticRegression on pooled embeddings...")
    clf_lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    clf_lr.fit(x_tr_pooled, y_tr_np)
    val_probs_lr = clf_lr.predict_proba(x_va_pooled)[:, 1]
    val_metrics_lr = compute_binary_metrics(y_va_np, val_probs_lr, threshold=0.50)

    print("[Training] Evaluating Candidate 2: Balanced RandomForest on pooled embeddings...")
    clf_rf = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1)
    clf_rf.fit(x_tr_pooled, y_tr_np)
    val_probs_rf = clf_rf.predict_proba(x_va_pooled)[:, 1]
    val_metrics_rf = compute_binary_metrics(y_va_np, val_probs_rf, threshold=0.50)

    print("[Training] Evaluating Candidate 3: PyTorch AttentionPoolingVisualDetector...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Training] Using compute device: {device}")

    torch.manual_seed(42)
    nn_model = AttentionPoolingVisualDetector(in_features=1024, hidden_dim=256, dropout=0.3).to(device)
    train_dataset = TensorDataset(x_train_raw, y_train_raw.float())
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)

    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight.to(device))
    optimizer = optim.AdamW(nn_model.parameters(), lr=1e-4, weight_decay=1e-3)

    best_val_auc = 0.0
    best_weights = None
    epochs = 8

    for epoch in range(1, epochs + 1):
        nn_model.train()
        total_loss = 0.0
        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            logits = nn_model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(by)

        nn_model.eval()
        with torch.no_grad():
            val_logits = nn_model(x_val_raw.to(device))
            val_probs_nn = torch.sigmoid(val_logits).cpu().numpy()

        val_auc = roc_auc_score(y_va_np, val_probs_nn)
        val_bal = balanced_accuracy_score(y_va_np, val_probs_nn >= 0.50)
        print(f"  Epoch {epoch}/{epochs}: Loss = {total_loss / len(train_dataset):.4f}, Val ROC-AUC = {val_auc:.4f}, Val Bal Acc = {val_bal:.4f}")

        if val_auc > best_val_auc:
            best_val_auc = val_auc
            best_weights = nn_model.state_dict().copy()

    # Load best weights
    nn_model.load_state_dict(best_weights)
    nn_model.eval()

    with torch.no_grad():
        final_val_probs_nn = torch.sigmoid(nn_model(x_val_raw.to(device))).cpu().numpy()

    val_metrics_nn = compute_binary_metrics(y_va_np, final_val_probs_nn, threshold=0.50)

    # Candidate Comparison
    candidate_comparison = {
        "Balanced_LogisticRegression": {
            "validation_accuracy": val_metrics_lr["accuracy"],
            "validation_balanced_accuracy": val_metrics_lr["balanced_accuracy"],
            "validation_f1": val_metrics_lr["f1_score"],
            "validation_roc_auc": val_metrics_lr["roc_auc"],
        },
        "Balanced_RandomForest": {
            "validation_accuracy": val_metrics_rf["accuracy"],
            "validation_balanced_accuracy": val_metrics_rf["balanced_accuracy"],
            "validation_f1": val_metrics_rf["f1_score"],
            "validation_roc_auc": val_metrics_rf["roc_auc"],
        },
        "AttentionPooling_NeuralNetwork": {
            "validation_accuracy": val_metrics_nn["accuracy"],
            "validation_balanced_accuracy": val_metrics_nn["balanced_accuracy"],
            "validation_f1": val_metrics_nn["f1_score"],
            "validation_roc_auc": val_metrics_nn["roc_auc"],
        }
    }

    # Model Selection & Threshold Tuning on VALIDATION set ONLY
    print("\n[Model Selection] Finding optimal decision threshold on VALIDATION set...")
    # Search threshold in [0.20, 0.80] with step 0.02 to maximize Youden's J / Balanced Accuracy
    threshold_candidates = np.linspace(0.20, 0.80, 31)
    best_threshold = 0.50
    best_bal_acc = 0.0

    for thresh in threshold_candidates:
        cand_metrics = compute_binary_metrics(y_va_np, final_val_probs_nn, threshold=thresh)
        if cand_metrics["balanced_accuracy"] > best_bal_acc:
            best_bal_acc = cand_metrics["balanced_accuracy"]
            best_threshold = float(thresh)

    print(f"[Model Selection] Calibrated frozen threshold on validation set: {best_threshold:.2f} (Val Balanced Acc: {best_bal_acc:.4f})")
    frozen_val_metrics = compute_binary_metrics(y_va_np, final_val_probs_nn, threshold=best_threshold)

    # UNTOUCHED TEST EVALUATION (Evaluated ONCE after model & threshold are frozen)
    print("\n[Evaluation] Evaluating frozen model on UNTOUCHED test partition...")
    with torch.no_grad():
        test_logits = nn_model(x_test_raw.to(device))
        test_probs_nn = torch.sigmoid(test_logits).cpu().numpy()

    test_metrics = compute_binary_metrics(y_te_np, test_probs_nn, threshold=best_threshold)

    # Save artifacts
    print("[Serialization] Saving trained model artifacts and schemas...")

    # 1. PyTorch weights
    pt_path = output_models_dir / "deepfake_visual_classifier.pt"
    torch.save(nn_model.state_dict(), pt_path)

    # 2. Scikit-learn joblib model (for instant microsecond CPU inference fallback)
    joblib_path = output_models_dir / "deepfake_visual_classifier.joblib"
    joblib.dump(clf_lr, joblib_path)

    # 3. Model Schema
    schema = {
        "model_name": "CYBERGUARD Visual Deepfake Detector (DFDC-Shield 2026)",
        "model_version": "1.0.0",
        "model_type": "AttentionPoolingVisualDetector",
        "input_features": 1024,
        "input_frames": 20,
        "backbone": "CLIP ViT-H/14 (laion2b_s32b_b79k)",
        "normalization": "L2 normalized (unit hypersphere)",
        "target_mapping": {
            "genuine": 0,
            "manipulated": 1
        },
        "frozen_threshold": round(best_threshold, 4),
        "supported_inputs": [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "video/mp4",
            "tensor/1024_embedding"
        ]
    }
    schema_path = output_models_dir / "deepfake_visual_schema.json"
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    # 4. Metadata file
    metadata = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model_name": "CYBERGUARD Supervised Visual Deepfake Detector",
        "algorithm": "AttentionPoolingVisualDetector",
        "training_hardware": str(device),
        "epochs_trained": epochs,
        "frozen_threshold": round(best_threshold, 4),
        "dataset": {
            "name": "DFDC_Shield_2026",
            "source_datasets": ["DFDC (dfdc-10)", "FaceForensics++ (C23)", "Celeb-DF v2"],
            "train_samples": int(len(y_train_raw)),
            "validation_samples": int(len(y_val_raw)),
            "test_samples": int(len(y_test_raw)),
            "class_distribution_train": {
                "genuine": int((y_train_raw == 0).sum().item()),
                "manipulated": int((y_train_raw == 1).sum().item()),
            },
            "class_distribution_test": {
                "genuine": int((y_test_raw == 0).sum().item()),
                "manipulated": int((y_test_raw == 1).sum().item()),
            }
        },
        "candidate_comparison": candidate_comparison,
        "validation_metrics": frozen_val_metrics,
        "test_benchmark_metrics": {
            "claim": "Performance on the DFDC-derived held-out test partition.",
            "metrics": test_metrics
        },
        "leakage_and_limitation_disclosure": (
            "1. Evaluated on the held-out test partition of the DFDC/Shield 2026 benchmark. "
            "2. Because video-level source identity IDs were not preserved in the pre-extracted .pt files, "
            "cryptographic source-disjointness cannot be independently verified. "
            "3. Does not claim 100% accuracy or universal real-world generalizability against novel unencountered diffusion/GAN generators. "
            "4. Serves as the primary supervised visual detection signal alongside the 2D Fast Fourier Transform (FFT) forensic analyzer."
        )
    }
    meta_path = output_models_dir / "deepfake_visual_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[Serialization] Artifacts saved to {output_models_dir}:")
    print(f"  - {pt_path.name}")
    print(f"  - {joblib_path.name}")
    print(f"  - {schema_path.name}")
    print(f"  - {meta_path.name}")

    return {
        "schema": schema,
        "metadata": metadata,
        "test_metrics": test_metrics,
    }


def main():
    script_dir = Path(__file__).resolve().parent
    workspace_root = script_dir.parent.parent.parent
    print("=" * 65)
    print("  CYBERGUARD — VISUAL DEEPFAKE MODEL TRAINING & TEST EVALUATION")
    print("=" * 65)

    results = train_and_evaluate(workspace_root)
    m = results["test_metrics"]

    print("\n" + "=" * 65)
    print("         FROZEN TEST PARTITION EVALUATION REPORT")
    print("=" * 65)
    print(f"Test Samples        : {m['sample_count']}")
    print(f"Genuine Samples     : {m['genuine_count']}")
    print(f"Manipulated Samples : {m['manipulated_count']}")
    print(f"Frozen Threshold    : {m['threshold']}")
    print(f"Confusion Matrix    : TN={m['confusion_matrix']['tn']}, FP={m['confusion_matrix']['fp']}, FN={m['confusion_matrix']['fn']}, TP={m['confusion_matrix']['tp']}")
    print(f"Accuracy            : {m['accuracy'] * 100:.2f}% (95% CI: [{m['accuracy_ci_95'][0]*100:.2f}%, {m['accuracy_ci_95'][1]*100:.2f}%])")
    print(f"Balanced Accuracy   : {m['balanced_accuracy'] * 100:.2f}%")
    print(f"Precision           : {m['precision'] * 100:.2f}%")
    print(f"Recall (Sensitivity): {m['recall_sensitivity'] * 100:.2f}%")
    print(f"Specificity         : {m['specificity'] * 100:.2f}%")
    print(f"F1 Score            : {m['f1_score'] * 100:.2f}%")
    print(f"ROC-AUC             : {m['roc_auc']:.4f}")
    print(f"PR-AUC              : {m['pr_auc']:.4f}")
    print("=" * 65)


if __name__ == "__main__":
    main()
