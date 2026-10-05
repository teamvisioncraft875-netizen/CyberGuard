#!/usr/bin/env python3
"""
CYBERGUARD Phase 9: Final Frozen Test Gate Evaluation.
Evaluates the finalized, frozen candidate models against the immutable Phase 8 test sets EXACTLY ONCE.
- Visual: 2,242 samples (X_test.pt, y_test.pt)
- Audio: 50 samples (25 genuine / 25 manipulated across 17 unseen speakers)

No parameters, thresholds, or architectures are tuned after observing this result.
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any

import joblib
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
EXP_DIR = ML_SERVICE_DIR / "experiments" / "deepfake_v2_20261004_223500"
AUDIO_DATASET_DIR = REPO_ROOT / "datasets" / "deepfake-audio-detection"
VISUAL_DATA_DIR = REPO_ROOT / "datasets" / "DFDC" / "shield_2026_final_data"

if str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

from scripts.train_audio_v2 import extract_28_features, FEATURE_NAMES
from scripts.train_visual_v2 import (
    EnhancedAttentionPooling, TriPoolFusionVisualDetector,
    TemporalDeltaVisualDetector, TransformerTemporalVisualDetector
)
from app.services.media_anomaly.image_detector import AttentionPoolingVisualDetector

def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, Any]:
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

def evaluate_audio():
    print("\n=======================================================")
    print("PHASE 9 FINAL FROZEN TEST GATE — AUDIO MODALITY")
    print("=======================================================")
    manifest = pd.read_csv(AUDIO_DATASET_DIR / "manifest.csv")
    test_df = manifest[manifest["split"] == "test"].copy()
    print(f"Test samples: {len(test_df)} ({test_df['label'].value_counts().to_dict()})")
    print(f"Unique unseen speakers: {test_df['source_id'].nunique()}")

    # Extract test features
    test_rows = []
    for idx, row in test_df.iterrows():
        p = AUDIO_DATASET_DIR / row["path"]
        feats = extract_28_features(str(p))
        test_rows.append([feats[fn] for fn in FEATURE_NAMES])

    X_test_df = pd.DataFrame(test_rows, columns=FEATURE_NAMES)
    y_test = (test_df["label"] == "manipulated").astype(int).values

    # 1. Baseline Audio Model (v1.0.0)
    prod_model_path = ML_SERVICE_DIR / "app" / "models" / "deepfake_audio_classifier.joblib"
    prod_schema_path = ML_SERVICE_DIR / "app" / "models" / "deepfake_audio_schema.json"
    prod_model = joblib.load(prod_model_path)
    with open(prod_schema_path, "r", encoding="utf-8") as f:
        prod_schema = json.load(f)

    prod_feats = prod_schema["features"]
    prod_X_test = X_test_df[prod_feats]
    prod_probs = prod_model.predict_proba(prod_X_test)[:, 1]
    baseline_metrics = compute_metrics(y_test, prod_probs, threshold=0.50)
    print(f"\n[Baseline v1.0.0 Audio (13 features, tau=0.50)]")
    print(f"  Accuracy: {baseline_metrics['accuracy']*100:.2f}% | BalAcc: {baseline_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {baseline_metrics['recall']*100:.2f}% | Spec: {baseline_metrics['specificity']*100:.2f}% | FPR: {baseline_metrics['fpr']*100:.2f}%")
    print(f"  F1: {baseline_metrics['f1']:.4f} | ROC-AUC: {baseline_metrics['roc_auc']:.4f} | PR-AUC: {baseline_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {baseline_metrics['confusion_matrix']}")

    # 2. Candidate D (Multi-Layer Perceptron)
    cand_d_path = EXP_DIR / "candidate_d_multi_layer_perceptron_neural_net.joblib"
    cand_d_model = joblib.load(cand_d_path)
    cand_d_probs = cand_d_model.predict_proba(X_test_df)[:, 1]
    cand_d_metrics = compute_metrics(y_test, cand_d_probs, threshold=0.49)
    print(f"\n[Candidate D Audio V2 (MLP 28 features, tau=0.49)]")
    print(f"  Accuracy: {cand_d_metrics['accuracy']*100:.2f}% | BalAcc: {cand_d_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {cand_d_metrics['recall']*100:.2f}% | Spec: {cand_d_metrics['specificity']*100:.2f}% | FPR: {cand_d_metrics['fpr']*100:.2f}%")
    print(f"  F1: {cand_d_metrics['f1']:.4f} | ROC-AUC: {cand_d_metrics['roc_auc']:.4f} | PR-AUC: {cand_d_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {cand_d_metrics['confusion_matrix']}")

    # Also evaluate Candidate A (Calibrated LR) for complete audit trail
    cand_a_path = EXP_DIR / "candidate_a_calibrated_logistic_regression.joblib"
    cand_a_model = joblib.load(cand_a_path)
    cand_a_probs = cand_a_model.predict_proba(X_test_df)[:, 1]
    cand_a_metrics = compute_metrics(y_test, cand_a_probs, threshold=0.33)
    print(f"\n[Candidate A Audio V2 (Calibrated LR 28 features, tau=0.33)]")
    print(f"  Accuracy: {cand_a_metrics['accuracy']*100:.2f}% | BalAcc: {cand_a_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {cand_a_metrics['recall']*100:.2f}% | Spec: {cand_a_metrics['specificity']*100:.2f}% | FPR: {cand_a_metrics['fpr']*100:.2f}%")
    print(f"  F1: {cand_a_metrics['f1']:.4f} | ROC-AUC: {cand_a_metrics['roc_auc']:.4f} | PR-AUC: {cand_a_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {cand_a_metrics['confusion_matrix']}")

    return {
        "baseline_v1": baseline_metrics,
        "candidate_d": cand_d_metrics,
        "candidate_a": cand_a_metrics
    }

def evaluate_visual():
    print("\n=======================================================")
    print("PHASE 9 FINAL FROZEN TEST GATE — VISUAL MODALITY")
    print("=======================================================")
    X_test = torch.load(VISUAL_DATA_DIR / "X_test.pt", map_location="cpu")
    y_test = torch.load(VISUAL_DATA_DIR / "y_test.pt", map_location="cpu").numpy()
    print(f"Test samples: {X_test.shape}, pos: {int(y_test.sum())}/{len(y_test)}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # 1. Baseline Model v1.0.0
    prod_model = AttentionPoolingVisualDetector(in_features=1024)
    prod_weights = torch.load(ML_SERVICE_DIR / "app" / "models" / "deepfake_visual_classifier.pt", map_location="cpu", weights_only=True)
    prod_model.load_state_dict(prod_weights)
    prod_model.to(device)
    prod_model.eval()

    with torch.no_grad():
        prod_logits = prod_model(X_test.to(device)).cpu()
        prod_probs = torch.sigmoid(prod_logits).numpy()

    baseline_metrics = compute_metrics(y_test, prod_probs, threshold=0.64)
    print(f"\n[Baseline v1.0.0 Visual (AttentionPooling, tau=0.64)]")
    print(f"  Accuracy: {baseline_metrics['accuracy']*100:.2f}% | BalAcc: {baseline_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {baseline_metrics['recall']*100:.2f}% | Spec: {baseline_metrics['specificity']*100:.2f}% | FPR: {baseline_metrics['fpr']*100:.2f}%")
    print(f"  F1: {baseline_metrics['f1']:.4f} | ROC-AUC: {baseline_metrics['roc_auc']:.4f} | PR-AUC: {baseline_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {baseline_metrics['confusion_matrix']}")

    # 2. Candidate E (Transformer Self-Attention Focal)
    cand_e_model = TransformerTemporalVisualDetector(in_features=1024, hidden_dim=256, nhead=4, num_layers=2, dropout=0.35)
    cand_e_weights = torch.load(EXP_DIR / "candidate_e_temporal_transformer_self_attention_focal.pt", map_location="cpu")
    cand_e_model.load_state_dict(cand_e_weights)
    cand_e_model.to(device)
    cand_e_model.eval()

    with torch.no_grad():
        cand_e_logits = cand_e_model(X_test.to(device)).cpu()
        cand_e_probs = torch.sigmoid(cand_e_logits).numpy()

    cand_e_metrics = compute_metrics(y_test, cand_e_probs, threshold=0.70)
    print(f"\n[Candidate E Visual V2 (Transformer Self-Attention, tau=0.70)]")
    print(f"  Accuracy: {cand_e_metrics['accuracy']*100:.2f}% | BalAcc: {cand_e_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {cand_e_metrics['recall']*100:.2f}% | Spec: {cand_e_metrics['specificity']*100:.2f}% | FPR: {cand_e_metrics['fpr']*100:.2f}%")
    print(f"  F1: {cand_e_metrics['f1']:.4f} | ROC-AUC: {cand_e_metrics['roc_auc']:.4f} | PR-AUC: {cand_e_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {cand_e_metrics['confusion_matrix']}")

    # 3. Candidate A (Enhanced Attention Pooling Focal)
    cand_a_model = EnhancedAttentionPooling(in_features=1024, hidden_dim=256, dropout=0.35)
    cand_a_weights = torch.load(EXP_DIR / "candidate_a_enhanced_attention_pooling_focal.pt", map_location="cpu")
    cand_a_model.load_state_dict(cand_a_weights)
    cand_a_model.to(device)
    cand_a_model.eval()

    with torch.no_grad():
        cand_a_logits = cand_a_model(X_test.to(device)).cpu()
        cand_a_probs = torch.sigmoid(cand_a_logits).numpy()

    cand_a_metrics = compute_metrics(y_test, cand_a_probs, threshold=0.75)
    print(f"\n[Candidate A Visual V2 (Enhanced Attention Pooling, tau=0.75)]")
    print(f"  Accuracy: {cand_a_metrics['accuracy']*100:.2f}% | BalAcc: {cand_a_metrics['balanced_accuracy']*100:.2f}%")
    print(f"  Recall: {cand_a_metrics['recall']*100:.2f}% | Spec: {cand_a_metrics['specificity']*100:.2f}% | FPR: {cand_a_metrics['fpr']*100:.2f}%")
    print(f"  F1: {cand_a_metrics['f1']:.4f} | ROC-AUC: {cand_a_metrics['roc_auc']:.4f} | PR-AUC: {cand_a_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {cand_a_metrics['confusion_matrix']}")

    return {
        "baseline_v1": baseline_metrics,
        "candidate_e": cand_e_metrics,
        "candidate_a": cand_a_metrics
    }

def main():
    audio_results = evaluate_audio()
    visual_results = evaluate_visual()

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": "PHASE 9 — FINAL FROZEN TEST GATE EVALUATION",
        "audio": audio_results,
        "visual": visual_results
    }

    out_path = EXP_DIR / "final_frozen_test_report.json"
    with open(out_path, "w") as f:
        json.dump(final_report, f, indent=2)
    print(f"\nFinal Frozen Test Report saved to {out_path}")

if __name__ == "__main__":
    main()
