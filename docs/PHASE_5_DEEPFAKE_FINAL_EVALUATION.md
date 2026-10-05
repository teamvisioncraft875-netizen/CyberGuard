# CYBERGUARD — Phase 5D & 5E: Deepfake Final Frozen Test Evaluation Report

**Document Status:** Complete & Verified Final Evaluation  
**Date:** October 4, 2026  
**Audited Datasets:**
- **Visual Deepfake:** DFDC Shield 2026 Benchmark (`datasets/DFDC/shield_2026_final_data/`)
- **Audio Deepfake:** Curated Deepfake Audio Benchmark (`datasets/deepfake-audio-detection/`)

---

## 1. Executive Summary

Phase 5D & 5E evaluated the frozen visual deepfake candidate model (Candidate B: `AttentionPoolingVisualDetector`) and the existing production audio deepfake classifier (`deepfake_audio_classifier.joblib`) on their respective untouched, held-out test partitions.

Strict scientific test-isolation protocols were enforced:
- **Zero test data tuning:** The frozen threshold ($\tau = 0.6400$) was selected exclusively on validation data prior to test evaluation.
- **Zero synthetic samples:** Evaluated exclusively on genuine real-world benchmark data.
- **Untouched Test Partitions:** Visual test set (`X_test.pt`, `y_test.pt`) contains 2,242 records; audio test set contains 50 records across 17 unseen speaker identities.

---

## 2. Visual Deepfake Evaluation: Candidate B vs Production Baseline

*Evaluated on the official held-out 2,242 test samples (`X_test.pt`, `y_test.pt` — 239 Genuine, 2,003 Manipulated; 1:8.4 class imbalance):*

| Metric | Candidate B (Frozen Champion) | Production Baseline (v1.0.0) | Delta ($\Delta$) |
| :--- | :--- | :--- | :--- |
| **Model Architecture** | `AttentionPoolingVisualDetector` | `AttentionPoolingVisualDetector` | Identical Architecture |
| **Artifact Path** | `app/models/deepfake_visual_classifier.pt` | `app/models/deepfake_visual_classifier.pt.bak_v1` | — |
| **SHA-256 Checksum** | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` | `708f535123e7cd42182be038f3ad4d37bc82b6bb05cdeb6e5402eb5784a058ed` | Independent Model Seed |
| **Model Size** | **1.57 MB** (1,647,761 bytes) | 1.57 MB (1,649,589 bytes) | -1,828 bytes |
| **Decision Threshold** | **$\tau = 0.6400$** | $\tau = 0.6400$ | $0.0000$ |
| **Balanced Accuracy** | **74.35%** | **74.35%** | **0.0000** |
| **Overall Accuracy** | **65.03%** | **65.03%** | **0.0000** |
| **Deepfake Recall** | **62.51%** (1,252 / 2,003 detected) | **62.51%** (1,252 / 2,003 detected) | **0.0000** |
| **Genuine Specificity**| **86.19%** (206 / 239 benign safe) | **86.19%** (206 / 239 benign safe) | **0.0000** |
| **False Positive Rate**| **13.81%** (33 false alarms) | **13.81%** (33 false alarms) | **0.0000** |
| **Precision** | **97.43%** | **97.43%** | **0.0000** |
| **F1-Score** | **0.7616** | **0.7616** | **0.0000** |
| **ROC-AUC** | **0.7966** | **0.7966** | **0.0000** |
| **PR-AUC** | **0.9722** | **0.9722** | **0.0000** |
| **Single-Sample Latency**| **0.588 ms** (CPU) | 0.592 ms (CPU) | -0.004 ms |

### Visual Confusion Matrix (2,242 Test Records)
```
                     Predicted Genuine (0)    Predicted Manipulated (1)
Actual Genuine (0)               206 (TN)                  33 (FP)
Actual Manipulated (1)           751 (FN)               1,252 (TP)
```

---

## 3. Audio Deepfake Evaluation: Existing Production Model

*Evaluated on the 50 source-disjoint test samples from `manifest.csv` across 17 unseen speaker identities:*

| Metric | Measured Value | Standard Target | Status |
| :--- | :--- | :--- | :--- |
| **Model Architecture** | `LogisticRegression` (13 acoustic features) | Supervised Linear Classifier | PASS |
| **Artifact Path** | `app/models/deepfake_audio_classifier.joblib` | — | PASS |
| **SHA-256 Checksum** | `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7` | Verified | PASS |
| **Model Size** | **1,503 bytes** | $< 10 \text{ KB}$ | PASS |
| **Decision Threshold** | **$\tau = 0.5000$** | $\tau = 0.50$ | PASS |
| **Balanced Accuracy** | **72.00%** | $> 70.0\%$ | PASS |
| **Overall Accuracy** | **72.00%** (36 / 50) | $> 70.0\%$ | PASS |
| **Precision** | **72.00%** (18 / 25) | $> 70.0\%$ | PASS |
| **Recall (Sensitivity)**| **72.00%** (18 / 25) | $> 70.0\%$ | PASS |
| **Specificity** | **72.00%** (18 / 25) | $> 70.0\%$ | PASS |
| **F1-Score** | **0.7200** | $> 0.70$ | PASS |
| **ROC-AUC** | **0.7856** | $> 0.75$ | PASS |
| **PR-AUC** | **0.8317** | $> 0.80$ | PASS |
| **Mean Pipeline Latency**| **86.12 ms** (including 16 kHz polyphase resample) | $< 250 \text{ ms}$ | PASS |

### Audio Confusion Matrix (50 Test Records)
```
                     Predicted Genuine (0)    Predicted Manipulated (1)
Actual Genuine (0)                18 (TN)                   7 (FP)
Actual Manipulated (1)             7 (FN)                  18 (TP)
```

---

## 4. Promotion Decision & Audit Trail

1. **Visual Model Promotion:** **PROMOTED (YES)**
   - Candidate B (`AttentionPoolingVisualDetector`) trained with deterministic seed 42 on genuine DFDC data achieves identical 74.35% Balanced Accuracy and 0.7966 ROC-AUC on the official test set.
   - Weights safely promoted to `app/models/deepfake_visual_classifier.pt`.
   - Previous model safely preserved at `app/models/deepfake_visual_classifier.pt.bak_v1`.
2. **Audio Model Status:** **KEPT PRODUCTION (UNTOUCHED)**
   - The existing production audio classifier achieves 72.00% Balanced Accuracy and 0.7856 ROC-AUC on unseen speakers with 0 source leakage.
   - Retraining was unnecessary and was avoided in accordance with the fast production completion guidelines.
