# CYBERGUARD — Phase 8 Deepfake Detection Improvement & Hardening

## Document Metadata
- **Phase:** Phase 8.2 — Visual Deepfake Model Candidate Training & Validation
- **Status:** Complete (Phase 8.2 Evaluated; Promotion Recommendation Formulated)
- **Date:** 2026-10-05
- **Dataset:** DFDC Shield 2026 Preprocessed ViT-B/16 Embeddings (20 frames x 1024 dims)
- **Partitions:**
  - Training: `X_train.pt` / `y_train.pt` (10,458 samples: 9,346 manipulated, 1,112 genuine)
  - Validation: `X_val.pt` / `y_val.pt` (2,241 samples: 2,003 manipulated, 238 genuine)
  - Frozen Final Test: `X_test.pt` / `y_test.pt` (2,242 samples: 2,003 manipulated, 239 genuine)
- **Primary Script:** `services/ml-service/scripts/train_visual_candidates_phase8.py`
- **Audit Script:** `services/ml-service/scripts/phase8_dataset_hardening.py`

---

## 1. Baseline Performance (Production v1.0.0)

The production visual classifier (`services/ml-service/app/models/deepfake_visual_classifier.pt`) uses an `AttentionPoolingVisualDetector` with fixed operating threshold $\tau = 0.6400$.

### Frozen Final-Test Baseline Metrics (2,242 samples):
- **Accuracy:** 65.03%
- **Balanced Accuracy:** 74.35%
- **Precision:** 97.43%
- **Recall:** 62.51%
- **Specificity:** 86.19%
- **F1 Score:** 0.7616
- **False Positive Rate (FPR):** 13.81%
- **ROC-AUC:** 0.7966
- **PR-AUC:** 0.9722
- **Confusion Matrix:**
  - True Negatives (TN): 206
  - False Positives (FP): 33
  - False Negatives (FN): 751
  - True Positives (TP): 1,252
- **Inference Latency:** 0.588 ms / sample (CPU single-sequence)
- **Artifact Size:** 1.65 MB (1,647,761 bytes)

---

## 2. Candidate Architectures & Formulations

Three candidate architectures and training configurations were designed to evaluate whether architectural fusion and class weighting can improve detection recall and balanced accuracy without degrading specificity:

1. **Candidate A: AttentionPoolingVisualDetector (Balanced Weights)**
   - Architecture: Identical to production AttentionPoolingVisualDetector (Linear 1024->128 -> Tanh -> Linear 128->1 -> Softmax attention weights -> Linear 1024->256 -> LayerNorm -> ReLU -> Dropout(0.3) -> Linear 256->64 -> LayerNorm -> ReLU -> Dropout(0.21) -> Linear 64->1).
   - Loss Function: Class-weighted BCE with Phase 8.1 computed balanced weights ($w_0 = 4.7023$ for genuine, $w_1 = 0.5595$ for manipulated).

2. **Candidate B: Dual Temporal Fusion (Mean + Attention, Unweighted)**
   - Architecture: Dual pooling concatenation $z = [x_{\text{mean}} \parallel x_{\text{attn}}] \in \mathbb{R}^{2048}$.
   - Classification Head: LayerNorm(2048) -> Dropout(0.3) -> Linear 2048->256 -> LayerNorm(256) -> ReLU -> Dropout(0.3) -> Linear 256->64 -> LayerNorm(64) -> ReLU -> Dropout(0.21) -> Linear 64->1.
   - Loss Function: Standard unweighted binary cross-entropy (`nn.functional.binary_cross_entropy_with_logits`).

3. **Candidate C: Dual Temporal Fusion (Mean + Attention, Balanced Weights)**
   - Architecture: Identical to Candidate B (Dual Temporal Fusion).
   - Loss Function: Class-weighted BCE with Phase 8.1 computed balanced weights ($w_0 = 4.7023$ for genuine, $w_1 = 0.5595$ for manipulated).

---

## 3. Training & Reproducibility Configuration

- **Random Seed:** 42 (deterministic `torch.manual_seed(42)` and `torch.cuda.manual_seed_all(42)`)
- **PyTorch Version:** 2.14.0+cu126
- **Compute Hardware:** NVIDIA GeForce RTX 2050 (CUDA)
- **Optimizer:** AdamW (`lr = 1.5e-4`, `weight_decay = 1e-3`)
- **Learning Rate Schedule:** `CosineAnnealingLR(T_max = 8)`
- **Batch Size:** 128
- **Epochs:** 8
- **Training Augmentation:**
  - Random temporal window selection: 16 contiguous frames randomly offset from 20 sequence frames.
  - Gaussian embedding jitter: $\sigma = 0.015$ applied with probability $p = 0.50$.
  - L2 re-normalization: embedding vectors re-normalized to the unit hypersphere.
- **Validation Isolation:** Validation data (`X_val.pt`, `y_val.pt`) evaluated strictly without data augmentation.
- **Test Set Isolation:** Frozen test set (`X_test.pt`, `y_test.pt`) completely isolated during candidate training, validation, and threshold selection.

---

## 4. Candidate Validation Comparison Table

Candidates were compared strictly on validation data (`X_val.pt`, `y_val.pt`, 2,241 samples). A fine-grained search grid ($0.05 \le \tau \le 0.95$, step 0.01) selected the operating threshold maximizing Balanced Accuracy subject to the operational constraint $\text{Specificity} \ge 80.0\%$:

| Candidate | Selected Threshold ($\tau$) | Accuracy | Balanced Acc | Precision | Recall | Specificity | F1 Score | FPR | ROC-AUC | PR-AUC |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Candidate A** (Balanced Attention Pooling) | 0.5800 | 62.83% | 73.47% | 97.48% | 59.96% | 86.97% | 0.7425 | 13.03% | 0.7898 | 0.9714 |
| **Candidate B** (Dual Temporal Fusion Unweighted) | **0.9500** | **62.12%** | **74.36%** | **98.00%** | **58.81%** | **89.92%** | **0.7351** | **10.08%** | **0.7947** | **0.9723** |
| **Candidate C** (Dual Temporal Fusion Balanced) | 0.5100 | 62.92% | 73.52% | 97.49% | 60.06% | 86.97% | 0.7433 | 13.03% | 0.7947 | 0.9721 |

### Validation Selection Decision:
**Candidate B (Dual Temporal Fusion Unweighted)** achieved the highest Validation Balanced Accuracy (74.36%), the highest Validation Specificity (89.92%), the lowest FPR (10.08%), and the highest ROC-AUC (0.7947). In accordance with the pre-registered protocol, Candidate B was selected as the winning candidate for single-pass evaluation on the frozen final test gate at operating threshold $\tau = 0.9500$.

---

## 5. Final Test Gate Evaluation (Untouched Test Set)

Candidate B was evaluated **exactly once** on `X_test.pt` / `y_test.pt` (2,242 samples) with its frozen operating threshold $\tau = 0.9500$. No hyperparameter tuning or threshold modification occurred after observing test set results.

### Head-to-Head Comparison: Production Baseline vs Candidate B

| Metric | Production Baseline (v1.0.0) | Candidate B (Phase 8.2) | Delta | Assessment |
|:---|:---|:---|:---|:---|
| **Architecture** | AttentionPoolingVisualDetector | DualTemporalFusionVisualDetector | Dual Pooling | Faster, Mean+Attn |
| **Operating Threshold ($\tau$)** | 0.6400 | 0.9500 | +0.3100 | Calibrated for fusion head |
| **Accuracy** | 65.03% | 61.86% | -3.17% | Lower |
| **Balanced Accuracy** | 74.35% | 73.68% | -0.67% | Marginally lower |
| **Recall** | 62.51% | 58.66% | -3.85% | **Degraded** |
| **Precision** | 97.43% | 97.75% | +0.32% | Slight gain |
| **Specificity** | 86.19% | 88.70% | +2.51% | Improved |
| **F1 Score** | 0.7616 | 0.7332 | -0.0284 | Lower |
| **False Positive Rate (FPR)** | 13.81% | 11.30% | -2.51% | Improved |
| **ROC-AUC** | 0.7966 | 0.7931 | -0.0035 | Comparable |
| **PR-AUC** | 0.9722 | 0.9717 | -0.0005 | Comparable |
| **False Negatives (FN)** | 751 | 828 | +77 | **Higher error count** |
| **False Positives (FP)** | 33 | 27 | -6 | Lower error count |
| **Inference Latency** | 0.588 ms | 0.319 ms | -0.269 ms | **1.84x faster** |
| **Model Size** | 1.65 MB | 2.71 MB | +1.06 MB | Acceptable |

### Confusion Matrix Breakdown:
- **Baseline (v1.0.0):** $\text{TN}=206$, $\text{FP}=33$, $\text{FN}=751$, $\text{TP}=1252$
- **Candidate B (Phase 8.2):** $\text{TN}=212$, $\text{FP}=27$, $\text{FN}=828$, $\text{TP}=1175$

---

## 6. Production Promotion Recommendation

### Formal Decision: **KEEP v1.0.0 AS PRODUCTION**

Per the pre-established promotion criteria:
> *"Promote ONLY if the final untouched test result demonstrates a meaningful improvement while maintaining acceptable false-positive behavior and production latency. If the candidate does not meaningfully improve the model: KEEP v1.0.0 AS PRODUCTION. That is a valid result."*

### Scientific & Operational Rationale:
1. **Primary Objective Failure on Recall:** The primary motivation for Phase 8 visual improvement was to address the high false negative rate (751 FN, 62.51% recall). Candidate B resulted in a recall of 58.66% (-3.85%) and increased false negatives to 828 (+77 missed deepfakes).
2. **Balanced Accuracy Did Not Improve:** Baseline balanced accuracy is 74.35%, whereas Candidate B achieved 73.68% (-0.67%).
3. **Marginal Specificity Gain Insufficient to Offset Missed Threats:** While Candidate B improved specificity from 86.19% to 88.70% (+2.51%) and reduced false positives from 33 to 27, in an enterprise threat defense posture, allowing 77 additional deepfake attacks to pass undetected outweighs a 6-sample false alarm reduction.
4. **Preservation of System Stability:** Current production artifact `services/ml-service/app/models/deepfake_visual_classifier.pt` and its registered threshold $\tau = 0.6400$ remain the active, superior production checkpoint.

---

## 7. Artifact Integrity & Reproducibility Evidence

The Candidate B artifact is safely archived in the Phase 8 experiment directory and will not overwrite the production model:

- **Candidate Artifact Path:** `services/ml-service/experiments/visual_candidates_phase8_20261004_213510/candidate_b_(dual_temporal_fusion_unweighted).pt`
- **Candidate File Size:** 2,713,587 bytes (2.71 MB)
- **Candidate SHA-256 Checksum:** `3a7eeeeef8caab770abcc0bdd169bbb6995f825074dcb79482968329d3b0dd1a`
- **Experiment Evaluation JSON:** `services/ml-service/experiments/visual_candidates_phase8_20261004_213510/visual_candidate_evaluation_report.json`
- **Production Artifact (Intact):** `services/ml-service/app/models/deepfake_visual_classifier.pt` (`4c0cf94e09d136db6d735079a4a75369bb9c614b1ba022a1068aa9a5b33190df`)

---

## 8. Test Suite & Regression Verification

Regression verification was executed across the ML service media detection suite:
- **Command:** `pytest tests/test_dfdc_visual_engine.py tests/test_media_engine.py -v`
- **Results:**
  - `tests/test_dfdc_visual_engine.py`: 10 passed
  - `tests/test_media_engine.py`: 18 passed
  - **Total Passed:** 28 of 28 passed (100%)
  - **Total Failed:** 0
  - **Regressions:** 0
