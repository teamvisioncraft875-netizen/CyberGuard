# CYBERGUARD Phase 2 — Phishing Candidate Model Training & Comparison Report

**Document Version:** 1.0.0  
**Status:** COMPLETE (RECOMMENDATION: KEEP v1.0.0)  
**Author:** CYBERGUARD ML Lead  
**Experiment Identifier:** `phishing_candidate_exp_20261004_082003`  
**Execution Timestamp:** 2026-10-04T08:22:15Z  

---

## 1. Frozen Baseline Overview

The production phishing engine (`services/ml-service/app/services/message_engine.py`) operates with immutable production artifacts frozen at `v1.0.0`:
- **Architecture:** `CalibratedClassifierCV(LinearSVC(C=1.0, random_state=42), cv=3, method='sigmoid')`
- **Feature Space:** TF-IDF 25,000 features (unigram + bigram, sublinear TF scaling, token pattern `r"(?u)\b[a-zA-Z0-9_\-\.]{2,}\b"`)
- **Operating Threshold:** $\tau = 0.36$
- **Baseline In-Source Test Performance (4,368 samples):**
  - Accuracy: 99.59% (reproduced: 99.45%)
  - Balanced Accuracy: 98.93% (reproduced: 99.04%)
  - Precision: 99.22% (reproduced: 97.86%)
  - Recall: 98.00% (reproduced: 98.46%)
  - Specificity: 99.87% (reproduced: 99.62%)
  - F1 Score: 98.60% (reproduced: 98.16%)
  - ROC-AUC: 0.9987 (reproduced: 0.9981)

---

## 2. Candidate Model Configurations Evaluated

All candidates were trained on the identical 34,944-sample training partition of `datasets/cleaned_manifests/phishing_curated_manifest.parquet` using identical TF-IDF feature extractions:

| Candidate ID | Model Architecture | Hyperparameters & Solver | Model Size | Training Duration |
|---|---|---|---|---|
| **Candidate A** | `Calibrated_LinearSVC` *(Baseline)* | $C=1.0$, `dual='auto'`, 3-fold Platt calibration, seed 42 | 602 KB | 0.75 s |
| **Candidate B** | `Balanced_LogisticRegression` | $C=3.0$, `class_weight='balanced'`, solver `saga`, seed 42 | 201 KB | 5.93 s |
| **Candidate C** | `Standard_L2_LogisticRegression` | $C=1.0$, `class_weight=None`, solver `lbfgs`, seed 42 | 201 KB | 0.40 s |
| **Candidate D** | `SGD_LogLoss_Classifier` | $\alpha=10^{-4}$, loss `log_loss`, penalty `L2`, seed 42 | 201 KB | 0.22 s |

---

## 3. Validation Comparison (Strictly Validation Partition: 4,368 Samples)

All model comparison and threshold tuning decisions were conducted exclusively on the Validation partition. The held-out test partition remained untouched during candidate evaluation:

| Candidate Model | Baseline Threshold $\tau = 0.36$ (F1 / Rec / FPR) | Validation Optimal $\tau$ | Val Accuracy | Val Bal. Acc. | Val Precision | Val Recall | Val Specificity | Val FPR | Val F1 Score | Val ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| **A. Calibrated LinearSVC** | 0.9862 / 98.92% / 0.30% | $\tau = 0.48$ | **99.77%** | **99.36%** | **99.69%** | **98.77%** | **99.95%** | **0.05%** | **0.9923** | **0.9999** |
| **B. Balanced LogisticRegression**| 0.9877 / 99.08% / 0.27% | $\tau = 0.46$ | 99.70% | 99.38% | 99.08% | 98.92% | 99.84% | 0.16% | 0.9900 | 0.9999 |
| **C. Standard L2 LogisticRegression**| 0.9773 / 95.85% / 0.05% | $\tau = 0.20$ | 99.47% | 98.68% | 98.91% | 97.54% | 99.81% | 0.19% | 0.9822 | 0.9996 |
| **D. SGD LogLoss Classifier** | 0.9708 / 94.46% / 0.03% | $\tau = 0.24$ | 99.34% | 98.21% | 98.90% | 96.62% | 99.81% | 0.19% | 0.9774 | 0.9994 |

---

## 4. Threshold Selection Methodology

Threshold analysis was performed on validation probabilities with the enterprise objective:
$$\max_{\tau} F_1(\tau) \quad \text{subject to} \quad \text{FPR}(\tau) \le 1.0\% \quad \text{and} \quad \text{Recall}(\tau) \ge 95.0\%$$

- **For Candidate A (Calibrated LinearSVC):**
  - At $\tau = 0.36$: Recall is 98.92%, Precision is 98.32%, FPR is 0.30%, F1 is 0.9862.
  - At $\tau = 0.48$: Recall is 98.77%, Precision is 99.69%, FPR drops to 0.05% (only 2 false positives out of 3,719 corporate emails), F1 reaches 0.9923.
- **For Candidate B (Balanced Logistic Regression):**
  - Requires $\tau = 0.46$ to balance recall (98.92%) and precision (99.08%).
- **For Candidates C & D (Standard Logistic Regression & SGD):**
  - Unweighted models output lower raw probabilities for minority classes, requiring sharp threshold reductions ($\tau = 0.20$ and $\tau = 0.24$) to achieve acceptable recall, making them sensitive to distribution shifts.

---

## 5. Cross-Source Generalization Audit

Before evaluating the final held-out test partition, candidates were tested on external benchmark distributions without retraining:

| Candidate Model | Operating $\tau$ | NIST TREC 2007 (28,990 samples) | Ling Academic Benign (2,401 samples) | Nazario LOSO Recall |
|---|---|---|---|---|
| **A. Calibrated LinearSVC** | $\tau = 0.48$ | **Acc: 90.68% \| Prec: 81.84% \| Rec: 53.52% \| F1: 0.6472** | **Specificity: 98.96% (FPR: 1.04%)** | 32.39% |
| **A. Calibrated LinearSVC** | $\tau = 0.36$ *(Prod)* | Acc: 89.08% \| Prec: 65.97% \| Rec: 65.41% \| F1: 0.6569 | Specificity: 97.54% (FPR: 2.46%) | 32.39% |
| **B. Balanced LogisticRegression** | $\tau = 0.46$ | Acc: 89.10% \| Prec: 71.55% \| Rec: 52.76% \| F1: 0.6074 | Specificity: 99.04% (FPR: 0.96%) | 32.39% |
| **C. Standard L2 LogisticRegression**| $\tau = 0.20$ | Acc: 88.56% \| Prec: 69.09% \| Rec: 51.38% \| F1: 0.5893 | Specificity: 98.88% (FPR: 1.12%) | 32.39% |
| **D. SGD LogLoss Classifier** | $\tau = 0.24$ | Acc: 88.73% \| Prec: 73.60% \| Rec: 45.92% \| F1: 0.5655 | Specificity: 99.42% (FPR: 0.58%) | 32.39% |

### Key Generalization Finding:
Candidate A (`Calibrated_LinearSVC`) significantly outperforms Logistic Regression and SGD on external generalization (TREC F1 of **0.6472** vs. **0.6074** for Balanced LR and **0.5893** for Standard LR).

---

## 6. Single-Pass Held-Out Test Evaluation

The winning architecture (`Calibrated_LinearSVC`) was evaluated **exactly once** on the untouched 4,368-sample test partition:

| Metric | Selected Candidate (@ $\tau = 0.48$) | Baseline Reproduction (@ $\tau = 0.36$) | Documented v1.0.0 Production |
|---|---|---|---|
| **Accuracy** | **99.57%** | 99.45% | 99.59% |
| **Balanced Accuracy** | **98.79%** | 99.04% | 98.93% |
| **Precision** | **99.37%** | 97.86% | 99.22% |
| **Recall (Sensitivity)** | **97.69%** | 98.46% | 98.00% |
| **Specificity** | **99.89%** | 99.62% | 99.87% |
| **False Positive Rate** | **0.11%** (4 FPs / 3,719) | 0.38% (14 FPs / 3,719) | 0.13% (5 FPs / 3,719) |
| **F1 Score** | **98.52%** | 98.16% | 98.60% |
| **ROC-AUC** | **0.9981** | 0.9981 | 0.9987 |
| **PR-AUC** | **0.9944** | 0.9944 | 0.9964 |

### Final Test Confusion Matrix (@ $\tau = 0.48$):
$$\begin{array}{c|cc}
& \textbf{Pred Benign (0)} & \textbf{Pred Threat (1)} \\
\hline
\textbf{True Benign (0)} & 3715\text{ (TN)} & 4\text{ (FP)} \\
\textbf{True Threat (1)} & 15\text{ (FN)} & 634\text{ (TP)} \\
\end{array}$$

---

## 7. Latency & Resource Utilization

| Architecture | Model Checkpoint Size | Inference Latency (CPU) | Throughput (est.) |
|---|---|---|---|
| **Calibrated LinearSVC** | 602 KB | **0.432 ms / sample** | ~2,310 emails / sec |
| **Balanced Logistic Regression** | 201 KB | **0.311 ms / sample** | ~3,215 emails / sec |
| **Standard L2 Logistic Regression**| 201 KB | **0.348 ms / sample** | ~2,875 emails / sec |
| **SGD LogLoss Classifier** | 201 KB | **0.318 ms / sample** | ~3,140 emails / sec |

All candidate linear models demonstrate sub-millisecond per-sample inference latency on standard CPU hardware.

---

## 8. Reproducibility Verification

The selected candidate model was trained and evaluated in two independent passes with fixed seed `42`:
- `Predictions Identical`: **`True`** (4,368 / 4,368 test predictions match identically).
- `Probabilities Identical`: **`True`** (Within floating-point precision tolerance $\le 10^{-7}$).
- `Vocabulary Hash`: `5464be9f620df683b98671de1f222b7244784b438cb47b6652b539612c032ce0`

---

## 9. Final Model Decision & Recommendation

### Recommendation: **KEEP v1.0.0 (NO MODEL REPLACEMENT)**

#### Evidence & Rationale:
1. **No Meaningful Advantage from Alternative Architectures:** Neither Balanced Logistic Regression, Standard L2 Logistic Regression, nor SGDClassifier demonstrated a statistically meaningful improvement over the Calibrated LinearSVC baseline. In fact, all alternatives exhibited noticeably degraded generalization performance on external benchmark distributions (TREC 2007 F1 drop of $-4.0\%$ to $-8.2\%$).
2. **Threshold Stability:** While $\tau = 0.48$ achieves slightly higher precision (99.37% vs 97.86%) and lower FPR on the test set, the frozen production threshold $\tau = 0.36$ provides higher recall on subtle social engineering and credential lures (98.46% vs 97.69%) while maintaining an exceptionally low corporate false positive rate ($0.38\%$).
3. **Production Stability:** Replacing a verified production baseline is only justified when a concrete, significant operational improvement is proven across both in-source and cross-source benchmarks.
4. **Conclusion:** Production `v1.0.0` remains the optimal, mathematically supported champion model.

---

```text
PHASE 2 STEP 4 STATUS: COMPLETE (CHAMPION RETAINED: v1.0.0)
```
