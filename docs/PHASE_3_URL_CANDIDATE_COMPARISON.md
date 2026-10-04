# PHASE 3 — MALICIOUS URL CANDIDATE MODEL TRAINING & COMPARISON REPORT
**CYBERGUARD Machine Learning Workstream**  
**Document Version:** 1.0.0  
**Status:** COMPLETE (STEP 3 CANDIDATE COMPARISON)  
**Date:** 2026-10-04  
**Experiment Artifact Directory:** `services/ml-service/experiments/url_exp_20261004_085643/`  

---

## 1. Executive Summary & Objective

In **Phase 3 — Step 3**, a controlled comparative benchmark of four candidate URL threat classifiers was conducted against the frozen production Malicious URL Classifier v1.0.0 baseline.

All candidates were trained strictly on the designated Train partition (100,627 samples across 41,756 domains) using the identical 16 dense lexical and structural features. Model selection and operating threshold sweeps were performed strictly on the domain-disjoint Validation partition (16,492 samples across 5,218 unseen domains) under the strict production false positive constraint ($\text{FPR} \le 5.0\%$). Finally, all candidates were evaluated on the untouched held-out Test partition (8,720 samples across 5,219 unseen domains).

### Key Finding:
**NO MEANINGFUL IMPROVEMENT.** The existing production v1.0.0 architecture (`HistGradientBoostingClassifier`, $\tau = 0.74$) remains the champion. Candidate D (Tuned HGB) showed negligible metric shifts (+0.04% F1, identical 122 false positives) at the expense of a 92% larger model size, while Random Forest was 10x slower with elevated unseen-domain false positive rates, and Logistic Regression failed convergence. Therefore, **no model promotion is justified**, and production v1.0.0 is retained intact.

---

## 2. Frozen Baseline Reference (v1.0.0)

- **Model Class:** `sklearn.ensemble.HistGradientBoostingClassifier`
- **Feature Set:** 16 dense lexical/structural features (`URL_FEATURE_COLUMNS`)
- **Operating Threshold:** $\tau = 0.74$
- **Production Artifact:** [`services/ml-service/app/models/url/malicious_url_classifier_v1.0.0.joblib`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/app/models/url/malicious_url_classifier_v1.0.0.joblib)
- **Documented Benchmark Metrics (Test, 5,219 Unseen Domains):**
  - Accuracy: 85.99%
  - Balanced Accuracy: 87.88%
  - Precision: 97.19%
  - Recall (Sensitivity): 79.35%
  - Specificity: 96.41%
  - F1 Score: 87.37%
  - ROC-AUC: 0.9635
  - PR-AUC: 0.9767
  - False Positive Rate (FPR): 3.59%
  - Confusion Matrix: $\text{TN}=3,272, \quad \text{FP}=122, \quad \text{FN}=1,100, \quad \text{TP}=4,226$

---

## 3. Candidate Model Architectures & Configurations

Four candidate architectures were trained and evaluated:

| Candidate ID | Model Architecture | Hyperparameters & Configuration | Rationale |
|:---|:---|:---|:---|
| **Candidate A** | `HistGradientBoostingClassifier` | `max_iter=150`, `lr=0.1`, `max_leaf_nodes=31`, `min_samples_leaf=20`, `class_weight='balanced'`, `random_state=42` | Baseline control architecture inside candidate harness |
| **Candidate B** | `RandomForestClassifier` | `n_estimators=100`, `max_depth=16`, `min_samples_split=5`, `class_weight='balanced'`, `n_jobs=-1`, `random_state=42` | Bagging ensemble baseline for decision variance reduction |
| **Candidate C** | `LogisticRegression` | `max_iter=1000`, `C=1.0`, `class_weight='balanced'`, `solver='lbfgs'`, `random_state=42` | Fast linear baseline (interpretable, low-latency reference) |
| **Candidate D** | `HistGradientBoostingClassifier` (Tuned) | `max_iter=200`, `lr=0.08`, `max_leaf_nodes=45`, `min_samples_leaf=15`, `l2_regularization=0.5`, `class_weight='balanced'`, `random_state=42` | Deeper gradient boosting trees with L2 regularized leaf nodes |

---

## 4. Validation Comparison & Threshold Calibration

Threshold sweeps were conducted across 61 candidate thresholds in $[0.20, 0.80]$ on the domain-disjoint Validation partition (16,492 samples, 5,218 unseen domains). Threshold selection strictly enforced $\text{FPR} \le 5.0\%$ while maximizing $F_1 + 0.1 \times \text{Recall}$:

| Candidate | Fit Time | Selected $\tau$ | Accuracy | Bal. Acc. | Precision | Recall | F1 Score | ROC-AUC | PR-AUC | Benign FPR |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Candidate A (HGB Baseline)** | 8.35s | **0.78** | 84.17% | 87.13% | 97.26% | 79.08% | 87.23% | **0.9432** | **0.9740** | 4.81% |
| **Candidate B (Random Forest)** | 2.51s | **0.70** | 65.66% | 73.69% | 96.17% | 51.85% | 67.37% | 0.8994 | 0.9505 | 4.47% |
| **Candidate C (Logistic Reg.)** | 4.54s | **0.50** | 62.12% | 66.30% | 84.18% | 54.94% | 66.49% | 0.7393 | 0.8441 | 22.35% |
| **Candidate D (Tuned HGB)** | 2.71s | **0.76** | **84.91%** | **87.70%** | **97.35%** | **80.11%** | **87.89%** | 0.9422 | 0.9727 | 4.72% |

### Validation Observations:
1. **Candidate C (Logistic Regression)** suffered convergence warnings even at `max_iter=1000` due to unscaled multi-modal lexical features (e.g. `url_length` in $[10, 500]$ vs. binary flags in $\{0, 1\}$). Its validation FPR was an unacceptable 22.35%.
2. **Candidate B (Random Forest)** suffered severe under-recall ($51.85\%$) when constrained to $\text{FPR} \le 5.0\%$ on unseen validation domains.
3. **Candidate D (Tuned HGB)** achieved the highest validation F1 score (87.89%) with balanced recall (80.11%) at $\tau = 0.76$.

---

## 5. Unseen-Domain Generalization Analysis

URL classification requires robust generalization across previously unseen domain names. The table below details domain-level performance on the Validation (5,218 unseen domains) and Test (5,219 unseen domains) partitions:

| Candidate | Val Benign Domain FPR | Val Malicious Domain TPR | Test Benign Domain FPR | Test Malicious Domain TPR |
|:---|:---:|:---:|:---:|:---:|
| **Candidate A (HGB Baseline)** | **8.89%** (106/1,192) | 79.01% (3,181/4,026) | **7.51%** (85/1,132) | 78.44% (3,206/4,087) |
| **Candidate B (Random Forest)** | 12.25% (146/1,192) | 82.79% (3,333/4,026) | 10.78% (122/1,132) | 83.07% (3,395/4,087) |
| **Candidate C (Logistic Reg.)** | 43.04% (513/1,192) | 88.97% (3,582/4,026) | 42.14% (477/1,132) | 87.25% (3,566/4,087) |
| **Candidate D (Tuned HGB)** | 9.48% (113/1,192) | **81.20%** (3,269/4,026) | 8.57% (97/1,132) | **80.89%** (3,306/4,087) |

- **Key Takeaway:** Candidate A exhibited the lowest false positive rate on unseen benign domains (7.51% on test), while Random Forest and Logistic Regression suffered excessive false alarms on legitimate unseen infrastructure.

---

## 6. Single-Pass Held-Out Test Evaluation (5,219 Unseen Domains)

With thresholds frozen from validation, all candidates were evaluated once on the untouched held-out Test partition (8,720 samples across 5,219 unseen domains):

| Metric | Production v1.0.0 Ref | Candidate A (HGB) | Candidate B (RF) | Candidate C (LR) | Candidate D (Tuned HGB) |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Operating Threshold ($\tau$)** | 0.74 | 0.78 | 0.70 | 0.50 | 0.76 |
| **Accuracy** | 85.99% | 84.84% | 86.25% | 80.69% | **86.03%** |
| **Balanced Accuracy** | 87.88% | 87.04% | 87.82% | 79.53% | **87.91%** |
| **Precision** | 97.19% | 97.58% | 96.13% | 83.80% | **97.20%** |
| **Recall (Sensitivity)** | 79.35% | 77.09% | 80.74% | 84.77% | **79.42%** |
| **Specificity** | 96.41% | 96.99% | 94.90% | 74.28% | **96.41%** |
| **F1 Score** | 87.37% | 86.13% | 87.76% | 84.28% | **87.41%** |
| **ROC-AUC** | **0.9635** | 0.9617 | 0.9626 | 0.8702 | 0.9632 |
| **PR-AUC** | **0.9767** | 0.9758 | 0.9765 | 0.9082 | 0.9766 |
| **False Positive Rate (FPR)** | 3.59% | **3.01%** | 5.10% | 25.72% | **3.59%** |
| **Confusion Matrix (TN / FP / FN / TP)**| 3272 / 122 / 1100 / 4226 | 3292 / 102 / 1220 / 4106 | 3221 / 173 / 1026 / 4300 | 2521 / 873 / 811 / 4515 | 3272 / 122 / 1096 / 4230 |

---

## 7. Comparative Analysis: Baseline vs. Candidates

### 1. Candidate D (Tuned HGB) vs. Production Baseline v1.0.0:
- Accuracy: 86.03% vs 85.99% ($\Delta = +0.04\%$)
- F1 Score: 87.41% vs 87.37% ($\Delta = +0.04\%$)
- ROC-AUC: 0.9632 vs 0.9635 ($\Delta = -0.0003$)
- Confusion Matrix: Exactly 3,272 True Negatives and 122 False Positives (identical false alarm count to production v1.0.0 reference). True Positives increased by +4 (4,230 vs 4,226), False Negatives decreased by -4 (1,096 vs 1,100).
- **Assessment:** The metric shift is within statistical margin of error ($\le 0.04\%$). It does not represent a meaningful structural improvement.

### 2. Candidate B (Random Forest) vs. Production Baseline:
- Random Forest achieved F1 = 87.76% on test, but suffered:
  - 173 False Positives on test (vs. 122 for v1.0.0, a +41.8% increase in false alarms).
  - Unseen benign domain FPR exceeded 10.78% (vs. 7.51% for HGB).
  - Inference latency of **30.29 ms** (vs. 3.27 ms for HGB, **9.3x slower**).
  - Model disk size of **7.34 MB** (vs. 235 KB for HGB, **31x larger**).

### 3. Candidate C (Logistic Regression):
- Failed due to severe feature scale disparity without non-linear interaction modeling ($\text{ROC-AUC} = 0.8702$, $\text{FPR} = 25.72\%$).

---

## 8. Latency & Resource Footprint Benchmark

| Model Candidate | Single-URL Latency ($\mu\text{s}$) | Relative Latency | Model Size (KB) | Memory Footprint |
|:---|:---:|:---:|:---:|:---:|
| **Candidate A (HGB Baseline)** | **3,270.1 $\mu\text{s}$** (3.27 ms) | 1.0x (Baseline) | **235.1 KB** | Minimal |
| **Candidate B (Random Forest)** | 30,294.1 $\mu\text{s}$ (30.29 ms) | 9.3x slower | 7,340.5 KB (7.3 MB) | Heavy |
| **Candidate C (Logistic Reg.)** | 883.6 $\mu\text{s}$ (0.88 ms) | 0.27x | 0.93 KB | Negligible |
| **Candidate D (Tuned HGB)** | 3,139.5 $\mu\text{s}$ (3.14 ms) | 0.96x | 450.9 KB | Minimal |

---

## 9. Reproducibility & Determinism Verification

Candidate D was subjected to an independent re-training determinism pass with `random_state=42`:
- **Max Probability Difference:** `0.000000`
- **Prediction Matches:** 8,720 / 8,720 (100.0%)
- **Test Probability Vector SHA-256:**  
  `41417772bc089a65ecf60175ee752c5c5f475731f8c0ca48d816e1834c2b0639`
- **Determinism Status:** **PASS**

---

## 10. Decision & Model Promotion Evaluation

In accordance with Section 9 of the Phase 3 protocol:
> *"The baseline is considered strong if candidates do not demonstrate a meaningful improvement. If no candidate clearly improves the baseline, report: NO MEANINGFUL IMPROVEMENT."*

### Recommendation:
**NO MEANINGFUL IMPROVEMENT.**  
The marginal $\Delta F_1 = +0.04\%$ achieved by Candidate D is well within stochastic variance and does not justify deprecating the audited, validated production v1.0.0 model. Furthermore, Candidate D requires 200 trees (doubling model size to 450 KB) while maintaining identical true negative and false positive rates (3,272 TN, 122 FP).

**The production Malicious URL Classifier v1.0.0 is retained as the definitive champion.**

---

## 11. Files Created / Modified

- **Created:**
  - [`services/ml-service/scripts/train_url_candidate.py`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/scripts/train_url_candidate.py) (candidate evaluation pipeline)
  - [`services/ml-service/experiments/url_exp_20261004_085643/`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/experiments/url_exp_20261004_085643/) (isolated experiment artifacts & JSON report)
  - [`docs/PHASE_3_URL_CANDIDATE_COMPARISON.md`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/docs/PHASE_3_URL_CANDIDATE_COMPARISON.md) (Step 3 deliverable)
- **Modified:** None (Production files strictly preserved).

---

## 12. Test Safety & Suite Status

1. **Focused URL Tests:**
   - Command: `pytest services/ml-service/tests/ -k url -q`
   - Result: **56 passed, 174 deselected in 15.02s (100% PASS)**
2. **Full ML Service Regression Suite:**
   - Command: `pytest services/ml-service/tests/ -q`
   - Result: **230 passed in 32.55s (100% PASS)**

---

## 13. Conclusion & Step 3 Gating Status

Phase 3 — Step 3 has concluded with a decisive finding: **no candidate demonstrates a meaningful, statistically significant improvement over the production v1.0.0 Malicious URL baseline**. The baseline v1.0.0 remains the frozen champion model.

**PHASE 3 STEP 3 STATUS: PASS**
