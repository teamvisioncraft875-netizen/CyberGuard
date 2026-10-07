# CYBERGUARD — Phase 11 Visual Deepfake V3 Final Evaluation Report
**Scope:** AI/ML Service (`services/ml-service/`) — Visual Deepfake Detection Engine  
**Date:** October 6, 2026  
**Final Status:** V3 REJECTED — V1 RETAINED (FINAL DEEPFAKE ENGINE FREEZE)

---

## 1. Executive Decision

**Decision:** **`V3 REJECTED — V1 RETAINED`**

### Definitive Justification
1. **Target Gate Criteria Not Met:** Neither candidate achieved the required promotion gates (Recall $\ge 70\%$, Balanced Accuracy $\ge 75\%$, $\text{F1} \ge 0.78$, $\text{FPR} \le 20\%$).
2. **Degraded Balanced Accuracy:** On the validation split, all new candidates exhibited lower balanced accuracy than production V1 ($74.35\%$): Candidate A ($74.09\%$), Candidate B ($73.75\%$), and Candidate C ($73.37\%$).
3. **Disproportionate False-Alarm Surge:** On the untouched frozen test partition ($N = 2,242$), Candidate A yielded only a $+1.44\%$ recall gain while increasing FPR from $13.81\%$ to $15.48\%$ and dropping balanced accuracy to $74.24\%$. Candidate B increased false alarms by $+30.3\%$ ($43$ false positives vs $33$ in V1, $\text{FPR}=17.99\%$) while actually achieving lower ROC-AUC ($0.7945$ vs $0.7966$).
4. **Strict Stop Condition:** In accordance with the explicit protocol, no further experimental iterations (no V4, no additional architectures) are permitted. Visual V1 (`AttentionPoolingVisualDetector`, threshold $0.6400$) is definitively retained and frozen in production.

---

## 2. V1 Production Baseline

| Metric | Validation ($N = 2,241$) | Frozen Test ($N = 2,242$) |
| :--- | :--- | :--- |
| **Accuracy** | 65.06% | 65.03% |
| **Balanced Accuracy** | 74.35% | 74.35% |
| **Recall (Sensitivity)** | 62.56% | 62.51% |
| **Specificity** | 86.13% | 86.19% |
| **Precision** | 97.43% | 97.43% |
| **False Positive Rate (FPR)** | 13.87% | 13.81% |
| **F1 Score** | 0.7619 | 0.7616 |
| **ROC-AUC** | 0.7935 | 0.7966 |
| **PR-AUC** | 0.9721 | 0.9722 |
| **Confusion Matrix** | $\text{TN}=205, \text{FP}=33, \text{FN}=750, \text{TP}=1253$ | $\text{TN}=206, \text{FP}=33, \text{FN}=751, \text{TP}=1252$ |

- **Operating Threshold:** `0.6400`
- **Artifact:** `services/ml-service/app/models/deepfake_visual_classifier.pt`
- **SHA-256:** `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3`

---

## 3. V3 Candidates Explored

Three lightweight, targeted candidates were developed and trained exclusively on the training partition ($10,458$ samples):

1. **Candidate A (Robust Temporal Statistical Pooling):**
   - Concatenates global temporal mean, standard deviation, max-pooling, and learned frame attention weights ($4 \times 1024 = 4096$ dims) projected into a regularized LayerNorm MLP classifier.
2. **Candidate B (Balanced Mean + Attention Fusion):**
   - Fuses global temporal mean and learned attention ($2048$ dims) through LayerNorm, GELU activations, and class-balanced weighting ($w=0.40$).
3. **Candidate C (Temporal Conv + Attention with Frame Noise):**
   - 1D temporal convolution kernel over the sequence followed by dual pooling and mild embedding noise augmentation ($\sigma=0.01$).

---

## 4. Validation Split Evaluation ($N = 2,241$)

Thresholds were calibrated strictly on validation data to maximize balanced accuracy while enforcing $\text{FPR} \le 20\%$:

| Candidate | Selected Thresh | Recall | Specificity | Balanced Acc | F1 | FPR | ROC-AUC | PR-AUC | Parameters | Size (MB) | Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Production V1** | **0.6400** | **62.56%** | **86.13%** | **74.35%** | **0.7619** | **13.87%** | **0.7935** | **0.9721** | **410,882** | **1.57 MB** | **0.46 ms** |
| **Candidate A** | 0.7900 | 64.15% | 84.03% | 74.09% | 0.7727 | 15.97% | 0.8091 | 0.9742 | 2,378,498 | 9.08 MB | 2.63 ms |
| **Candidate B** | 0.8000 | 67.25% | 80.25% | 73.75% | 0.7931 | 19.75% | 0.7961 | 0.9726 | 677,122 | 2.59 MB | 0.44 ms |
| **Candidate C** | 0.7900 | 64.80% | 81.93% | 73.37% | 0.7763 | 18.07% | 0.7943 | 0.9721 | 935,810 | 3.58 MB | 1.13 ms |

**Target Gate Check:**
- Candidate A: Recall $64.15\% < 70\%$ (FAIL), Balanced Acc $74.09\% < 75\%$ (FAIL).
- Candidate B: Recall $67.25\% < 70\%$ (FAIL), Balanced Acc $73.75\% < 75\%$ (FAIL).
- Candidate C: Recall $64.80\% < 70\%$ (FAIL), Balanced Acc $73.37\% < 75\%$ (FAIL).

---

## 5. Frozen-Test Evaluation ($N = 2,242$)

Evaluated once with thresholds frozen from validation:

| Metric | Production V1 | Candidate A | Candidate B | Delta (A vs V1) | Delta (B vs V1) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Threshold** | 0.6400 | 0.7900 | 0.8000 | — | — |
| **Accuracy** | 65.03% | 66.15% | 67.26% | +1.12% | +2.23% |
| **Balanced Accuracy** | **74.35%** | 74.24% | 73.76% | **-0.11%** | **-0.59%** |
| **Recall (Sensitivity)** | 62.51% | 63.95% | 65.50% | +1.44% | +2.99% |
| **Specificity** | **86.19%** | 84.52% | 82.01% | -1.67% | **-4.18%** |
| **Precision** | 97.43% | 97.19% | 96.83% | -0.24% | -0.60% |
| **FPR** | **13.81%** | 15.48% | 17.99% | +1.67% | **+4.18%** |
| **F1 Score** | 0.7616 | 0.7715 | 0.7814 | +0.0099 | +0.0198 |
| **ROC-AUC** | 0.7966 | 0.8078 | 0.7945 | +0.0112 | -0.0021 |
| **PR-AUC** | 0.9722 | 0.9738 | 0.9720 | +0.0016 | -0.0002 |

---

## 6. Confusion Matrices on Frozen Test

```
Production V1 (Threshold 0.6400):
                 Predicted Real    Predicted Fake
Actual Real            206                33     (FPR = 13.81%)
Actual Fake            751              1252     (Recall = 62.51%)

Candidate A (Threshold 0.7900):
                 Predicted Real    Predicted Fake
Actual Real            202                37     (FPR = 15.48%)
Actual Fake            722              1281     (Recall = 63.95%)

Candidate B (Threshold 0.8000):
                 Predicted Real    Predicted Fake
Actual Real            196                43     (FPR = 17.99%)
Actual Fake            691              1312     (Recall = 65.50%)
```

---

## 7. Model Characteristics & Latency (Production V1)

- **Architecture:** `AttentionPoolingVisualDetector`
- **Parameter Count:** 410,882 parameters
- **Artifact Size:** 1,647,761 bytes (1.57 MB)
- **Mean Inference Latency:** `0.4626 ms` (CPU single-worker, batch=1)
  - **Median (p50):** `0.4473 ms`
  - **p95:** `0.5761 ms`
  - **p99:** `0.6944 ms`

---

## 8. Data Leakage & Integrity Verification

1. **Split Independence:**
   - Zero hash collisions ($\text{SHA-256}$) across Train, Validation, and Test embeddings.
   - Overlap Train-Val: `0`
   - Overlap Train-Test: `0`
   - Overlap Val-Test: `0`
2. **Feature Integrity:**
   - Zero NaN or Inf values detected in any split.
3. **No Test-Time Optimization:**
   - Thresholds and model choices were locked prior to the single frozen-test evaluation.

---

## 9. Security Verification

- **Payload Size Limits:** 10 MB strict file size ceiling enforced.
- **Short Payload Protection:** Inputs $<32$ bytes safely rejected with HTTP 400.
- **SSRF Defenses:** Loopback and private IP URLs prohibited.
- **Local Model Loading:** Weights loaded exclusively from internal application paths; zero arbitrary path loading.
- **Process Safety:** Zero subprocess execution.

---

## 10. Regression Test Verification

- **Targeted Visual & Media Tests:** 47 / 47 passing (`test_dfdc_visual_engine.py`, `test_media_engine.py`, `test_media_validation.py`).
- **Production Model Integrity:** 5 / 5 models verified with exact SHA-256 match.
- **Full ML Test Suite:** **230 / 230 tests passing**.

---

## 11. Artifact Hashes & Rollback Metadata

| Component | Status | Artifact Path | SHA-256 |
| :--- | :--- | :--- | :--- |
| **Visual Production (V1)** | **ACTIVE** | `services/ml-service/app/models/deepfake_visual_classifier.pt` | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` |
| **Visual Rollback (Bak V1)** | BACKUP | `services/ml-service/app/models/deepfake_visual_classifier.pt.bak_v1` | `708f535123e7cd42182be038f3ad4d37bc82b6bb05cdeb6e5402eb5784a058ed` |
| **Audio Production (V2)** | **ACTIVE** | `services/ml-service/app/models/deepfake_audio_classifier.joblib` | `452577e565da60e89dbe5be6c7dcca5eefe89f8b1d8154ca759c8643e7d778ca` |
| **Audio Rollback (Bak V1)** | BACKUP | `services/ml-service/app/models/deepfake_audio_classifier.joblib.bak_v1` | `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7` |

---

## 12. Known Limitations & Final Recommendation

1. **Visual Recall Boundary:**
   - Production Visual V1 has a known recall ceiling of ~62.5% on DFDC benchmark sequences due to subtle, low-frequency frame-level face blend manipulations that do not significantly perturb high-level CLIP embeddings.
   - Specificity ($86.19\%$) and precision ($97.43\%$) remain high, preventing excessive false positives.
2. **Definitive Freeze:**
   - Both Visual V1 and Audio V2 are production-frozen. No further model training or threshold tuning should occur.
