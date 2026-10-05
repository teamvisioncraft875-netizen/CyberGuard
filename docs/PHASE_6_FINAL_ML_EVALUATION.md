# CYBERGUARD — Phase 6: Final Cross-Engine Machine Learning Evaluation & Comparison Report

**Document Status:** Complete & Authoritative  
**Date:** October 4, 2026  
**Audited Engines:**
1. Phishing & Social Engineering Detection Engine
2. Malicious URL Detection Engine
3. Static PE Malware Detection Engine
4. Visual Deepfake Detection Engine
5. Audio Deepfake & Voice Cloning Engine

---

## 1. Executive Summary

Phase 6 synthesizes the complete, end-to-end machine learning engineering and scientific validation across all threat detection engines in the **CYBERGUARD** cybersecurity platform. 

Every model evaluated in this cross-engine benchmark was trained, tuned, and tested under strict enterprise protocols:
- **Zero Synthetic Data:** Every single training and evaluation record corresponds to authentic, real-world cyber threats and legitimate enterprise traffic. Zero synthetic, perturbed, or fabricated samples were introduced.
- **Strict Data Freeze & Partition Isolation:** The final test partitions remained strictly held out and untouched during feature extraction, candidate exploration, and decision threshold calibration. Thresholds were selected exclusively on validation data.
- **Enterprise-Grade Verification:** 100% test pass rate across the full test suite (**230 / 230 tests passed** in `services/ml-service/tests/`), confirming zero cross-engine regressions.

---

## 2. Project Scope & Architecture Boundary

The in-scope machine learning stack operates as an autonomous microservice (`services/ml-service/app/`) integrated into CYBERGUARD via the Node.js / Express API Gateway (`services/backend/`).

### In-Scope Engines:
1. **Phishing Engine:** Real-time semantic and lexical analysis of incoming emails, SMS messages, and social engineering lures.
2. **Malicious URL Engine:** Deep lexical, structural, and brand-impersonation analysis of website links and suspicious domains.
3. **Malware Engine:** High-throughput 2,381-dimensional static Windows PE binary inspection.
4. **Media Engine (Visual Deepfake):** Multi-frame temporal attention pooling on CLIP ViT-H/14 embeddings combined with 2D Fast Fourier Transform (FFT) periodic spectral peak detection.
5. **Media Engine (Audio Deepfake):** 16 kHz standardized acoustic spectral, jitter, and neural vocoder cutoff inspection.

### Explicit Out-of-Scope Components:
- **Secret Detection Engine:** Evaluated as backend rule-based security logic, not ML.
- **Network / Login / System Anomaly Engines:** Retained in production; out of current ML candidate exploration scope.
- **Frontend Applications:** `apps/web` and `apps/mobile` interfaces.

---

## 3. Dataset Provenance & Split Isolation

| Engine | Dataset Sources | Clean Sample Count | Partition Split Strategy | Target Threat Class |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing** | Nazario, Nigerian Fraud, CEAS 08, Enron, SpamAssassin | 43,680 clean emails | 80/10/10 Stratified Split (34,944 Train / 4,368 Val / 4,368 Test) | Targeted credential lures, CEO fraud, social engineering |
| **Malicious URL** | URLHaus, OpenPhish, PhishTank, Alexa/Tranco, Corporate Mail | 125,839 clean URLs | Domain-aware `GroupShuffleSplit` (100,627 Train / 16,492 Val / 8,720 Test; **0 domain overlap**) | Typosquatting, look-alike domains, credential phishing |
| **Malware** | EMBER 2018 v2 Official Benchmark | 800,000 genuine PE records | 80/20 Stratified Split on 600k labeled (480,000 Train / 120,000 Val) + **200,000 Official Held-Out Test Set** | Ransomware, trojans, worms, malicious Windows binaries |
| **Deepfake Visual** | DFDC Shield 2026 (DFDC-10 + FaceForensics++ C23 + Celeb-DF v2) | 14,941 video sequences ($20 \times 1024$ CLIP ViT) | Pre-stratified benchmark split (10,458 Train / 2,241 Val / 2,242 Test; **0 vector overlap**) | Facial manipulation, generative AI face swaps, deepfakes |
| **Deepfake Audio** | Curated Deepfake Audio Benchmark | 240 standardized audio recordings | Source-Disjoint Split across 87 unique speaker identities (140 Train / 50 Val / 50 Test; **0 source overlap**) | Voice cloning, text-to-speech fraud, synthetic audio |

---

## 4. Production Model Inventory & Artifact Registry

| Engine | Production Model Artifact | Architecture | File Size | SHA-256 Checksum | Operating Threshold |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phishing** | `app/models/phishing/phishing_classifier_v1.0.0.joblib` | Calibrated `LinearSVC` + TF-IDF Vectorizer | 537,887 B (0.51 MB) | `0a3f4ce38a9df04d9b852752023014b31a9748beddf8da7c339ab15b4c97c72b` | $\tau = 0.3600$ |
| **Malicious URL** | `app/models/url/malicious_url_classifier_v1.0.0.joblib` | `HistGradientBoostingClassifier` | 241,046 B (0.23 MB) | `c657040891cb2ba4981ef56492713f8d2f5900e0721ad2c21424dfe17c9a6d12` | $\tau = 0.7400$ |
| **Malware** | `app/models/malware/ember_model_2018.txt` | LightGBM GBDT (1,000 trees, 1,024 leaves) | 97,563,714 B (93.04 MB) | `2efaf2366ec824020feb953a29f72dec287efc530280b607a38181865d78ae12` | $\tau = 0.5590$ |
| **Deepfake Visual** | `app/models/deepfake_visual_classifier.pt` | PyTorch `AttentionPoolingVisualDetector` | 1,647,761 B (1.57 MB) | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` | $\tau = 0.6400$ |
| **Deepfake Audio** | `app/models/deepfake_audio_classifier.joblib` | Scikit-learn `LogisticRegression` | 1,503 B (0.001 MB) | `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7` | $\tau = 0.5000$ |

---

## 5. Individual Engine Benchmark Results

### 5.1 Phishing & Social Engineering Detection Engine
- **Test Partition:** 4,368 held-out email/message texts (3,719 benign, 649 phishing).
- **Core Results ($\tau = 0.3600$):**
  - Accuracy: **99.59%**
  - Balanced Accuracy: **98.93%**
  - Precision: **99.22%**
  - Recall: **98.00%** (636 / 649 threats intercepted)
  - Specificity: **99.87%**
  - False Positive Rate: **0.13%** (5 false alarms out of 3,719 legitimate messages)
  - F1-Score: **0.9860** | ROC-AUC: **0.9987** | PR-AUC: **0.9964**
- **Sub-Cohort Resilience:** 97.44% recall on Nazario targeted attacks; 98.49% recall on advanced fraud; $<0.15\%$ FPR on clean Enron/SpamAssassin corporate email.

### 5.2 Malicious URL Detection Engine
- **Test Partition:** 8,720 held-out URLs across completely unseen domains (3,394 benign, 5,326 malicious).
- **Core Results ($\tau = 0.7400$):**
  - Accuracy: **85.99%**
  - Balanced Accuracy: **87.88%**
  - Precision: **97.19%**
  - Recall: **79.35%** (4,226 / 5,326 malicious URLs intercepted)
  - Specificity: **96.41%** (3,272 / 3,394 benign URLs verified)
  - False Positive Rate: **3.59%** (122 false alarms)
  - F1-Score: **0.8737** | ROC-AUC: **0.9635** | PR-AUC: **0.9767**
- **Domain Independence:** Enforces `GroupShuffleSplit`, guaranteeing that no second-level domain in the test set appeared in the training or validation splits.

### 5.3 Static PE Malware Detection Engine
- **Test Partition:** Official held-out EMBER 2018 test set (200,000 binaries: 100,000 benign, 100,000 malware).
- **Core Results ($\tau = 0.5590$):**
  - Accuracy: **97.623%**
  - Balanced Accuracy: **97.623%**
  - Precision: **98.155%**
  - Recall: **97.071%** (97,071 / 100,000 malware binaries intercepted)
  - Specificity: **98.175%** (98,175 / 100,000 legitimate binaries verified)
  - False Positive Rate: **1.825%** (1,825 false alarms out of 100,000)
  - F1-Score: **0.976098** | ROC-AUC: **0.99600224** | PR-AUC: **0.99659172**
- **Production Advantage:** Candidate B detected **+540 additional real malware samples** over the previous production model while reducing model disk storage from 121.39 MB down to 93.04 MB (-23.35%).

### 5.4 Visual Deepfake Detection Engine
- **Test Partition:** 2,242 held-out video frame sequences from DFDC Shield 2026 (239 genuine, 2,003 manipulated; 1:8.4 imbalance).
- **Core Results ($\tau = 0.6400$):**
  - Balanced Accuracy: **74.35%**
  - Overall Accuracy: **65.03%**
  - Precision: **97.43%**
  - Recall: **62.51%** (1,252 / 2,003 manipulated sequences detected)
  - Specificity: **86.19%** (206 / 239 genuine sequences verified)
  - False Positive Rate: **13.81%** (33 false alarms)
  - F1-Score: **0.7616** | ROC-AUC: **0.7966** | PR-AUC: **0.9722**
- **Temporal Attention:** Inspects multi-frame sequences to pinpoint isolated manipulation anomalies, backed by 2D FFT periodic spectral peak detection.

### 5.5 Audio Deepfake & Voice Cloning Engine
- **Test Partition:** 50 held-out 16 kHz audio recordings across 17 unseen human speaker identities (25 genuine, 25 manipulated).
- **Core Results ($\tau = 0.5000$):**
  - Accuracy: **72.00%**
  - Balanced Accuracy: **72.00%**
  - Precision: **72.00%**
  - Recall: **72.00%** (18 / 25 voice clones detected)
  - Specificity: **72.00%** (18 / 25 genuine speakers verified)
  - False Positive Rate: **28.00%** (7 false alarms)
  - F1-Score: **0.7200** | ROC-AUC: **0.7856** | PR-AUC: **0.8317**
- **Identity Generalization:** Evaluated strictly against zero-day speaker sources not present in training.

---

## 6. Unified Cross-Engine Comparison Table

### Table 1: Detection & Discrimination Efficacy
| Engine | Model Type | Evaluation Test Set | Accuracy | Balanced Accuracy | Precision | Recall | Specificity | FPR | F1-Score | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Phishing** | `LinearSVC` | 4,368 clean emails | **99.59%** | **98.93%** | **99.22%** | **98.00%** | **99.87%** | **0.13%** | **0.9860** | **0.9987** | **0.9964** |
| **Malicious URL** | `HistGradientBoosting` | 8,720 unseen-domain URLs | 85.99% | 87.88% | 97.19% | 79.35% | 96.41% | 3.59% | 0.8737 | 0.9635 | 0.9767 |
| **Malware** | LightGBM GBDT | 200,000 EMBER binaries | 97.62% | 97.62% | 98.15% | 97.07% | 98.18% | 1.83% | 0.9761 | 0.9960 | 0.9966 |
| **Deepfake Visual** | `AttentionPooling` + 2D FFT| 2,242 DFDC sequences | 65.03% | 74.35% | 97.43% | 62.51% | 86.19% | 13.81% | 0.7616 | 0.7966 | 0.9722 |
| **Deepfake Audio** | `LogisticRegression` (16k) | 50 unseen speaker files | 72.00% | 72.00% | 72.00% | 72.00% | 72.00% | 28.00% | 0.7200 | 0.7856 | 0.8317 |

### Table 2: Engineering & Operational Footprint
| Engine | Target Operating Threshold ($\tau$) | Test Sample Count | Class Balance (Neg : Pos) | Model Disk Size | Single-Sample Latency (Pure Model) | Full Pipeline Latency (With Preprocessing) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Phishing** | $\tau = 0.3600$ | 4,368 | $5.7 : 1$ | 0.51 MB | 0.42 ms | 2.51 ms (TF-IDF transform) |
| **Malicious URL** | $\tau = 0.7400$ | 8,720 | $1 : 1.6$ | 0.23 MB | 2.47 ms | 2.93 ms (Lexical feature extract) |
| **Malware** | $\tau = 0.5590$ | 200,000 | $1 : 1$ (Balanced) | 93.04 MB | 0.56 ms | 1.42 ms (PE feature parser) |
| **Deepfake Visual** | $\tau = 0.6400$ | 2,242 | $1 : 8.4$ (Imbalanced) | 1.57 MB | 0.59 ms | ~45.0 ms (2D FFT spectral analyzer) |
| **Deepfake Audio** | $\tau = 0.5000$ | 50 | $1 : 1$ (Balanced) | 1.50 KB | 0.08 ms | ~86.0 ms (16 kHz polyphase resample) |

---

## 7. Confusion Matrix Audit

Every confusion matrix was verified against its exact held-out test partition sum:

### 1. Phishing Engine ($N = 4,368$)
$$\text{TN} = 3,714, \quad \text{FP} = 5, \quad \text{FN} = 13, \quad \text{TP} = 636 \quad (\text{Sum} = 4,368)$$
- False discovery rate: 5 false alarms out of 641 total detections (0.78%).

### 2. Malicious URL Engine ($N = 8,720$)
$$\text{TN} = 3,272, \quad \text{FP} = 122, \quad \text{FN} = 1,100, \quad \text{TP} = 4,226 \quad (\text{Sum} = 8,720)$$
- Conservative threshold ($\tau = 0.74$) protects legitimate enterprise web browsing by enforcing 96.41% specificity.

### 3. Malware Engine ($N = 200,000$)
$$\text{TN} = 98,175, \quad \text{FP} = 1,825, \quad \text{FN} = 2,929, \quad \text{TP} = 97,071 \quad (\text{Sum} = 200,000)$$
- 97,071 malicious binaries intercepted out of 100,000 real malware samples ($97.07\%$ Recall).

### 4. Deepfake Visual Engine ($N = 2,242$)
$$\text{TN} = 206, \quad \text{FP} = 33, \quad \text{FN} = 751, \quad \text{TP} = 1,252 \quad (\text{Sum} = 2,242)$$
- Reflects the severe $1 : 8.4$ real-world class imbalance of the DFDC benchmark.

### 5. Deepfake Audio Engine ($N = 50$)
$$\text{TN} = 18, \quad \text{FP} = 7, \quad \text{FN} = 7, \quad \text{TP} = 18 \quad (\text{Sum} = 50)$$
- Exactly balanced evaluation across unseen speakers ($18+7+7+18 = 50$).

---

## 8. Model Quality & Engineering Interpretation

### Phishing Model (`LinearSVC`)
- **Strengths:** Outstanding text discrimination (99.87% ROC-AUC, 0.13% FPR). Highly resistant to false alarms in corporate communications.
- **Limitations:** Primarily evaluates textual content; obfuscated images containing embedded text require OCR preprocessing (handled via Media engine).

### Malicious URL Model (`HistGradientBoosting`)
- **Strengths:** Proven cross-domain generalizability (`GroupShuffleSplit` enforced 0 domain overlap). Fast 2.9 ms inference.
- **Limitations:** Domain-level lookups cannot inspect post-login or dynamic JavaScript DOM payloads without active crawler detonation.

### Malware Static PE Model (LightGBM GBDT)
- **Strengths:** State-of-the-art static PE detection (97.07% recall, 0.9960 ROC-AUC). Compact 93 MB footprint is 23.35% smaller than the original model.
- **Limitations:** Purely static analysis; heavily packed or memory-injected payloads require dynamic telemetry monitoring (handled via System Anomaly engine).

### Deepfake Visual Model (`AttentionPoolingVisualDetector`)
- **Strengths:** Multi-frame temporal attention pooling pinpoints brief, single-frame manipulation artifacts in video streams. Sub-millisecond neural inference.
- **Limitations:** Dataset consists of pre-extracted CLIP ViT embeddings. Novel diffusion architectures not represented in training can evade visual attention; mitigated by pairing with 2D FFT periodic spectral peak detection.

### Deepfake Audio Model (`LogisticRegression`)
- **Strengths:** Sampling-rate-invariant 16 kHz feature extraction. Verified generalization across 17 unseen speaker identities.
- **Limitations:** Small test partition (50 samples); should be expanded in Phase 7 as additional labeled multi-speaker benchmarks become publicly available.

---

## 9. Production-Readiness Assessment

| Engine | Readiness Status | Risk Rating | Operational Deployment Guidance |
| :--- | :--- | :--- | :--- |
| **Phishing** | **GREEN** | Low | Production-ready for automatic email/SMS quarantine and high-confidence alerting. |
| **Malicious URL** | **GREEN** | Low | Production-ready for web proxy filtering, browser extensions, and link reputation scoring. |
| **Malware** | **GREEN** | Low | Production-ready for endpoint detection (EDR), file upload screening, and quarantine. |
| **Deepfake Visual** | **YELLOW** | Medium | Deploy with hybrid scoring: combine model classification with 2D FFT periodic grid peak analysis. High-risk verdicts require manual SOC review. |
| **Deepfake Audio** | **YELLOW** | Medium | Deploy as an advisory biometric threat signal. Requires secondary out-of-band verification for executive wire transfer authorizations. |

---

## 10. Reproducibility & Integrity Audit

- **Bitwise / Deterministic Reproducibility:** Verified across independent passes for Malware ($\Delta = 0.0$), URL ($\Delta = 0.0$), Phishing ($\Delta = 0.0$), and Deepfake Visual ($\Delta = 0.0$).
- **Configuration & Seeds:** Fixed seed `42` utilized across all scikit-learn, LightGBM, and PyTorch components.
- **Artifact Checksums:** All SHA-256 hashes registered and verified in `docs/phase6_final_metrics.json`.
- **Dependency Environment:**
  - Python: `3.14.6`
  - PyTorch: `2.14.0+cu126` (CUDA active)
  - LightGBM: `4.7.0`
  - Scikit-Learn: `1.9.0`
  - Pillow: `12.3.0` | Scipy: `1.18.0` | SoundFile: `0.14.0`

---

## 11. Test-Suite Execution Status

All test suites executed against the final integrated models:
- **Focused Media Tests:** **47 / 47 PASSED** (`test_dfdc_visual_engine.py`, `test_media_engine.py`, `test_media_validation.py`)
- **Focused Malware Tests:** **11 / 11 PASSED** (`test_malware_engine.py`)
- **Full ML Microservice Suite:** **230 / 230 PASSED (100% pass rate in 39.57s)**
  - Zero failures, zero warnings-as-errors, zero cross-service regressions across all 28 test modules.
