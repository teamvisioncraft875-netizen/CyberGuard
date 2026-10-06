# CYBERGUARD — Final Machine Learning Production Readiness Statement

**Document Version:** 1.0.0-release-candidate  
**Date:** October 5, 2026  
**Status:** PRODUCTION FROZEN & PR READY  
**Classification:** Post-Phase-8 Production Consolidation  

---

## A. Production Model Inventory

CYBERGUARD operates five core machine learning threat detection models within the `services/ml-service` microservice, coordinated through the Node.js / Express API Gateway (`services/backend`):

1. **Phishing & Social Engineering Engine:** Real-time semantic and lexical evaluation of communications.
2. **Malicious URL Detection Engine:** GroupShuffleSplit domain-independent lexical and structural web analysis.
3. **Static PE Malware Detection Engine:** High-capacity 2,381-feature LightGBM GBDT binary classifier.
4. **Visual Deepfake Detection Engine:** Multi-frame temporal attention pooling on normalized CLIP ViT-B/16 embeddings.
5. **Audio Deepfake & Voice Cloning Engine:** Standardized 16 kHz acoustic and spectral forensic classifier.

---

## B. Model Versions & Architectures

| Engine | Version | Framework | Architecture | Runtime Loader |
|:---|:---|:---|:---|:---|
| **Phishing** | `v1.0.0` | scikit-learn | Calibrated `LinearSVC` + TF-IDF Vectorizer | `joblib.load` |
| **Malicious URL** | `v1.0.0` | scikit-learn | `HistGradientBoostingClassifier` | `joblib.load` |
| **Malware** | `v1.1.0` | LightGBM | LightGBM GBDT (1,000 trees, 1,024 leaves) | `lightgbm.Booster` |
| **Deepfake Visual** | `v1.0.0` | PyTorch | `AttentionPoolingVisualDetector` | `torch.load(..., weights_only=True)` |
| **Deepfake Audio** | `v2.0.0` | scikit-learn | `Pipeline(StandardScaler, MLPClassifier)` (28 forensic features) | `joblib.load` |

---

## C. Operating Decision Thresholds

All production decision thresholds were pre-calibrated strictly on held-out validation partitions to maximize balanced accuracy under enterprise false positive constraints:

| Engine | Operating Threshold ($\tau$) | Target Objective |
|:---|:---:|:---|
| **Phishing** | $\tau = 0.3600$ | Intercept credential harvesting lures; maintain corporate benign FPR $< 0.15\%$ |
| **Malicious URL** | $\tau = 0.7400$ | Strict brand protection; maintain benign domain FPR $\le 3.59\%$ |
| **Malware** | $\tau = 0.5590$ | Enterprise binary quarantine; intercept $>97\%$ malware at $\text{FPR} = 1.825\%$ |
| **Deepfake Visual** | $\tau = 0.6400$ | Temporal attention peak detection; maintain genuine video specificity $\ge 86\%$ |
| **Deepfake Audio** | $\tau = 0.4900$ | Unseen TTS vocoder anomaly boundary across standardized 16 kHz audio (28 features) |

---

## D. Cryptographic Checksums (SHA-256) & Artifact Paths

| Engine | Artifact Relative Path | File Size | Authoritative SHA-256 Checksum |
|:---|:---|:---:|:---|
| **Phishing** | `services/ml-service/app/models/phishing/phishing_classifier_v1.0.0.joblib` | 537,887 B | `0a3f4ce38a9df04d9b852752023014b31a9748beddf8da7c339ab15b4c97c72b` |
| **Phishing Vec** | `services/ml-service/app/models/phishing/phishing_vectorizer_v1.0.0.joblib` | 314,154 B | `58b6b929e4926acbbc6dd3d72d80276b3f2cbd57e1bb165adb59ccc69a34ddfe` |
| **Malicious URL** | `services/ml-service/app/models/url/malicious_url_classifier_v1.0.0.joblib` | 241,046 B | `c657040891cb2ba4981ef56492713f8d2f5900e0721ad2c21424dfe17c9a6d12` |
| **Malware** | `services/ml-service/app/models/malware/ember_model_2018.txt` | 97,563,714 B | `2efaf2366ec824020feb953a29f72dec287efc530280b607a38181865d78ae12` |
| **Deepfake Visual** | `services/ml-service/app/models/deepfake_visual_classifier.pt` | 1,647,761 B | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` |
| **Deepfake Audio** | `services/ml-service/app/models/deepfake_audio_classifier.joblib` | 140,193 B | `452577e565da60e89dbe5be6c7dcca5eefe89f8b1d8154ca759c8643e7d778ca` |

---

## E. Dataset Provenance & Evaluation Partitioning

| Engine | Source Datasets | Total Samples | Partitioning Strategy | Leakage Prevention |
|:---|:---|:---:|:---|:---|
| **Phishing** | Nazario, Nigerian Fraud, CEAS08, Enron, SpamAssassin | 43,680 | 80/10/10 Stratified Split | Exact body hash deduplication |
| **Malicious URL** | URLHaus, OpenPhish, PhishTank, Alexa/Tranco | 125,839 | GroupShuffleSplit by 2nd-level domain | 0 domain overlap across train/val/test |
| **Malware** | EMBER 2018 v2 Official Benchmark | 800,000 | 600k train/val + 200,000 official held-out test | Strict temporal hold-out |
| **Deepfake Visual** | DFDC Shield 2026 (DFDC, FF++ C23, Celeb-DF v2) | 14,941 | 10,458 train / 2,241 val / 2,242 test | 0 vector hash collision between train & val |
| **Deepfake Audio** | Curated Deepfake Audio Benchmark | 240 | 140 train / 50 val / 50 test | Source-disjoint (0 speaker overlap) |

---
## F. Final Production Benchmark Metrics (Frozen Test Gate)

| Metric | Phishing (v1.0.0) | Malicious URL (v1.0.0) | Malware (v1.1.0) | Deepfake Visual (v1.0.0) | Deepfake Audio (v2.0.0) |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Operating $\tau$** | 0.3600 | 0.7400 | 0.5590 | 0.6400 | 0.4900 |
| **Test Set Size** | 4,368 msgs | 8,720 URLs | 200,000 PEs | 2,242 sequences | 50 audio clips |
| **Accuracy** | **99.59%** | **85.99%** | **97.62%** | **65.03%** | **90.00%** |
| **Balanced Acc** | **98.93%** | **87.88%** | **97.62%** | **74.35%** | **90.00%** |
| **Precision** | **99.22%** | **97.19%** | **98.16%** | **97.43%** | **85.71%** |
| **Recall** | **98.00%** | **79.35%** | **97.07%** | **62.51%** | **96.00%** |
| **Specificity** | **99.87%** | **96.41%** | **98.18%** | **86.19%** | **84.00%** |
| **FPR** | **0.13%** | **3.59%** | **1.83%** | **13.81%** | **16.00%** |
| **F1 Score** | **0.9860** | **0.8737** | **0.9761** | **0.7616** | **0.9057** |
| **ROC-AUC** | **0.9987** | **0.9635** | **0.9960** | **0.7966** | **0.8976** |
| **PR-AUC** | **0.9964** | **0.9767** | **0.9966** | **0.9722** | **0.8761** |
| **Inference Latency** | 0.45 ms / msg | 0.18 ms / URL | 0.15 ms / sample | 0.59 ms / seq | 1.18 ms / clip |

---

## G. Known Limitations & Operational Considerations

1. **Phishing Engine:** High sensitivity to semantic fraud; prompt injection overrides implemented to prevent jailbreaking.
2. **Malicious URL Engine:** Lexical-only evaluation without live dynamic crawling; brand impersonation relies on curated lexical dictionaries.
3. **Malware Engine:** Static Windows PE analysis only; does not analyze ELF, Mach-O, scripts, or runtime execution behavior.
4. **Deepfake Visual Engine:** Operates on 20-frame CLIP ViT sequences; highly compressed social media videos and subtle lip-sync deepfakes may evade detection (62.51% recall on test set).
5. **Deepfake Audio Engine:** Evaluated on 240-clip benchmark across 17 unseen speakers; acoustic features remain sensitive to extreme microphone channel degradation.

---

## H. Phase 8, 9, 10 & 11 Decisions & Evidence Summary

1. **Visual Deepfake Improvement (Phase 8.2, Phase 9 & Phase 11 V3 Final Attempt):**
   - Phase 11 V3 evaluated three candidate architectures (Statistical Pooling, Balanced Mean+Attention, and Temporal Conv+Attention).
   - Candidate A achieved 63.95% Recall (+1.44% vs v1.0.0) with lower Balanced Accuracy (74.24% vs 74.35%) and higher FPR (15.48% vs 13.81%).
   - Candidate B achieved 65.50% Recall but suffered from a 30.3% surge in false alarms (FPR 17.99% vs 13.81%) and lower ROC-AUC (0.7945 vs 0.7966).
   - No candidate satisfied the required promotion gates (Recall >= 70%, Balanced Accuracy >= 75%, F1 >= 0.78, FPR <= 20%).
   - **Decision: V3 REJECTED — V1 RETAINED & FROZEN.** Production model strictly retained as `v1.0.0` (`AttentionPoolingVisualDetector`, $\tau = 0.6400$, SHA-256: `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3`).

2. **Audio Deepfake Improvement (Phase 9 & Phase 10 Hardening):**
   - Audio Candidate D / V2 (`Pipeline(StandardScaler, MLPClassifier)` with 28 features) achieved decisive gains on the frozen test partition (N=50 across 17 unseen speakers):
     - Accuracy: **90.00%** (+18.00% vs v1.0.0)
     - Recall: **96.00%** (+24.00% vs v1.0.0)
     - Specificity: **84.00%** (+12.00% vs v1.0.0; FPR dropped from 28% to 16%)
     - F1: **0.9057** (+0.1857 vs v1.0.0)
     - ROC-AUC: **0.8976** (+0.1120 vs v1.0.0)
   - **Decision: PROMOTED TO PRODUCTION (v2.0.0) & HARDENED.** Operating threshold $\tau = 0.4900$. Full promotion gates passed; verified rollback backup created (`deepfake_audio_classifier.joblib.bak_v1`).

---

## I. Production-Readiness Classification

| Engine | Tier | Assessment Rationale |
|:---|:---:|:---|
| **Phishing** | **GREEN** | World-class metrics (99.59% accuracy, 0.13% FPR, 0.9987 ROC-AUC); enterprise-ready. |
| **Malicious URL** | **GREEN** | Robust domain-independent generalization (0 domain leakage, 96.41% specificity, 0.9635 ROC-AUC). |
| **Malware** | **GREEN** | Validated on 200,000 official held-out EMBER binaries (97.62% accuracy, 1.83% FPR, 0.9960 ROC-AUC). |
| **Deepfake Visual** | **YELLOW** | Production-integrated and fully operational, but has known detection limitations (62.51% recall on DFDC benchmark). |
| **Deepfake Audio** | **GREEN** | Production-promoted (v2.0.0 MLP, 28 acoustic features, 90.00% accuracy, 96.00% recall, 84.00% specificity on unseen Kokoro/Hume AI test set). |

> *Note on YELLOW Classification:* YELLOW does **NOT** indicate a broken engine. Deepfake Visual is fully functional, loads successfully, passes 100% of integration and contract tests, and provides reliable baseline heuristics. YELLOW transparently signals that its generalization evidence is comparatively weaker than Phishing, URL, Malware, and Audio v2 engines.

---

## J. Security Boundaries & Guardrails

- **Zero Arbitrary Execution:** Zero dynamic code execution, subprocess invocations, or shell calls in ML inference pipelines.
- **Static PE Inspection:** Malware analysis is strictly static binary parsing using validated byte offsets.
- **Payload Boundaries:** Strict maximum file limits (10 MB malware payload, 25 MB media payload) prevent memory exhaustion DoS.
- **SSRF Protection:** `MediaDetectionEngine` enforces RFC 1918 private network blocking, loopback rejection, and AWS metadata IP (`169.254.169.254`) blocking.
- **Fail-Closed Malformed Input Handling:** Corrupt headers, truncated archives, and invalid data URIs safely return default safe/low-threat responses with explicit error signals.
- **Zero Committed Secrets:** Repository-wide audit verified 0 API keys, credentials, or private keys in the ML code tree.

---

## K. Test Suite Results

All test suites were executed on Python 3.14.6 in the production environment:

- **Complete ML Service Suite:** **230 passed in 45.59s** (100% pass, 0 failed, 0 regressions)
- **Media Engine Suite:** **47 passed in 15.85s** (100% pass)
- **Malware Engine Suite:** **11 passed in 9.64s** (100% pass)
- **Phase 8 Deepfake Regression Suite:** **28 passed in 7.98s** (100% pass)
- **End-to-End Unified Pipeline Integration:** **100% verified functional**

---

## L. Rollback Procedures & Safeguards

In the event of an operational anomaly, verified rollback artifacts are archived on disk:

1. **Malware Rollback:**
   - Command: `Copy-Item services/ml-service/app/models/malware/ember_model_2018.txt.bak_v1 services/ml-service/app/models/malware/ember_model_2018.txt -Force`
   - Set operating threshold in config: $\tau = 0.8336$
   - Backup Checksum: `509de4a83e2d76b69fb3025ced0429e5f40f6a95ca40122b9eedd03317fff5e2`
2. **Visual Deepfake Rollback:**
   - Command: `Copy-Item services/ml-service/app/models/deepfake_visual_classifier.pt.bak_v1 services/ml-service/app/models/deepfake_visual_classifier.pt -Force`
   - Retain operating threshold in config: $\tau = 0.6400$ (reverts to original production baseline AttentionPoolingVisualDetector checkpoint)
   - Backup Checksum: `708f535123e7cd42182be038f3ad4d37bc82b6bb05cdeb6e5402eb5784a058ed`
3. **Audio Deepfake Rollback:**
   - Command: `Copy-Item services/ml-service/app/models/deepfake_audio_classifier.joblib.bak_v1 services/ml-service/app/models/deepfake_audio_classifier.joblib -Force`
   - Revert operating threshold in config: $\tau = 0.5000$ (reverts to v1.0.0 audio baseline)
   - Backup Checksum: `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7`
4. **Phishing, URL:** Initial authoritative release versions (`v1.0.0`). Zero rollback required.

---

## M. Final Release Recommendation

**RECOMMENDATION: PROCEED WITH FINAL ML PR REVIEW.**

All 14 release verification gates have passed without exception. The production ML models are frozen, reproducible, fully documented, and cryptographically verified.
