# CYBERGUARD — Phase 7: Model Versioning & Deployment Readiness Specification

**Document Version:** 1.0.0  
**Status:** Authoritative & Frozen for Production Deployment  
**Date:** October 4, 2026  
**Target Services:** `services/ml-service/app/`  

---

## 1. Final Model Inventory

CYBERGUARD deploys five high-assurance machine learning engines defending against real-world threat vectors across email, web domains, executable binaries, and synthetic media:

| Engine | Canonical Name | Target Vector | Production Model Architecture | Deployment Status |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing Engine** | `phishing_detector` | Targeted email lures, credential harvesting, CEO fraud | Calibrated `LinearSVC` + TF-IDF Vectorizer | **ACTIVE_PRODUCTION (v1.0.0)** |
| **Malicious URL Engine** | `malicious_url_detector` | Impersonation domains, typosquatting, payload links | `HistGradientBoostingClassifier` | **ACTIVE_PRODUCTION (v1.0.0)** |
| **Malware Engine** | `malware_pe_detector` | Malicious Windows PE executables, ransomware, droppers | LightGBM GBDT (Candidate B promoted) | **PROMOTED_PRODUCTION (v1.1.0)** |
| **Deepfake Visual Engine** | `deepfake_visual_detector`| Generative face swaps, diffusion deepfakes, synthetic video | `AttentionPoolingVisualDetector` + 2D FFT | **PROMOTED_PRODUCTION (v1.0.0)** |
| **Deepfake Audio Engine** | `deepfake_audio_detector` | Voice cloning, synthetic speech, neural vocoder spoofing | Acoustic `LogisticRegression` | **ACTIVE_PRODUCTION (v1.0.0)** |

---

## 2. Version Mapping & Registry Lineage

All models are indexed in the authoritative registry (`services/ml-service/app/models/model_registry.json` and mirrored in `docs/phase7_model_registry.json`).

| Engine | Version | Lineage & Selection Rationale | Previous Baseline | Rollback State |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing** | `v1.0.0` | 43,680 clean emails (Nazario/Nigerian/CEAS/Enron/SpamAssassin). High precision, 0.13% FPR. | Initial | Retained in-place |
| **Malicious URL** | `v1.0.0` | 125,839 clean URLs (URLHaus/OpenPhish/Alexa/Tranco). Zero domain overlap. | Initial | Retained in-place |
| **Malware** | `v1.1.0` | Candidate B selected over Candidates A & C. 480k train / 120k val genuine EMBER records. +540 malware caught vs v1.0.0 on 200k test set. | `v1.0.0` (EMBER 2018 base) | Backed up at `ember_model_2018.txt.bak_v1` |
| **Deepfake Visual** | `v1.0.0` | Candidate B Attention-Pooled ViT-H/14 network over Candidate A (LogisticRegression) & Candidate C (RandomForest). Dual-signal 2D FFT integration. | Original v1.0.0 baseline | Backed up at `deepfake_visual_classifier.pt.bak_v1` |
| **Deepfake Audio** | `v1.0.0` | Acoustic spectral, pitch jitter, and 16 kHz neural vocoder cutoff detection. Evaluated on 17 unseen speaker identities. | Initial | Retained in-place |

---

## 3. Production Artifact Paths & File Hierarchy

Artifacts are housed inside `services/ml-service/app/models/`:

```
services/ml-service/app/models/
├── model_registry.json                                  # [NEW] Authoritative registry
├── deepfake_audio_classifier.joblib                     # Audio deepfake model
├── deepfake_audio_metadata.json                         # Audio deepfake metadata
├── deepfake_audio_schema.json                           # Audio deepfake feature schema
├── deepfake_visual_classifier.pt                        # Promoted visual deepfake weights
├── deepfake_visual_classifier.pt.bak_v1                 # Visual rollback backup
├── deepfake_visual_schema.json                          # Visual deepfake schema
├── malware/
│   ├── ember_model_2018.txt                             # Promoted Candidate B model (v1.1.0)
│   ├── ember_model_2018.txt.bak_v1                      # Malware rollback backup (v1.0.0)
│   ├── malware_metadata_v1.0.0.json                     # Malware metadata
│   └── malware_schema_v1.0.0.json                       # Malware schema
├── phishing/
│   ├── phishing_classifier_v1.0.0.joblib                # Phishing classifier
│   ├── phishing_vectorizer_v1.0.0.joblib                # Phishing TF-IDF vectorizer
│   ├── phishing_metadata_v1.0.0.json                    # Phishing metadata
│   └── phishing_schema_v1.0.0.json                      # Phishing schema
└── url/
    ├── malicious_url_classifier_v1.0.0.joblib           # URL classifier
    ├── malicious_url_metadata_v1.0.0.json               # URL metadata
    └── malicious_url_schema_v1.0.0.json                 # URL schema
```

---

## 4. SHA-256 Checksums & Binary Fingerprints

| Engine | Relative Artifact Path | File Size | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **Phishing Model** | `app/models/phishing/phishing_classifier_v1.0.0.joblib` | 537,887 B (0.51 MB) | `0a3f4ce38a9df04d9b852752023014b31a9748beddf8da7c339ab15b4c97c72b` |
| **Phishing Vectorizer** | `app/models/phishing/phishing_vectorizer_v1.0.0.joblib` | 314,154 B (0.30 MB) | `58b6b929e4926acbbc6dd3d72d80276b3f2cbd57e1bb165adb59ccc69a34ddfe` |
| **Malicious URL** | `app/models/url/malicious_url_classifier_v1.0.0.joblib` | 241,046 B (0.23 MB) | `c657040891cb2ba4981ef56492713f8d2f5900e0721ad2c21424dfe17c9a6d12` |
| **Malware (Candidate B)**| `app/models/malware/ember_model_2018.txt` | 97,563,714 B (93.04 MB) | `2efaf2366ec824020feb953a29f72dec287efc530280b607a38181865d78ae12` |
| **Deepfake Visual** | `app/models/deepfake_visual_classifier.pt` | 1,647,761 B (1.57 MB) | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` |
| **Deepfake Audio** | `app/models/deepfake_audio_classifier.joblib` | 1,503 B (1.47 KB) | `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7` |

---

## 5. Frozen Production Operating Thresholds

Thresholds are strictly calibrated to optimize enterprise security operations (balancing low False Positive Rates with high Recall):

| Engine | Operating Threshold | Metric Justification | Primary Trade-Off |
| :--- | :--- | :--- | :--- |
| **Phishing** | $\tau = 0.3600$ | ROC-AUC: 0.9987, FPR: 0.13%, Recall: 98.00% | High-security gate: suppresses false positives to 5 in 3,719 emails |
| **Malicious URL** | $\tau = 0.7400$ | ROC-AUC: 0.9635, Precision: 97.20%, FPR: 3.59% | Zero-domain-overlap gate: avoids blocking legitimate corporate domains |
| **Malware** | $\tau = 0.5590$ | Candidate B Enterprise gate: 97.07% Recall, 1.83% FPR on 200k binaries | Captures +540 malware vs v1.0.0 baseline while keeping FPR under 2% |
| **Deepfake Visual** | $\tau = 0.6400$ | Precision: 97.43%, Specificity: 86.19% | Defends against false manipulation claims on compressed camera frames |
| **Deepfake Audio** | $\tau = 0.5000$ | Balanced Accuracy: 72.00% across 17 unseen speaker identities | Standard binary boundary for advisory acoustic anomaly detection |

---

## 6. Framework & Runtime Dependencies

The runtime environment requires standard Python 3.10+ machine learning libraries without proprietary or out-of-tree extensions:

- **scikit-learn** $\ge 1.3.0$: Phishing (`CalibratedClassifierCV`, `TfidfVectorizer`), URL (`HistGradientBoostingClassifier`), Audio (`LogisticRegression`)
- **LightGBM** $\ge 4.0.0$: Malware static binary inference (`lightgbm.Booster`)
- **PyTorch** $\ge 2.0.0$: Visual deepfake inference (`torch.nn.Module`, `AttentionPoolingVisualDetector`)
- **NumPy & SciPy**: 2D Fast Fourier Transform (`scipy.fft`), acoustic spectral extraction, power spectrum computation
- **Pillow**: Image decoding and bilinear frame standardization

---

## 7. Model Loading & In-Memory Lifecycle

All engines implement lazy singleton loading to prevent cold-start penalties and preserve process memory until the respective endpoint is invoked:

1. **Phishing:** Loaded on first invocation in `app.services.message_engine._get_phishing_model()`. Cached in module-level `_CACHED_MODEL` and `_CACHED_VECTORIZER`.
2. **Malicious URL:** Loaded on first invocation in `app.services.url_engine._get_url_model()`. Cached in `_CACHED_URL_MODEL`.
3. **Malware:** Loaded on first invocation in `app.services.malware_engine._get_malware_model()`. Cached in `_CACHED_BOOSTER` and `_CACHED_EXTRACTOR`.
4. **Deepfake Visual:** Loaded on first invocation in `app.services.media_anomaly.image_detector.get_visual_deepfake_classifier()`. Weights transferred with `weights_only=True` to prevent arbitrary code execution.
5. **Deepfake Audio:** Loaded on first invocation in `app.services.media_engine._get_deepfake_audio_classifier()`. Cached in module memory.

---

## 8. Deterministic Rollback Strategy

Should an operational anomaly arise in production, deterministic rollback procedures are established for every engine:

### Malware Engine Rollback (Reverting v1.1.0 to v1.0.0)
1. **Source Backup:** `services/ml-service/app/models/malware/ember_model_2018.txt.bak_v1`
2. **Backup Checksum:** `509de4a83e2d76b69fb3025ced0429e5f40f6a95ca40122b9eedd03317fff5e2`
3. **Execution Steps:**
   ```bash
   cp services/ml-service/app/models/malware/ember_model_2018.txt.bak_v1 services/ml-service/app/models/malware/ember_model_2018.txt
   ```
4. **Configuration Adjustment:** Update fallback threshold in `malware_engine.py` to `0.8336` (v1.0.0 low-FPR threshold).
5. **Validation:** Execute `python services/ml-service/scripts/verify_production_models.py`.
6. **Restart:** Restart FastAPI worker process.

### Deepfake Visual Engine Rollback (Reverting Candidate B to Original Production Baseline)
1. **Source Backup:** `services/ml-service/app/models/deepfake_visual_classifier.pt.bak_v1`
2. **Backup Checksum:** `708f535123e7cd42182be038f3ad4d37bc82b6bb05cdeb6e5402eb5784a058ed`
3. **Execution Steps:**
   ```bash
   cp services/ml-service/app/models/deepfake_visual_classifier.pt.bak_v1 services/ml-service/app/models/deepfake_visual_classifier.pt
   ```
4. **Configuration Adjustment:** Retain `frozen_threshold` in `deepfake_visual_schema.json` at `0.6400` (identical operating threshold for original v1.0.0 baseline).
5. **Validation:** Execute `python services/ml-service/scripts/verify_production_models.py`.
6. **Restart:** Restart FastAPI worker process.

### Phishing, URL, and Audio Engines
Initial releases (`v1.0.0`) are self-contained and frozen. In the event of rollback, retain the verified artifacts from this release.

---

## 9. Integrity Verification Procedure

Automated integrity verification is implemented in [services/ml-service/scripts/verify_production_models.py](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/scripts/verify_production_models.py).

### Usage:
```bash
python services/ml-service/scripts/verify_production_models.py
```

### Verification Criteria:
1. All 5 model artifact paths resolve to existing files.
2. SHA-256 digests match `model_registry.json` bit-for-bit.
3. Every model successfully instantiates into runtime memory.
4. Exits with returncode `0` on 100% pass; exits with returncode `1` on any failure.

---

## 10. API Integration Points

All endpoints are hosted in `services/ml-service/app/routers/analyzeRouter.py` under the `/analyze` prefix and consumed by the Express Gateway (`services/backend/`):

| Endpoint Route | HTTP Method | Input Schema | Output Schema | Target Engine |
| :--- | :--- | :--- | :--- | :--- |
| `/analyze/message` | `POST` | `MessageAnalyzeRequest` | `UnifiedAnalysisResponse` | Phishing & Social Engineering |
| `/analyze/url` | `POST` | `UrlAnalyzeRequest` | `UnifiedAnalysisResponse` | Malicious URL Classifier |
| `/analyze/malware` | `POST` | `MalwareAnalyzeRequest` or `multipart/form-data` | `UnifiedAnalysisResponse` | Static PE Malware GBDT |
| `/analyze/media` | `POST` | `MediaAnalyzeRequest` or `multipart/form-data` | `UnifiedAnalysisResponse` | Visual & Audio Deepfake Forensic Engines |

---

## 11. Test Verification Baseline

- **Full ML Test Suite:** `pytest tests/` $\rightarrow$ **230 / 230 PASSED** (0 failures, 0 regressions)
- **Media Suite:** `test_dfdc_visual_engine.py` (10), `test_media_engine.py` (18), `test_media_validation.py` (19) $\rightarrow$ **47 / 47 PASSED**
- **Malware Suite:** `test_malware_engine.py` $\rightarrow$ **11 / 11 PASSED**
- **Deployment Verification:** `verify_production_models.py` $\rightarrow$ **PASS (Code 0)**

---

## 12. Known Limitations & Operational Guidance

1. **Malware:** Static PE analysis inspects Windows Portable Executable headers and section bytes. Non-PE formats (scripts, ELF, Mach-O) are routed to safe heuristics and require sandbox behavioral dynamic analysis for complete coverage.
2. **Deepfake Visual:** Frame-level ViT attention pooling demonstrates high precision (97.43%) but conservative recall (62.51%) on heavily compressed video. Production deployments pair this network with continuous 2D FFT spectral anomaly scoring for high-confidence dual-signal verification.
3. **Deepfake Audio:** Acoustic spectral analysis operates on 16 kHz standardized mono audio. Multi-speaker noisy streams require voice activity isolation prior to classification.

---

## 13. Deployment Checklist

- [x] All 5 models frozen and indexed in `model_registry.json`.
- [x] Checksums computed and verified bitwise against disk artifacts.
- [x] Operational thresholds configured and tested in engine code.
- [x] Deterministic rollback artifacts preserved and documented.
- [x] Verification script `verify_production_models.py` implemented and verified.
- [x] Full regression suite passing with zero failures (**230 / 230 passed**).
- [x] API schemas conform strictly to `UnifiedAnalysisResponse`.
- [x] Git worktree verified clean of frontend, secret engine, or dataset modifications.
- [x] Ready for final Pull Request review.
