# CYBERGUARD Phase 0 — Full Project & ML Architecture Analysis

**Document Version:** 1.0.0  
**Phase Status:** COMPLETE  
**Auditor / Author:** CYBERGUARD ML Lead  
**Evaluation Baseline:** Frozen Production v1.0.0 Baseline  
**Scope:** Repository-wide architecture scanning, ML inventory, dataset provenance, training/inference pipelines, leakage risk analysis, and Phase 1–7 execution roadmap.

---

## 1. Project Structure

The CYBERGUARD repository is structured as a modular monorepo containing frontend applications, an API gateway/orchestration service, an AI/ML microservice, local training datasets, documentation, and automated test suites:

```text
CyberGuard/
├── apps/
│   ├── web/                    # React Command Dashboard (OWNED BY OTHER TEAM - STRICTLY OUT OF SCOPE / DO NOT MODIFY)
│   └── mobile/                 # React Native / Expo mobile security application
├── services/
│   ├── backend/                # Node.js / Express API gateway, WebSocket broadcaster, Auth & Secret Detection
│   │   ├── src/
│   │   │   ├── controllers/    # Express controllers (auth, analyze, incidents, health)
│   │   │   ├── routes/         # Express API routes
│   │   │   ├── services/
│   │   │   │   ├── secretDetector.js  # RegEx/Entropy secret scanner (NOT ML - STRICTLY DO NOT MODIFY)
│   │   │   │   └── ...
│   │   │   └── index.js
│   │   └── package.json
│   └── ml-service/             # Python / FastAPI AI/ML microservice
│       ├── app/
│       │   ├── main.py         # FastAPI application entrypoint & health probes
│       │   ├── models/         # Serialized model artifacts, schemas, metadata
│       │   │   ├── phishing/   # Phishing v1.0.0 artifacts
│       │   │   ├── url/        # Malicious URL v1.0.0 artifacts
│       │   │   ├── malware/    # Static PE Malware v1.0.0 artifacts
│       │   │   ├── deepfake_audio_*
│       │   │   ├── deepfake_visual_*
│       │   │   ├── login_*
│       │   │   └── network_*
│       │   ├── routers/        # FastAPI endpoints (/analyze/*, /health)
│       │   ├── schemas/        # Pydantic v2 schemas (UnifiedAnalysisResponse)
│       │   ├── services/       # Core inference engines (message, url, malware, media, login, system)
│       │   └── utils/          # Preprocessors & feature extractors (url, ember, audio, cowrie, ctu13)
│       ├── scripts/            # Training, evaluation, and generalization audit scripts
│       ├── tests/              # 230 passing pytest unit and integration tests
│       └── requirements.txt    # Python runtime and ML dependencies
├── datasets/                   # Local raw, benchmark, and curated datasets
│   ├── Phishing/               # Nazario, Nigerian Fraud, CEAS 2008, Enron, SpamAssassin, Ling, TREC
│   ├── Malicious url/          # PhishTank verified_online.csv
│   ├── malware/ember2018/      # EMBER 2018 JSONL feature shards & test partition
│   ├── deepfake-audio-detection/ # garystafford/deepfake-audio-detection (16 kHz mono)
│   ├── audio-dfd-benchmark/    # Podonos Audio Deepfake Detection Benchmark
│   ├── DFDC/shield_2026_final_data/ # Pre-extracted DFDC PyTorch feature tensors
│   ├── FaceForensics/          # Supporting facial manipulation benchmark
│   ├── ctu13/                  # NetFlow botnet traffic captures
│   └── logs_dataset/           # Cowrie honeypot logs
├── docs/                       # Technical specifications, API contracts, audits, and evaluation reports
│   ├── API_CONTRACT.md         # Authoritative REST API specification
│   ├── FINAL_ML_EVALUATION_REPORT.md # Consolidated Phase 6 evidence package
│   ├── PRODUCTION_READINESS_AUDIT.md # Phase 5 audit findings
│   └── PHASE_4_CROSS_ENGINE_VALIDATION.md # Cross-engine regression verification
└── package.json                # Monorepo workspaces definition
```

---

## 2. Existing ML Engines

CYBERGUARD hosts five primary production detection engine families (frozen at v1.0.0) alongside three supplementary security anomaly engines:

| Engine | Implementation Type | Model Architecture / Algorithm | Feature Space | Operating Threshold | Scope in This ML Workflow |
|---|---|---|---|---|---|
| **1. Phishing / Message** | Hybrid ML + Heuristic | `CalibratedClassifierCV(LinearSVC)` | 25,000 TF-IDF unigram+bigram | $\tau = 0.36$ | **IN-SCOPE** (Core Target) |
| **2. Malicious URL** | Hybrid ML + Heuristic | `HistGradientBoostingClassifier` | 16 dense structural/lexical features | $\tau = 0.74$ | **IN-SCOPE** (Core Target) |
| **3. Static PE Malware** | Pretrained + Verified ML | `LightGBM Booster` (1,000 trees) | 2,381 EMBER v2 static PE features | $\tau = 0.8336$ | **IN-SCOPE** (Core Target, Static Only) |
| **4. Deepfake Audio** | Supervised ML | `LogisticRegression` (L2, C=1.0) | 13 acoustic features (16 kHz mono) | $\tau = 0.50$ | **IN-SCOPE** (Core Target) |
| **5. Deepfake Visual** | Hybrid ML + Forensic | `AttentionPoolingVisualDetector` + 2D FFT | 1024-dim frame embeddings + spectral FFT | $\tau = 0.64$ | **IN-SCOPE** (Core Target) |
| **Login Anomaly** | Unsupervised ML | `IsolationForest` | 6 behavioral/network features | Scaled score | **OUT-OF-SCOPE** (Compatibility only) |
| **Network Threat** | Hybrid ML | Random Forest + Isolation Forest | 18 NetFlow telemetry features | Multi-class | **OUT-OF-SCOPE** (Compatibility only) |
| **System Telemetry** | Heuristic / Statistical | Baseline deviation z-scores | Process surges, port deviations | Heuristic | **OUT-OF-SCOPE** (Compatibility only) |
| **Secret Detection** | Deterministic / Heuristic | RegEx patterns + Shannon entropy | Source strings / tokens | Rule-based | **STRICTLY PROHIBITED** (`secretDetector.js`) |

---

## 3. Dataset Inventory

Detailed inventory of raw, processed, and benchmark datasets present in the workspace:

### 3.1 Phishing & Social Engineering (`datasets/Phishing/`)
- `Nazario.csv` (7.8 MB): 1,565 raw targeted credential phishing lures and brand spoofing emails.
- `Nigerian_Fraud.csv` (9.2 MB): 3,332 advance-fee fraud and social engineering lures.
- `CEAS_08.csv` (67.9 MB): 39,154 raw messages (1,624 targeted phishing lures, 17,312 legitimate emails, 20,218 generic commercial marketing spam).
- `Enron.csv` (44.8 MB): 29,767 raw messages (15,791 authentic corporate communications, 13,972 unsolicited generic marketing messages).
- `SpamAssasin.csv` (14.9 MB): 5,809 raw messages (4,091 legitimate personal/list messages, 1,718 generic spam messages).
- `Ling.csv` (9.3 MB): 2,401 benign academic linguistics correspondence emails (clean negative generalization benchmark).
- `TREC_07.csv` (10.0 MB): 28,975 broad email samples from the NIST TREC 2007 Public Spam Corpus (unseen external generalization benchmark).
- `phising.csv` (1.5 MB): 10,000 legacy generic message records.

### 3.2 Malicious URL (`datasets/Malicious url/`)
- `verified_online.csv` (14.3 MB): 74,997 raw verified malicious phishing/malware URLs from PhishTank (74,994 unique URLs across 40,497 unique domains).
- *Benign Corpus (Extracted from authentic email datasets)*: 50,845 verified authentic benign URLs across 11,704 unique corporate and institutional domains.
- *Combined Curated Dataset*: 125,839 clean URLs across 52,193 unique domains.

### 3.3 Static PE Malware (`datasets/malware/ember2018/`)
- `ember_model_2018.txt` (12.7 MB): Official LightGBM booster model trained on 800,000 labeled and unlabeled 2018 PE binaries.
- `test_features.jsonl` (186.9 MB): 200,000 official test records (100,000 labeled benign, 100,000 labeled malware).
- `train_features_0.jsonl` through `train_features_5.jsonl` (shards totaling ~1.4 GB): 800,000 training records (300,000 benign, 300,000 malware, 200,000 unlabeled records with label=-1).

### 3.4 Deepfake Media
- **Audio (`datasets/deepfake-audio-detection/`):**
  - `manifest.csv` (55.1 KB): 240 samples across 87 unique speaker/generator sources.
  - `raw/real/` and `raw/fake/`: Raw FLAC/WAV audio recordings from human speakers and diverse synthesis engines (ElevenLabs, Bark, Kokoro, Hume AI).
- **Audio Secondary (`datasets/audio-dfd-benchmark/`):** Podonos Audio Deepfake Detection Benchmark (16 kHz wideband and 8 kHz narrowband directories).
- **Visual (`datasets/DFDC/shield_2026_final_data/`):**
  - `X_train.pt` (856.7 MB), `y_train.pt` (85.2 KB): 10,458 samples (1,112 genuine, 9,346 manipulated).
  - `X_val.pt` (183.6 MB), `y_val.pt` (19.5 KB): 2,241 samples (238 genuine, 2,003 manipulated).
  - `X_test.pt` (183.7 MB), `y_test.pt` (19.5 KB): 2,242 samples (239 genuine, 2,003 manipulated).
  - Pre-extracted 20 frames $\times$ 1024-dim CLIP ViT-H/14 embeddings.
- **Visual Secondary (`datasets/FaceForensics/`):** Supporting facial manipulation frames and classification directories.

---

## 4. Model Artifact Inventory

Inventory of serialized production model weights, preprocessors, and metadata stored in `services/ml-service/app/models/`:

| Engine | Artifact Filename | Type / Format | Size | Metadata / Schema Path |
|---|---|---|---|---|
| **Phishing** | `phishing/phishing_classifier_v1.0.0.joblib` | Scikit-learn `CalibratedClassifierCV` | 393 KB | `phishing/phishing_metadata_v1.0.0.json`<br>`phishing/phishing_schema_v1.0.0.json` |
| **Phishing Vectorizer** | `phishing/phishing_vectorizer_v1.0.0.joblib` | Scikit-learn `TfidfVectorizer` (25k vocab) | 1.1 MB | Included in phishing schema |
| **Malicious URL** | `url/malicious_url_classifier_v1.0.0.joblib` | Scikit-learn `HistGradientBoostingClassifier` | 667 KB | `url/malicious_url_metadata_v1.0.0.json`<br>`url/malicious_url_schema_v1.0.0.json` |
| **Static PE Malware** | `malware/ember_model_2018.txt` | LightGBM Text Dump (1,000 trees) | 12.7 MB | `malware/malware_metadata_v1.0.0.json`<br>`malware/malware_schema_v1.0.0.json` |
| **Deepfake Audio** | `deepfake_audio_classifier.joblib` | Scikit-learn `LogisticRegression` | 1.2 KB | `deepfake_audio_metadata.json`<br>`deepfake_audio_schema.json` |
| **Deepfake Visual (PyTorch)** | `deepfake_visual_classifier.pt` | PyTorch State Dict (`AttentionPooling`) | 1.4 MB | `deepfake_visual_metadata.json`<br>`deepfake_visual_schema.json` |
| **Deepfake Visual (Fallback)** | `deepfake_visual_classifier.joblib` | Scikit-learn `LogisticRegression` | 8.3 KB | `deepfake_visual_metadata.json` |

---

## 5. Training Pipeline Inventory

Current standalone training and evaluation scripts located in `services/ml-service/scripts/`:

1. **Phishing Training Pipeline:**
   - Script: `scripts/train_phishing_classifier.py`
   - Inputs: `datasets/Phishing/` (Nazario, Nigerian_Fraud, CEAS_08, Enron, SpamAssassin)
   - Methodology: Stratified 80/10/10 split (seed 42), semantic threat filtering, TF-IDF 25k extraction, candidate comparison (`LinearSVC` vs `LogisticRegression`), validation threshold calibration ($\tau = 0.36$), frozen test evaluation.
   - Outputs: `phishing_classifier_v1.0.0.joblib`, `phishing_vectorizer_v1.0.0.joblib`, `phishing_evaluation_report.json`.

2. **Phishing Generalization Audit:**
   - Script: `scripts/audit_phishing_generalization.py`
   - Inputs: `TREC_07.csv`, `Ling.csv`, and Nazario Leave-One-Source-Out partition.
   - Outputs: `phishing_generalization_audit_report.json`.

3. **Malicious URL Training Pipeline:**
   - Script: `scripts/train_url_classifier.py`
   - Inputs: `datasets/Malicious url/verified_online.csv` + benign email URLs.
   - Methodology: Domain-level `GroupShuffleSplit` (80/13/7 split, 5,219 unseen test domains), 16 dense features, candidate comparison (`HistGradientBoosting` vs `RandomForest` vs `LogisticRegression`), validation threshold calibration ($\tau = 0.74$).
   - Outputs: `malicious_url_classifier_v1.0.0.joblib`, `url_evaluation_report.json`.

4. **Malware Evaluation Pipeline:**
   - Script: `scripts/evaluate_malware_ember.py`
   - Inputs: `datasets/malware/ember2018/test_features.jsonl` (10,000 balanced sample) + `ember_model_2018.txt`.
   - Methodology: Pure static PE feature extraction (2,381 dims via LIEF), inference timing, dual threshold comparison ($\tau = 0.50$ balanced and $\tau = 0.8336$ low-FPR target).
   - Outputs: `malware_metadata_v1.0.0.json`, `malware_schema_v1.0.0.json`, `malware_evaluation_report.json`.

5. **Deepfake Audio Training Pipeline:**
   - Script: `scripts/train_media_classifier.py`
   - Inputs: `datasets/deepfake-audio-detection/manifest.csv` and audio files.
   - Methodology: Source-disjoint train/val/test splits (47/23/17 sources), 16 kHz mono standardization, 13 acoustic features, ablation experiments, threshold calibration ($\tau = 0.50$).
   - Outputs: `deepfake_audio_classifier.joblib`, `deepfake_audio_metadata.json`, `deepfake_audio_schema.json`.

6. **Deepfake Visual Training Pipeline:**
   - Script: `scripts/train_visual_classifier.py`
   - Inputs: `datasets/DFDC/shield_2026_final_data/` (`X_train.pt`, `X_val.pt`, `X_test.pt`).
   - Methodology: PyTorch `AttentionPoolingVisualDetector` training (8 epochs, Adam, lr=1e-4, weight_decay=1e-4), validation threshold calibration ($\tau = 0.64$), held-out test evaluation.
   - Outputs: `deepfake_visual_classifier.pt`, `deepfake_visual_metadata.json`, `deepfake_visual_schema.json`.

7. **Deepfake Combined Evaluation Pipeline:**
   - Script: `scripts/evaluate_media_detector.py`
   - Evaluates audio and visual engines, generates ROC/PR curves and `media_evaluation_report.json`.

---

## 6. Inference Pipeline Inventory

The runtime inference workflow within `services/ml-service/app/services/` maps directly to HTTP endpoints:

1. **Message Threat Inference (`services/ml-service/app/services/message_engine.py`):**
   - Normalizes incoming text.
   - Runs TF-IDF transformation via `phishing_vectorizer_v1.0.0.joblib`.
   - Predicts threat probability using `phishing_classifier_v1.0.0.joblib`.
   - Compares score against $\tau = 0.36$.
   - Applies heuristic indicators (urgent keywords, financial demands) and returns `UnifiedAnalysisResponse`.

2. **URL Threat Inference (`services/ml-service/app/services/url_engine.py`):**
   - Parses URL with `URLPreprocessor`.
   - Extracts 16 dense structural and lexical features.
   - Predicts risk score via `malicious_url_classifier_v1.0.0.joblib`.
   - Compares score against $\tau = 0.74$.
   - Identifies brand impersonation lures and returns `UnifiedAnalysisResponse`.

3. **Static PE Malware Inference (`services/ml-service/app/services/malware_engine.py`):**
   - Receives binary bytes (up to 50 MB) or structural JSON headers.
   - Verifies PE signature (`b"MZ"` and PE header offset).
   - Extracts 2,381 EMBER features using `PEFeatureExtractor` (LIEF parser in-memory).
   - Computes score via `ember_model_2018.txt`.
   - Compares score against $\tau = 0.8336$ (1% FPR target) and outputs MITRE ATT&CK mappings (T1204, T1059, T1027).

4. **Media Threat Inference (`services/ml-service/app/services/media_engine.py`):**
   - Inspects file magic bytes (WAV, FLAC, MP3, PNG, JPEG, WEBP).
   - If audio: converts to mono 16 kHz, computes 13 acoustic features, runs `LogisticRegression` against $\tau = 0.50$.
   - If visual: extracts face or full-frame embedding, executes `AttentionPoolingVisualDetector` against $\tau = 0.64$, and supplements with 2D FFT spectral forensic analysis.

---

## 7. API Inventory

All endpoints strictly adhere to `docs/API_CONTRACT.md` and return `UnifiedAnalysisResponse`:

| Endpoint URL | HTTP Method | Payload Format | Description |
|---|---|---|---|
| `/health` | `GET` | None | Service liveness probe |
| `/health/readiness` | `GET` | None | Engine readiness check |
| `/analyze/message` | `POST` | JSON (`MessageAnalyzeRequest`) | Phishing and social engineering text analysis |
| `/analyze/url` | `POST` | JSON (`UrlAnalyzeRequest`) | Malicious URL lexical & structural analysis |
| `/analyze/malware` | `POST` | Multipart Binary or JSON | Static PE malware analysis (up to 50 MB) |
| `/analyze/media` | `POST` | Multipart Binary or JSON (base64 Data URI) | Audio and visual deepfake forensic analysis |
| `/analyze/login` | `POST` | JSON (`LoginAnalyzeRequest`) | Login anomaly & credential stuffing detection |
| `/analyze/system` | `POST` | JSON (`SystemAnalyzeRequest`) | Workstation telemetry anomaly detection |

*Prefix Aliases:* All `/analyze/*` endpoints are mirrored at `/api/v1/analyze/*` and `/internal/analyze/*`.

---

## 8. Dependency Inventory

### 8.1 Python ML Microservice (`services/ml-service/requirements.txt`)
- `fastapi>=0.110.0` (REST API routing)
- `uvicorn[standard]>=0.28.0` (ASGI server)
- `python-dotenv>=1.0.1` (Environment variable loading)
- `scikit-learn>=1.4.0` (LinearSVC, HistGradientBoosting, LogisticRegression, IsolationForest)
- `pandas>=2.0.0` (DataFrame manipulation)
- `pyarrow>=14.0.0` (Parquet storage)
- `joblib>=1.3.0` (Model serialization)
- `pytest>=8.0.0` (Test runner)
- `soundfile>=0.12.0` (Audio decoding)
- `pillow>=10.0.0` (Image processing)
- `lightgbm>=4.0.0` (EMBER malware booster)
- `lief>=0.14.0` (Static PE parsing)
- `torch>=2.0.0` (Deepfake visual attention network)

### 8.2 Backend Gateway (`services/backend/package.json`)
- `express`: REST API Gateway
- `socket.io`: Real-time WebSocket incident broadcasting
- `pg`: PostgreSQL relational telemetry
- `jsonwebtoken`, `bcrypt`: Authentication and RBAC
- *Note:* `secretDetector.js` operates purely in Node.js with regex patterns and Shannon entropy; it does not consume Python ML resources.

---

## 9. Existing Evaluation Evidence

Authoritative, frozen v1.0.0 evaluation metrics compiled from verified test artifacts (`docs/FINAL_ML_EVALUATION_REPORT.md`):

| Engine Family | Evaluation Partition | Accuracy | Bal. Acc. | Precision | Recall | Specificity | F1 Score | ROC-AUC | PR-AUC | Operational Threshold |
|---|---|---|---|---|---|---|---|---|---|---|
| **Phishing (In-Source)** | 4,368 untouched test samples | 99.59% | 98.93% | 99.22% | 98.00% | 99.87% | 98.60% | 0.9987 | 0.9964 | $\tau = 0.36$ |
| **Phishing (TREC 2007)** | 28,975 unseen external samples | 89.38% | 75.73% | 71.50% | 55.67% | 95.78% | 62.60% | 0.9302 | 0.7735 | $\tau = 0.36$ |
| **Phishing (Nazario LOSO)** | 1,556 held-out Nazario lures | — | — | — | 32.39% | — | — | — | — | $\tau = 0.36$ |
| **Malicious URL** | 8,720 samples across 5,219 unseen domains | 85.99% | 87.88% | 97.19% | 79.35% | 96.41% | 87.37% | 0.9635 | 0.9767 | $\tau = 0.74$ |
| **Static PE Malware** | 10,000 EMBER test samples (5k benign / 5k mal) | 98.32% | 98.32% | 99.07% | 97.56% | 99.08% (FPR 0.92%) | 98.31% | 0.9975 | 0.9979 | $\tau = 0.8336$ |
| **Deepfake Audio** | 50 samples across 17 held-out sources | 72.00% | 72.00% | 72.00% | 72.00% | 72.00% | 72.00% | 0.7856 | 0.8317 | $\tau = 0.50$ |
| **Deepfake Visual** | 2,242 frames (DFDC test partition) | 65.03% | 74.35% | 97.43% | 62.51% | 86.19% | 76.16% | 0.7966 | 0.9722 | $\tau = 0.64$ |

---

## 10. Missing Components

1. **Unified Dataset Manifests for Retraining:**
   - Raw source datasets currently exist in scattered CSV and JSONL formats across `datasets/`. A standardized metadata manifest (`manifest.json` or `.parquet`) tracking sample hash, source identity, subclass, and split tag does not yet exist for all datasets.
2. **Domain-Aware Disjoint URL Manifest:**
   - The benign URL corpus was dynamically extracted during training. A persistent, pre-computed, domain-indexed manifest is needed for deterministic re-runs without repeating extraction.
3. **Automated Cross-Source Benchmark Runner:**
   - Phishing generalization is tested via `audit_phishing_generalization.py`, but a unified multi-engine cross-source benchmark harness is absent.
4. **Formal Model Registry File:**
   - Model versions and metadata are currently distributed across individual JSON files in `services/ml-service/app/models/`. A centralized `model_registry.json` will be constructed in Phase 7.

---

## 11. Risks & Data Leakage Risks

1. **Text Spam vs. Phishing Semantic Leakage:**
   - *Risk:* Treating commercial spam as phishing leads to false positive blocking of legitimate marketing or administrative emails.
   - *Mitigation:* Strict semantic threat subclass filtering enforced in Phase 1; generic spam remains excluded from positive labels.
2. **URL Domain Leakage:**
   - *Risk:* If URLs from the same root domain appear in both training and test sets, the model memorizes domain reputations rather than lexical structural patterns.
   - *Mitigation:* Domain-level `GroupShuffleSplit` must be maintained so that no domain in the test set exists in the training set.
3. **Malware Dynamic Execution Risk:**
   - *Risk:* Accidental process invocation of malicious PE files.
   - *Mitigation:* Static PE analysis strictly enforced; zero subprocess or execution APIs permitted.
4. **Deepfake Audio Speaker / Generator Leakage:**
   - *Risk:* If identical voice actors or TTS voices appear across train and test partitions, models learn speaker identity rather than acoustic manipulation artifacts.
   - *Mitigation:* Source-disjoint partitioning must remain strictly enforced across all 87 source IDs.
5. **Deepfake Visual Source Video Identity Limitations:**
   - *Risk:* Pre-extracted DFDC tensors lack video-level subject IDs, which may allow frames from the same video sequence to span partitions if random frame splitting were used.
   - *Mitigation:* Rely exclusively on the pre-partitioned official train/val/test splits (`X_train.pt`, `X_val.pt`, `X_test.pt`) and document this limitation explicitly.

---

## 12. Proposed Training Plan (Phases 1–7)

- **Phase 1: Dataset Cleaning & Feature Engineering**
  - Clean, deduplicate, and audit raw datasets one family at a time (Phishing $\to$ URL $\to$ Malware $\to$ Deepfake).
  - Generate reproducible dataset manifests with source preservation and leakage validation.
  - Do not overwrite or delete original raw datasets.
- **Phase 2: Phishing Model Training / Fine-Tuning**
  - Evaluate Calibrated LinearSVC vs Logistic Regression baselines using cleaned manifests.
  - Compare validation results against v1.0.0; preserve v1.0.0 unless demonstrably superior.
- **Phase 3: Malicious URL Model Training**
  - Evaluate HistGradientBoosting vs Random Forest vs Logistic Regression on domain-isolated splits.
  - Optimize for high precision ($>95\%$) and low enterprise false alarm rate.
- **Phase 4: Malware Model Training & Validation**
  - Verify EMBER 2018 LightGBM static feature extraction and evaluate retraining feasibility vs official benchmark booster.
  - Enforce static-only safety.
- **Phase 5: Deepfake Model Training (Audio & Visual Separated)**
  - Audio: Retain 16 kHz mono standardization and 13 acoustic features on source-disjoint splits.
  - Visual: Train/fine-tune PyTorch attention-pooling network on DFDC representations with 2D FFT forensic integration.
- **Phase 6: Final Evaluation & Comparison**
  - Execute frozen held-out test evaluations across all five engines.
  - Generate consolidated metrics, confusion matrices, and `docs/FINAL_MODEL_COMPARISON.md`.
- **Phase 7: Model Versioning & Deployment Preparation**
  - Create centralized model registry, artifact hashes, deployment guides, and rollback documentation.

---

## 13. Files Expected to Change in Future Phases

### Anticipated New Files (to be created in designated phases):
- `datasets/manifests/` (Cleaned manifests created in Phase 1)
- `services/ml-service/scripts/train_*.py` (Updated/refined training pipelines in Phases 2–5)
- `docs/FINAL_MODEL_COMPARISON.md` (Phase 6 deliverable)
- `docs/MODEL_DEPLOYMENT_PREPARATION.md` (Phase 7 deliverable)
- `services/ml-service/app/models/model_registry.json` (Phase 7 centralized registry)

### Strictly Protected Files (ZERO modifications allowed):
- `apps/web/*` (React Command Dashboard)
- `services/backend/src/services/secretDetector.js` (Secret Detection Engine)
- All original raw datasets in `datasets/` (Must not be deleted or overwritten)

---

```text
PHASE 0 STATUS: COMPLETE
```
