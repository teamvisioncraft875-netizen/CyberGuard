# CYBERGUARD Production Readiness Audit

**Document Version:** 1.0.0  
**Audit Date:** 2026-10-04  
**Audit Scope:** Production Detection Engines (`services/ml-service`)  
**Evaluator:** AI/ML Lead & System Architect  

---

## 1. Scope

This audit provides the production-readiness assessment of the four primary detection engine families in the CYBERGUARD AI/ML Microservice (`services/ml-service`):
1. **Phishing & Message Threat Engine** (`Calibrated_LinearSVC`)
2. **Malicious URL Threat Engine** (`HistGradientBoostingClassifier`)
3. **Static PE Malware Detection Engine** (`EMBER 2018 LightGBM`)
4. **Deepfake Media Detection Engine** (Audio `LogisticRegression` + Visual `AttentionPoolingVisualDetector` with 2D FFT forensic spectral analyzer)

In accordance with strict project rules:
- No models were retrained.
- No frozen operating thresholds were modified.
- No frontend files (`apps/web/`) were touched.
- The Secret Detection Engine (`services/backend/src/services/secretDetector.js`) remained strictly isolated and untouched.
- No binary malware was executed; all analysis is static.

---

## 2. Engine Inventory

| Engine Family | Subsystem / Algorithm | Artifact Path | Version | Frozen Threshold | Input Modality |
|---|---|---|---|---|---|
| **Phishing & Message** | `CalibratedClassifierCV(LinearSVC)` with TF-IDF 25k | `app/models/phishing/phishing_classifier_v1.0.0.joblib` | `v1.0.0` | $\tau = 0.36$ | Text (Email, SMS, Social) |
| **Malicious URL** | `HistGradientBoostingClassifier` (16 dense features) | `app/models/url/malicious_url_classifier_v1.0.0.joblib` | `v1.0.0` | $\tau = 0.74$ | String (URL) |
| **Static PE Malware** | `LightGBM Booster` (1,000 trees, 2,381 features) | `app/models/malware/ember_model_2018.txt` | `v1.0.0` | $\tau = 0.8336$ | Windows PE Binary (bytes / base64) |
| **Deepfake Audio** | `LogisticRegression` (13 acoustic features, 16 kHz mono) | `app/models/deepfake_audio_classifier.joblib` | `v1.0.0` | $\tau = 0.50$ | Audio payload (WAV, FLAC, MP3, OGG) |
| **Deepfake Visual** | `AttentionPoolingVisualDetector` + 2D FFT Analyzer | `app/models/deepfake_visual_classifier.pt` | `v1.0.0` | $\tau = 0.64$ | Image / Video frames (PNG, JPEG, WEBP) |

---

## 3. Model Artifact Integrity

Every model artifact, vectorizer, PyTorch state dictionary, metadata descriptor, and JSON schema was programmatically loaded and verified:

1. **Phishing Engine**:
   - `phishing_classifier_v1.0.0.joblib` (537,887 bytes) — Verified loadable (`CalibratedClassifierCV`).
   - `phishing_vectorizer_v1.0.0.joblib` (314,154 bytes) — Verified loadable (25,000 vocabulary entries).
   - `phishing_metadata_v1.0.0.json` (3,261 bytes) & `phishing_schema_v1.0.0.json` (434 bytes) — Verified synchronized.
   - Operating threshold: $\tau = 0.36$.

2. **Malicious URL Engine**:
   - `malicious_url_classifier_v1.0.0.joblib` (241,046 bytes) — Verified loadable (`HistGradientBoostingClassifier`).
   - `malicious_url_metadata_v1.0.0.json` (2,289 bytes) & `malicious_url_schema_v1.0.0.json` (683 bytes) — Verified synchronized.
   - Operating threshold: $\tau = 0.74$.

3. **Static PE Malware Engine**:
   - `ember_model_2018.txt` (127,284,141 bytes) — Verified loadable (`LightGBM Booster`, 2,381 features, 1,000 trees).
   - `malware_metadata_v1.0.0.json` (1,330 bytes) & `malware_schema_v1.0.0.json` (1,890 bytes) — Verified synchronized.
   - Operating threshold: $\tau = 0.8336$ (1% FPR target).

4. **Deepfake Audio Engine**:
   - `deepfake_audio_classifier.joblib` (1,503 bytes) — Verified loadable (`LogisticRegression`, 13 features).
   - `deepfake_audio_metadata.json` (3,056 bytes) & `deepfake_audio_schema.json` (642 bytes) — Verified synchronized.
   - Operating threshold: $\tau = 0.50$.

5. **Deepfake Visual Engine**:
   - `deepfake_visual_classifier.pt` (1,649,589 bytes) — Verified loadable (`OrderedDict` state dict for `AttentionPoolingVisualDetector`).
   - `deepfake_visual_metadata.json` (3,069 bytes) & `deepfake_visual_schema.json` (567 bytes) — Verified synchronized.
   - Operating threshold: $\tau = 0.64$.

*Duplicate / Stale Artifacts:* Zero unreferenced or stale model weights were detected in active loader paths.

---

## 4. Reproducibility

Repeated sequential evaluations (5 iterations) on identical inputs confirm 100% deterministic outputs across all engines:

| Engine | Test Input Hash / Identifier | Model Version | Predicted Probability | Risk Score | Risk Tier |
|---|---|---|---|---|---|
| **Phishing** | `URGENT: Your account credentials have expired...` | `v1.0.0` | `0.9984` | 99 | `Critical` |
| **URL** | `https://paypal-security-verification.com/login` | `v1.0.0` | `0.9995` | 99 | `Critical` |
| **Malware** | Genuine Windows `notepad.exe` (SHA-256: host OS) | `v1.0.0` | `0.00001` | 0 | `Safe` |
| **Malware** | EMBER test sample #0 (`163ced46c18ef09d8...`) | `v1.0.0` | `0.99999` | 99 | `Critical` |

All numerical outputs, decisions, and risk tier assignments showed zero variance between runs.

---

## 5. Preprocessing Alignment

1. **Phishing**:
   - Training: TF-IDF on cleaned text with `max_features=25000`, `ngram_range=(1, 2)`, `sublinear_tf=True`, Unicode accent stripping, and lowercase transformation.
   - Inference: Directly calls `vectorizer.transform([text])` ensuring exact feature alignment.
2. **URL**:
   - Training: Exact 16 dense features extracted by `extract_url_features` in identical column order (`URL_FEATURE_COLUMNS`).
   - Inference: Constructs input vectors using the identical `URL_FEATURE_COLUMNS` index.
3. **Malware**:
   - Training: 2,381 features conforming to EMBER 2018 v2.
   - Inference: [`ember_feature_extractor.py`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/app/utils/ember_feature_extractor.py) extracts all 9 groups in exact order: ByteHistogram (256), ByteEntropyHistogram (256), StringExtractor (104), GeneralFileInfo (10), HeaderFileInfo (62), SectionInfo (255), ImportsInfo (1280), ExportsInfo (128), and DataDirectories (30).
4. **Deepfake Audio**:
   - Training: Mono 16 kHz polyphase resample, DC offset removed, peak normalized, 13 acoustic features.
   - Inference: Identical preprocessing pipeline in `media_engine.py`.
5. **Deepfake Visual**:
   - Training: MTCNN face detection/alignment, 224×224 RGB tensor normalization, temporal attention pooling.
   - Inference: Identical feature extraction with FFT forensic fallback when faces are absent.

---

## 6. API Contract

All production detection routes (`/analyze/*`, `/internal/analyze/*`, `/api/v1/analyze/*`) enforce the unified [`UnifiedAnalysisResponse`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/docs/API_CONTRACT.md#L1101-L1103) schema:

```json
{
  "risk_level": "Safe" | "Low" | "Medium" | "High" | "Critical",
  "risk_score": 0..100,
  "explanation": "string",
  "signals": { ... },
  "recommended_actions": [ "string" ],
  "confidence_score": 0.0..1.0
}
```

- `risk_score` is strictly bounded within $[0, 100]$.
- `confidence_score` is strictly bounded within $[0.0, 1.0]$.
- Probabilities vs Confidence: In accordance with project rules, model raw output is labeled `ml_malware_probability` or `ml_malicious_probability`. `confidence_score` reflects distance from the decision boundary rather than uncalibrated probabilities.

---

## 7. Security

1. **Malware Engine Execution Guardrail**: **Zero binary execution**. The service never invokes `subprocess`, `os.system`, `execve`, or shell utilities to execute or detonate files. Static analysis is performed purely via in-memory buffers and structural PE parsing.
2. **Filesystem Isolation**: Binary payloads and media streams are parsed in memory or temporary files that are safely deallocated immediately.
3. **Path Traversal Protection**: Upload filenames are treated as display labels and never used to build unchecked filesystem write paths.
4. **Information Disclosure Prevention**: API error handlers return structured JSON error details without dumping backend stack traces or internal filesystem paths.

---

## 8. Resource Safety

1. **Upload Size Limits**:
   - Media endpoints: Enforced 10 MB maximum limit (HTTP 413 on violation).
   - Malware endpoint: Enforced 50 MB maximum limit (HTTP 413 on violation).
2. **Memory & Concurrency**:
   - All models use lazy singleton loaders (`_get_url_model()`, `_get_malware_model()`, `_get_media_engine()`). Heavy model files (e.g. 127 MB LightGBM booster) are loaded into memory exactly once and shared across requests.
3. **Measured Inference Latencies**:
   - Malware Engine: **0.070 ms / sample** (14,343 samples/sec on CPU).
   - URL Engine: **0.062 ms / sample** (16,000 samples/sec on CPU).
   - Phishing Engine: **~1.2 ms / sample** (including TF-IDF vectorization).
   - Deepfake Audio: **~8 ms / sample** (including audio resampling).
   - Deepfake Visual: **~45 ms / sample** (including FFT forensic analysis).

---

## 9. Failure Modes

| Test Scenario | Phishing Engine | URL Engine | Malware Engine | Media Engine | Service Behavior |
|---|---|---|---|---|---|
| **Valid Input** | 200 OK | 200 OK | 200 OK | 200 OK | Compliant response |
| **Empty Input** | 422 (Pydantic min length) | 200 OK (Safe, score 0) | 422 / 200 OK (Safe, score 0) | 400 (Payload empty/short) | Safe, no crash |
| **Malformed JSON** | 422 / 400 | 422 / 400 | 400 | 400 | Controlled error |
| **Wrong Type** | 422 | 422 | 422 | 422 | Pydantic validation |
| **Oversized Upload** | Handled | Handled | 413 Payload Too Large | 413 Payload Too Large | Rejected before processing |
| **Corrupted Payload** | Handled | Handled | 200 OK (Graceful zero-fallback) | 415 / Graceful FFT fallback | Safe, fails closed |
| **Model Unavailable** | Graceful fallback | Heuristic fallback | Heuristic fallback | Forensic FFT fallback | Continuous availability |

---

## 10. Risk Scoring

| Engine | Raw Evidence Input | Threshold | Risk Score Calculation | Risk Tier Assignment | Deterministic |
|---|---|---|---|---|---|
| **Phishing** | Platt Calibrated Sigmoid Prob | $\tau = 0.36$ | Piecewise scaled by risk band; elevated to $\ge 90$ for critical credential theft | $< 0.20$: Safe<br>$0.20-0.36$: Low<br>$0.36-0.60$: Medium<br>$0.60-0.85$: High<br>$\ge 0.85$: Critical | **YES** |
| **URL** | HistGradientBoosting Prob + Heuristics | $\tau = 0.74$ | Piecewise scaled; elevated to $\ge 90$ for confirmed brand impersonation | $< 0.20$: Safe<br>$0.20-0.45$: Low<br>$0.45-0.74$: Medium<br>$0.74-0.88$: High<br>$\ge 0.88$: Critical | **YES** |
| **Malware** | LightGBM Margin Prob | $\tau = 0.8336$ | Proportional probability scaling; clamped to $\le 10$ for benign non-PE files | $< 0.20$: Safe<br>$0.20-0.50$: Low<br>$0.50-0.70$: Medium<br>$0.70-0.85$: High<br>$\ge 0.85$: Critical | **YES** |
| **Media** | Supervised Prob + FFT Discontinuity | $\tau_{\text{aud}} = 0.50$<br>$\tau_{\text{vis}} = 0.64$ | Blend of classifier probability and high-frequency spectral artifact severity | $< 0.30$: Safe<br>$0.30-0.50$: Low<br>$0.50-0.65$: Medium<br>$0.65-0.85$: High<br>$\ge 0.85$: Critical | **YES** |

---

## 11. XAI (Explainable AI)

All engine explanations avoid absolute claims of fact ("this proves malware") and use grounded, defensible forensic language:
- Phishing: *"Message exhibits extreme urgency cues demanding credential verification and contains unverified link targets."*
- URL: *"Domain mimics PayPal brand patterns, was registered on a high-risk TLD, and matches active phishing structural signatures."*
- Malware: *"Static PE inspection of 'binary.exe' identified characteristic malware patterns across byte entropy (7.34), 6 sections (entry: '.text'), and 14 imported libraries."*
- Media: *"Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative neural TTS models."*

---

## 12. Dataset / Model Limitations

1. **Phishing Engine**:
   - Text-only input; cannot inspect images embedded in emails.
   - Cross-corpus evaluation on historical TREC 2007 yields lower recall (68.4%) than in-source test (98.0%) due to 2007 vs modern phrasing shift.
2. **URL Engine**:
   - Evaluates static URL lexical and structural patterns. Redirect chains (e.g. URL shorteners) require gateway-level DNS/HTTP resolution to inspect the ultimate target.
   - Recall on held-out unseen domains is 79.35% (conservative high-precision tuning: 97.19% precision).
3. **Malware Engine**:
   - Model was trained on EMBER 2018; benchmark metrics (98.32% accuracy at 0.92% FPR) reflect static PE evaluation and do not represent a universal guarantee against novel obfuscation/packing techniques.
4. **Deepfake Engine**:
   - Audio: 72% test accuracy on held-out unseen TTS engines (Kokoro, Hume AI); performance will vary against unseen generative architectures.
   - Visual: 74.35% balanced accuracy on held-out DFDC partition; relies on face alignment, falling back to 2D FFT spectral forensic analysis for face-less frames.

---

## 13. Model Versioning

All models have explicit version tags, feature schema definitions, and timestamped metadata:
- Phishing: `v1.0.0` (`phishing_metadata_v1.0.0.json`, `phishing_schema_v1.0.0.json`)
- URL: `v1.0.0` (`malicious_url_metadata_v1.0.0.json`, `malicious_url_schema_v1.0.0.json`)
- Malware: `v1.0.0` (`malware_metadata_v1.0.0.json`, `malware_schema_v1.0.0.json`)
- Deepfake Audio: `v1.0.0` (`deepfake_audio_metadata.json`, `deepfake_audio_schema.json`)
- Deepfake Visual: `v1.0.0` (`deepfake_visual_metadata.json`, `deepfake_visual_schema.json`)

---

## 14. Test Results

### Full Regression Suite
- **Command:** `pytest services/ml-service/tests/ -q`
- **Total Tests:** 230
- **Passed:** 230 (100%)
- **Failed:** 0
- **Skipped:** 0
- **Duration:** 33.87 seconds

### Targeted Engine Tests
- Phishing (`test_phishing_model.py`): 5 passed in 2.90s.
- Malicious URL (`test_url_engine_supervised.py`): 7 passed in 9.93s.
- Malware (`test_malware_engine.py`): 11 passed in 6.99s.
- Deepfake Media (`test_media_engine.py` + `test_dfdc_visual_engine.py`): 28 passed in 8.36s.

---

## 15. Git / Scope Verification

1. **Frontend Isolation**:
   ```bash
   git diff -- apps/web/
   # Output: completely empty (0 files modified)
   ```
2. **Secret Detection Isolation**:
   `services/backend/src/services/secretDetector.js` is completely untouched.
3. **Modified Production Files in Hardening Workflow**:
   - `services/ml-service/app/services/malware_engine.py` (New Phase 3 static PE engine)
   - `services/ml-service/app/utils/ember_feature_extractor.py` (New Phase 3 EMBER extractor)
   - `services/ml-service/app/routers/analyzeRouter.py` (Added `POST /analyze/malware`)
   - `services/ml-service/app/schemas/analyzeSchema.py` & `analyze.py` (Added `MalwareAnalyzeRequest`)
   - `services/ml-service/app/main.py` (Mounted router roots and direct `/analyze`)
   - `docs/API_CONTRACT.md` (Documented Section 8.6 Analyze Malware)

---

## 16. Known Limitations

- Real-world threats evolve continually. Benchmark metrics establish verifiable baselines on frozen test partitions but do not constitute universal immunity against novel zero-day attack methodologies.
- The microservice operates strictly as a stateless, real-time forensic detection tier; stateful response automation and incident lifecycle management remain the responsibility of the API Gateway and SOC dashboard layers.

---

## 17. Production Readiness Decision

Based on the verification of all model artifacts, 100% deterministic reproducibility, strict API contract compliance, thorough security isolation (zero malware execution, zero frontend/secret detector changes), and 230/230 passing regression tests:

### **DECISION: PASS WITH DOCUMENTED LIMITATIONS**
