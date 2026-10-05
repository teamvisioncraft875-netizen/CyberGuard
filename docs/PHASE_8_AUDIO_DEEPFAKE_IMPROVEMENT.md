# CYBERGUARD — Phase 8.3 Audio Deepfake Detection Improvement

## Document Metadata
- **Phase:** Phase 8.3 — Audio Deepfake Improvement: Controlled Candidate Training & Validation
- **Status:** Complete (Phase 8.3 Evaluated; Promotion Recommendation Formulated)
- **Date:** 2026-10-05
- **Dataset:** Curated Deepfake Audio Benchmark (`datasets/deepfake-audio-detection/manifest.csv`)
- **Partitions:**
  - Training: 140 samples (70 real / 70 fake, 47 unique speakers)
  - Validation: 50 samples (25 real / 25 fake, 23 unique speakers)
  - Frozen Final Test: 50 samples (25 real / 25 fake, 17 unseen speakers)
- **Primary Script:** `services/ml-service/scripts/train_audio_candidates_phase8.py`
- **Audit Script:** `services/ml-service/scripts/phase8_dataset_hardening.py`
- **Production Artifact Integrity:** `services/ml-service/app/models/media/deepfake_audio_classifier.joblib` (UNTOUCHED)

---

## 1. Executive Summary & Production Promotion Recommendation

### Formal Decision: **KEEP v1.0.0 AS PRODUCTION**

Per the pre-registered Promotion Rule:
> *"Candidate qualifies for promotion consideration ONLY if final test evidence shows a meaningful improvement over production. If improvement is marginal, mixed, or worse: KEEP v1.0.0 AS PRODUCTION. That is a VALID SUCCESSFUL OUTCOME."*

### Scientific & Operational Evaluation:
1. **Validation Performance:** Candidate A (StandardScaler + LogisticRegression on 28 features) dominated validation, achieving 92.00% Balanced Accuracy, 88.00% Recall, 96.00% Specificity, and 0.9552 ROC-AUC at operating threshold $\tau = 0.1300$.
2. **Frozen Final-Test Generalization:** When evaluated strictly **once** on the frozen final test set of 17 unseen speakers:
   - **Recall surged to 100.00%** (25/25 synthetic clips detected, 0 False Negatives vs 7 in production).
   - **ROC-AUC rose to 0.8992** (+0.1136 over production 0.7856).
   - **PR-AUC rose to 0.8762** (+0.0445 over production 0.8317).
   - **Balanced Accuracy rose to 74.00%** (+2.00% over production 72.00%).
   - **F1 Score rose to 0.7937** (+0.0737 over production 0.7200).
3. **The Unseen-Speaker Calibration Dilemma (Mixed Outcome):**
   - At the frozen threshold $\tau = 0.1300$, Candidate A produced 13 False Positives on unseen benign speakers (FPR = 52.00%, Specificity = 48.00%), compared to 7 False Positives (FPR = 28.00%, Specificity = 72.00%) in the baseline.
   - In enterprise security monitoring, an FPR of 52.00% on unseen human speakers breaches the operational constraint ($\text{Specificity} \ge 80.0\%$, $\text{FPR} \le 20.0\%$).
   - Because post-hoc threshold tuning on the final test set is strictly prohibited by scientific isolation rules, the frozen candidate evidence is **MIXED** (flawless threat recall vs elevated false alarm rate on unseen acoustic channels).
4. **Action:** The existing production audio model (`services/ml-service/app/models/media/deepfake_audio_classifier.joblib`, v1.0.0, $\tau = 0.5000$) remains active in production. Candidate A and its trained artifacts remain securely archived for future multi-speaker calibration studies.

---

## 2. Dataset Integrity & Isolation Verification

Before training, programmatic assertions verified:
- **Total Dataset Size:** 240 WAV audio clips standardized to 16 kHz mono float32.
- **Split Partitions:** Train: 140, Validation: 50, Frozen Test: 50.
- **Class Balance:**
  - Train: 70 real (0), 70 manipulated (1) [1.00:1 ratio]
  - Validation: 25 real (0), 25 manipulated (1) [1.00:1 ratio]
  - Test: 25 real (0), 25 manipulated (1) [1.00:1 ratio]
- **Speaker Disjointness:** 
  - Train: 47 unique speaker IDs
  - Validation: 23 unique speaker IDs
  - Test: 17 unique speaker IDs
  - $\text{Train} \cap \text{Val} = \emptyset$ (0 overlap)
  - $\text{Train} \cap \text{Test} = \emptyset$ (0 overlap)
  - $\text{Val} \cap \text{Test} = \emptyset$ (0 overlap)
- **Preprocessing Isolation:** `StandardScaler` was fitted **exclusively on `X_train`**. Validation and test matrices were transformed using the frozen train scaler parameters. Test labels were completely quarantined during feature extraction, training, threshold tuning, and model selection.

---

## 3. Forensic Acoustic Feature Schema (28 Features)

Addressing the Phase 8.0 root-cause findings (where the baseline used only 13 coarse unscaled acoustic features), an expanded 28-feature schema was developed:

### Base Acoustic & Spectral Features (13 features):
1. `zero_crossing_rate`: Rate of sign-changes in audio signal.
2. `spectral_centroid_hz`: Power-weighted mean frequency of spectrum.
3. `spectral_rolloff_85_hz`: Frequency below which 85% of spectral energy resides.
4. `spectral_rolloff_95_hz`: Frequency below which 95% of spectral energy resides.
5. `spectral_flux`: Frame-to-frame Euclidean spectral distance.
6. `subband_ratio_4k_to_8k`: Energy ratio in the 4 kHz–7.6 kHz harmonic band.
7. `subband_ratio_2k_to_4k`: Mid-formant energy ratio (2 kHz–4 kHz).
8. `high_freq_ratio_4k`: Total energy ratio $\ge 4\text{ kHz}$.
9. `spectral_flatness`: Wiener entropy (geometric mean / arithmetic mean of power spectrum).
10. `high_freq_cutoff_detected`: Binary flag indicating artificial high-frequency suppression (< 4.6 kHz rolloff + low 4–8 kHz ratio).
11. `mean_f0_hz`: Fundamental pitch frequency via normalized autocorrelation.
12. `pitch_jitter_pct`: Pitch period variability (detects robotic invariance or metallic glitch spikes).
13. `anomaly_score`: Heuristic composite anomaly indicator $[0.05, 0.95]$.

### Advanced Forensic Features (15 features):
14–23. `mfcc_1_mean` through `mfcc_10_mean` (10 features): Mel-Frequency Cepstral Coefficients capturing vocal tract resonances and synthetic filterbank smearing.
24–27. `spectral_contrast_b1` through `spectral_contrast_b4` (4 features): Peak-to-valley energy difference across 4 frequency subbands ([200, 800], [800, 2000], [2000, 4000], [4000, 8000] Hz).
28. `spectral_bandwidth_hz` (1 feature): Spectral spread / second central moment around the spectral centroid.

---

## 4. Controlled Candidate Architectures & Training Configuration

All models trained with `random_state = 42` using `StandardScaler` fitted strictly on `X_train`:

- **Candidate A:** `StandardScaler` + `LogisticRegression(C=1.0, max_iter=1000, random_state=42)`
  - *Purpose:* Corrects the severe feature-scale imbalance (e.g. spectral rolloff ~2300 Hz vs subband ratio ~0.02) and incorporates the 15 additional formant/contrast features while preserving linear simplicity.
- **Candidate B:** `StandardScaler` + `RandomForestClassifier(n_estimators=100, max_depth=5, min_samples_split=4, min_samples_leaf=2, random_state=42)`
  - *Purpose:* Calibrated non-linear decision boundaries with depth regularization to prevent overfitting on 140 training samples.
- **Candidate C:** `StandardScaler` + `HistGradientBoostingClassifier(max_depth=3, min_samples_leaf=10, l2_regularization=1.0, random_state=42)`
  - *Purpose:* Conservative gradient boosting with L2 shrinkage for low-sample tabular regimes.

---

## 5. Candidate Validation Performance (Frozen Test Set Not Touched)

Thresholds were optimized on the validation set grid ($\tau \in [0.05, 0.95]$, step 0.01) to maximize Balanced Accuracy subject to the operational constraint $\text{Specificity} \ge 80.0\%$:

| Candidate | Selected $\tau$ | Accuracy | Balanced Acc | Precision | Recall | Specificity | F1 Score | FPR | ROC-AUC | PR-AUC |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Candidate A** (StandardScaler + LogisticRegression) | **0.1300** | **92.00%** | **92.00%** | **95.65%** | **88.00%** | **96.00%** | **0.9167** | **4.00%** | **0.9552** | **0.9680** |
| **Candidate B** (StandardScaler + RandomForest) | 0.3500 | 90.00% | 90.00% | 88.46% | 92.00% | 88.00% | 0.9020 | 12.00% | 0.9456 | 0.9557 |
| **Candidate C** (StandardScaler + HistGradientBoosting) | 0.2000 | 84.00% | 84.00% | 81.48% | 88.00% | 80.00% | 0.8462 | 20.00% | 0.8944 | 0.9229 |

### Validation Selection Decision:
**Candidate A (StandardScaler + LogisticRegression)** achieved the highest Validation Balanced Accuracy (92.00%), highest Specificity (96.00%), lowest FPR (4.00%), highest Precision (95.65%), and highest ROC-AUC (0.9552). In accordance with the protocol, Candidate A was selected as the winning candidate for single-pass evaluation on the frozen final test gate at operating threshold $\tau = 0.1300$.

---

## 6. Final Test Gate Evaluation (Untouched Test Set)

Candidate A was evaluated **exactly once** on the frozen final test set (50 samples, 17 unseen speakers: 25 real, 25 fake) with its frozen operating threshold $\tau = 0.1300$:

### Head-to-Head Comparison: Current Production vs Candidate A

| Metric | Production Baseline (v1.0.0) | Candidate A (Phase 8.3) | Delta | Assessment |
|:---|:---|:---|:---|:---|
| **Architecture** | LogisticRegression (13 feats, unscaled) | StandardScaler + LogisticRegression (28 feats) | Normalized 28-dim | Scaled Formant Space |
| **Operating Threshold ($\tau$)** | 0.5000 | 0.1300 | -0.3700 | Calibrated on Val |
| **Accuracy** | 72.00% | 74.00% | +2.00% | Improved |
| **Balanced Accuracy** | 72.00% | 74.00% | +2.00% | Improved |
| **Recall** | **72.00%** | **100.00%** | **+28.00%** | **Flawless Threat Capture** |
| **Precision** | 72.00% | 65.79% | -6.21% | Lower |
| **Specificity** | **72.00%** | **48.00%** | **-24.00%** | **Degraded on Unseen Channels** |
| **F1 Score** | 0.7200 | 0.7937 | +0.0737 | Improved |
| **False Positive Rate (FPR)** | **28.00%** | **52.00%** | **+24.00%** | **Elevated False Alarms** |
| **ROC-AUC** | **0.7856** | **0.8992** | **+0.1136** | **Substantial Discrimination Gain** |
| **PR-AUC** | **0.8317** | **0.8762** | **+0.0445** | Improved |
| **False Negatives (FN)** | **7** | **0** | **-7** | **Zero Missed Deepfakes** |
| **False Positives (FP)** | **7** | **13** | **+6** | Higher False Positives |
| **Inference Latency** | 0.082 ms | 0.122 ms | +0.040 ms | Negligible overhead |
| **Model Size** | 1.06 KB | 3.14 KB | +2.08 KB | Extremely lightweight |

### Confusion Matrix Breakdown:
- **Baseline (v1.0.0):** $\text{TN}=18$, $\text{FP}=7$, $\text{FN}=7$, $\text{TP}=18$
- **Candidate A (Phase 8.3):** $\text{TN}=12$, $\text{FP}=13$, $\text{FN}=0$, $\text{TP}=25$

---

## 7. Analysis of the Generalization Tradeoff

The experiment reveals a fundamental forensic phenomenon in voice cloning detection:
1. **The Representation Advance:** Adding MFCCs, spectral contrast, and spectral bandwidth alongside `StandardScaler` dramatically increased the underlying discriminative power of the model. This is demonstrated by the large jump in ROC-AUC from **0.7856 to 0.8992** (+0.1136) and PR-AUC from **0.8317 to 0.8762**.
2. **The Calibration Sensitivity:** Because the validation set contained 23 speakers and the test set contained 17 completely unseen speakers with varied microphone frequency responses, optimizing threshold $\tau$ strictly for balanced accuracy on validation produced $\tau = 0.1300$. When deployed against unseen acoustic environments, this sensitive threshold captured **100% of all synthetic attacks** (0 false negatives), but misclassified 13 benign audio clips as suspicious.
3. **Operational Decision:** Because CYBERGUARD is an automated enterprise defense pipeline, increasing false alarm rates to 52.00% is unacceptable for autonomous blocking. Therefore, adhering to strict zero-leakage standards, the model cannot be re-tuned post-test, and the candidate **does not qualify for production replacement**.

---

## 8. Artifacts & Reproducibility Evidence

The experiment artifacts are fully serialized and reproducible:

- **Experiment Directory:** `services/ml-service/experiments/audio_candidates_phase8_20261004_215342/`
- **Candidate A Artifact:** `services/ml-service/experiments/audio_candidates_phase8_20261004_215342/candidate_a.joblib`
  - Size: 3,139 bytes
  - SHA-256: `c70935c53b1537449248a124508b1d774425ac300aacffcfb91cdf4881223700`
- **Candidate B Artifact:** `services/ml-service/experiments/audio_candidates_phase8_20261004_215342/candidate_b.joblib`
  - Size: 175,280 bytes
  - SHA-256: `be2178eec157b6ce7429f0fc6b6376315f6b4506252b806062b5d3a408dd2f9c`
- **Candidate C Artifact:** `services/ml-service/experiments/audio_candidates_phase8_20261004_215342/candidate_c.joblib`
  - Size: 100,536 bytes
  - SHA-256: `03c8ca5b917a9d6d38cada0bc507fea24845ae28c51fa988440f7bc6b4838891`
- **Evaluation Report JSON:** `services/ml-service/experiments/audio_candidates_phase8_20261004_215342/audio_candidate_evaluation_report.json`
- **Production Artifact (Intact):** `services/ml-service/app/models/media/deepfake_audio_classifier.joblib` (`fe7cfa70caea60144d156557876e58b8f2c002eeea60f089694cebcba0ce022b`)

---

## 9. Test Suite Verification

Regression verification was executed across the media engine suite:
- `pytest tests/test_media_engine.py -v`: **18 passed, 0 failed** (6.60s)
- `pytest tests/test_dfdc_visual_engine.py -v`: **10 passed, 0 failed** (9.01s)
- **Total:** **28 of 28 passed (100%)**, 0 regressions.
- **Production Status:** Confirmed that NO production model, threshold, or registry entry was modified.
