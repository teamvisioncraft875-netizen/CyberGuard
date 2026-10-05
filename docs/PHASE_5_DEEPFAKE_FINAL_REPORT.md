# CYBERGUARD — Phase 5 Deepfake Detection Engine: Final End-to-End Report

**Status:** COMPLETE & PROMOTED TO PRODUCTION  
**Date:** October 4, 2026  
**Module:** Media & Deepfake Detection Engine (`services/ml-service/app/services/media_engine.py`)  
**Production Artifacts:**
- Visual Deepfake Model: `services/ml-service/app/models/deepfake_visual_classifier.pt` (SHA-256: `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3`)
- Audio Deepfake Model: `services/ml-service/app/models/deepfake_audio_classifier.joblib` (SHA-256: `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7`)

---

## 1. Executive Summary

Phase 5 finalized and hardened the **Media & Deepfake Detection Engine** for CYBERGUARD. The engine provides defense-in-depth multimedia threat detection across two critical enterprise attack vectors:
1. **Visual Deepfakes:** AI-generated face swaps, synthetic facial impersonations, and generative video tampering detected via a hybrid pipeline combining a PyTorch temporal attention network (`AttentionPoolingVisualDetector`) on CLIP ViT-H/14 embeddings with 2D Fast Fourier Transform (FFT) periodic lattice spectral analysis.
2. **Audio Deepfakes & Voice Cloning:** Synthetic voice clones, text-to-speech CEO fraud, and neural vocoder artifacts detected via standardized 16 kHz acoustic feature extraction paired with a supervised linear classifier.

All models were evaluated on genuine held-out test partitions without synthetic data, achieving **74.35% Balanced Accuracy (0.7966 ROC-AUC)** on the official 2,242-sample visual test partition, and **72.00% Balanced Accuracy (0.7856 ROC-AUC)** on 50 source-disjoint test audio recordings across 17 unseen speaker identities.

---

## 2. Dataset Provenance & Zero Synthetic Data Verification

1. **Visual Benchmark (DFDC Shield 2026):**
   - **Source:** Aggregated from the DeepFake Detection Challenge (DFDC-10), FaceForensics++ (C23), and Celeb-DF v2.
   - **Partitioning:**
     - Train: 10,458 samples (1,112 genuine, 9,346 manipulated)
     - Validation: 2,241 samples (238 genuine, 2,003 manipulated)
     - Test: 2,242 samples (239 genuine, 2,003 manipulated)
     - Total: 14,941 samples ($1 : 8.4$ class imbalance).
   - **Representation:** Sequences of 20 frames $\times$ 1,024-dimensional feature embeddings extracted using **CLIP ViT-H/14** (`laion2b_s32b_b79k`) with L2 unit hypersphere normalization.
   - **Quality:** Zero NaNs, zero Infs, zero cross-partition sample overlap.
2. **Audio Benchmark (Curated Deepfake Audio):**
   - **Source:** Standardized 16 kHz mono acoustic speech recordings across 87 human speaker sources and state-of-the-art TTS/voice-cloning models.
   - **Partitioning:**
     - Train: 140 samples (70 real, 70 fake; 47 unique sources)
     - Validation: 50 samples (25 real, 25 fake; 23 unique sources)
     - Test: 50 samples (25 real, 25 fake; 17 unique sources)
     - Total: 240 samples.
   - **Source Disjointness:** Strictly 0 speaker source overlap across splits, eliminating identity leakage.
3. **Podonos Benchmark Status:**
   - 4,524 files in `datasets/audio-dfd-benchmark/` lack public ground-truth labels (`labels_speech.csv` is withheld by benchmark authors for email scoring). In strict compliance with the **Zero Synthetic/Fabricated Data** mandate, this dataset was omitted from training rather than inventing labels.

---

## 3. Production Model Architecture & Hyperparameters

### A. Visual Deepfake Detector (`AttentionPoolingVisualDetector`)
- **PyTorch Module:** 412,417 parameters (1.57 MB).
- **Temporal Attention Head:**
  $$\text{Score}(x_t) = W_2 \tanh(W_1 x_t + b_1) + b_2, \quad \alpha_t = \text{Softmax}(\text{Score}(x_t))$$
  $$\text{Embedding} = \sum_{t=1}^{20} \alpha_t x_t$$
- **Classification MLP Head:**
  $$\text{Embedding} \xrightarrow{\text{Linear}(1024, 256)} \xrightarrow{\text{LayerNorm}} \xrightarrow{\text{ReLU}} \xrightarrow{\text{Dropout}(0.3)} \xrightarrow{\text{Linear}(256, 64)} \xrightarrow{\text{LayerNorm}} \xrightarrow{\text{ReLU}} \xrightarrow{\text{Dropout}(0.3)} \xrightarrow{\text{Linear}(64, 1)}$$
- **Loss Formulation:** Weighted Binary Cross-Entropy with Logits (`pos_weight = 0.119`) to counterbalance the 1:8.4 class imbalance.
- **Operating Threshold:** $\tau = 0.6400$ (selected purely on validation data).

### B. Audio Deepfake Classifier (`LogisticRegression`)
- **Scikit-Learn Classifier:** 13 standardized acoustic features invariant to sampling rate and file formats.
- **Features Extracted:** Zero-crossing rate, spectral centroid, 85%/95% spectral rolloffs, spectral flux, 4k-8k sub-band ratios, spectral flatness, high-frequency cutoff flag, mean F0 pitch, pitch jitter percentage, and forensic anomaly score.
- **Operating Threshold:** $\tau = 0.5000$.

---

## 4. Final Benchmark Performance Summary

| Evaluation Dimension | Visual Deepfake Detector (Candidate B) | Audio Deepfake Classifier (Production) |
| :--- | :--- | :--- |
| **Target Partition** | Held-Out Test Set (2,242 samples) | Source-Disjoint Test Set (50 samples) |
| **Operating Threshold** | **$\tau = 0.6400$** | **$\tau = 0.5000$** |
| **Balanced Accuracy** | **74.35%** | **72.00%** |
| **Overall Accuracy** | **65.03%** | **72.00%** |
| **Recall (Detection Rate)** | **62.51%** (1,252 / 2,003 manipulated detected) | **72.00%** (18 / 25 manipulated detected) |
| **Specificity** | **86.19%** (206 / 239 genuine safe) | **72.00%** (18 / 25 genuine safe) |
| **False Positive Rate** | **13.81%** | **28.00%** |
| **Precision** | **97.43%** | **72.00%** |
| **F1-Score** | **0.7616** | **0.7200** |
| **ROC-AUC** | **0.7966** | **0.7856** |
| **PR-AUC** | **0.9722** | **0.8317** |
| **Inference Latency** | **0.588 ms** (pure model CPU) / ~45 ms (with 2D FFT) | **~86 ms** (including 16 kHz polyphase resample) |
| **Model Size** | **1.57 MB** (1,647,761 bytes) | **1,503 bytes** |
| **SHA-256 Checksum** | `d1ae1d66f72196c8b4e679edd319817dfae8b479ac7aa6792b0b52934b0bc5b3` | `1a9c3a03b3b596e06b087e6718ed0e52348105aa0cc5598b36ee58778a2e73c7` |

---

## 5. API Integration & Production Verification

1. **FastAPI ML Route (`POST /analyze/media`):**
   - Wired at `/analyze/media`, `/internal/analyze/media`, and `/api/v1/analyze/media`.
   - Supports both `multipart/form-data` uploads (up to 10 MB) and `application/json` base64 data URIs.
   - Enforces strict SSRF protection against private IP ranges and cloud metadata endpoints.
   - Returns calibrated 5-tier `UnifiedAnalysisResponse`:
     - `risk_level`: Safe, Low, Medium, High, Critical
     - `risk_score`: 0–100 integer
     - `explanation`: Plain-English forensic explanation detailing spectral peaks, high-frequency ratio, or pitch jitter
     - `signals`: Extracted forensic indicators, spectral peaks, high-frequency ratio, F0 pitch, and classifier verdict
     - `recommended_actions`: Prescriptive enterprise SOC guidance
     - `confidence_score`: Statistical confidence $[0.0, 1.0]$.
2. **Express Backend Gateway (`POST /api/v1/check/media`):**
   - Validates user media ownership and forwards payload to FastAPI `/internal/analyze/media`.

---

## 6. Test Suite Execution & Verification

- **Focused Media Test Suites:** **47 / 47 PASSED (100% in 12.51s)**
  - `pytest tests/test_dfdc_visual_engine.py` (10 passed)
  - `pytest tests/test_media_engine.py` (18 passed)
  - `pytest tests/test_media_validation.py` (19 passed)
- **Full ML Test Suite:** **230 / 230 PASSED (100% in 39.57s)**
  - Zero failures across all 28 test modules covering URL, Phishing, Malware, Network, Login, System, and Media engines.

---

## 7. Limitations & Operational Mitigations

1. **Pre-Extracted CLIP Representations:** The visual deepfake dataset consists of pre-extracted CLIP ViT embeddings rather than raw video files. In production, image inputs undergo 2D FFT spectral analysis and are scored via continuous forensic anomaly scoring and feature representations.
2. **Imbalanced Training Distribution:** The DFDC benchmark has an $8.4 : 1$ manipulated-to-genuine ratio. The loss function was calibrated using `pos_weight = 0.119` and decision threshold $\tau = 0.6400$ to maintain strong specificity (86.19%) while intercepting 62.51% of deepfakes.
3. **Voice Cloning Generalization:** While audio testing confirmed 72.00% detection accuracy on unseen speaker identities, completely novel zero-shot diffusion vocoders should be monitored with periodic retraining as new generator architectures emerge.
