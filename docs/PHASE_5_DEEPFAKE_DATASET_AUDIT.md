# CYBERGUARD — Phase 5A: Deepfake Dataset and Feature Audit Report

**Audit Status:** COMPLETE & VERIFIED  
**Date:** October 4, 2026  
**Audited Datasets:**
1. **DFDC Shield 2026 Visual Deepfake Benchmark** (`datasets/DFDC/shield_2026_final_data/`)
2. **Curated Deepfake Audio Benchmark** (`datasets/deepfake-audio-detection/`)

---

## 1. Executive Summary

Phase 5A evaluated the integrity, provenance, dimensionality, and split isolation of the real-world deepfake datasets available to the CYBERGUARD Media/Deepfake Detection Engine.

All datasets strictly adhere to the **Zero Synthetic Data** protocol:
- **Visual Dataset:** Pre-extracted sequences of 20 frames $\times$ 1,024-dimensional feature embeddings generated from **CLIP ViT-H/14** (`laion2b_s32b_b79k`) across DFDC-10, FaceForensics++ (C23), and Celeb-DF v2.
- **Audio Dataset:** Standardized 16 kHz mono acoustic speech recordings across 87 authentic human speaker sources and state-of-the-art voice cloning generators.

---

## 2. Visual Dataset Audit: DFDC Shield 2026

### A. Partition Dimension & Sample Inventory
- **Representation:** 3-dimensional tensor $[N, 20, 1024]$ where $N$ is the video sample count, 20 is the temporal frame dimension, and 1024 is the L2-normalized feature embedding dimension.

| Split | Tensor File | Shape | Total Samples | Genuine (0) | Manipulated (1) | Imbalance Ratio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | `X_train.pt` / `y_train.pt` | $[10458, 20, 1024]$ | 10,458 | 1,112 (10.63%) | 9,346 (89.37%) | $1 : 8.4$ |
| **Validation** | `X_val.pt` / `y_val.pt` | $[2241, 20, 1024]$ | 2,241 | 238 (10.62%) | 2,003 (89.38%) | $1 : 8.4$ |
| **Test** | `X_test.pt` / `y_test.pt` | $[2242, 20, 1024]$ | 2,242 | 239 (10.66%) | 2,003 (89.34%) | $1 : 8.4$ |
| **Total** | — | — | **14,941** | **1,589 (10.64%)** | **13,352 (89.36%)**| $1 : 8.4$ |

### B. Tensor Data Quality & Statistical Checks
- **NaN Count:** `0` (across all 14,941 $\times$ 20 $\times$ 1,024 = 306,000,000 float values)
- **Inf Count:** `0`
- **L2 Vector Normalization:** Mean L2 norm across all embeddings is **1.0000** (std: 0.0000). Every frame vector lies strictly on the unit hypersphere.
- **Feature Distribution:**
  - Min value: $-0.4589$
  - Max value: $+0.5372$
  - Mean: $0.000085$
  - Standard deviation: $0.03125$

### C. File Provenance & Cryptographic Checksums
| File | Size (Bytes) | Size (MB) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| `X_train.pt` | 856,720,937 | 817.03 MB | `da3a604c01e27ae837a6fcd40f4ca6ba6a656e3d9c6ea74a0e976d09ac4bb193` |
| `y_train.pt` | 85,225 | 0.08 MB | `30b1361664b48a4b5139671084d2affea6c6c952b524b6586201f82ea4dfa7a4` |
| `X_val.pt` | 183,584,219 | 175.08 MB | `3bc6894da2f104748bbf53bc6a261a81a5d1ee8c71ee54993659c8c022ef03c9` |
| `y_val.pt` | 19,483 | 0.02 MB | `048a3b1fe96ec22f75abe730a49b280fe961019f218a2de53c5bf1e1382be314` |
| `X_test.pt` | 183,666,146 | 175.16 MB | `450e0cfca0b186f9a01206945f45a7a9d1d53d5bee3d607b1a76e82714a22aa1` |
| `y_test.pt` | 19,490 | 0.02 MB | `b6dbde9991a98adf2cd7bcc2a6a656e9b638fcd9153f869ddbe1ecb28aa66b01` |

### D. Partition Disjointness
- Exact pooled vector overlap between **Train and Validation:** `0`
- Exact pooled vector overlap between **Train and Test:** `0`
- Exact pooled vector overlap between **Validation and Test:** `0`
- Strict partition boundaries verified.

---

## 3. Audio Dataset Audit: Curated Deepfake Audio Benchmark

### A. Inventory & Provenance
- **Local Directory:** `datasets/deepfake-audio-detection/`
- **Manifest:** `datasets/deepfake-audio-detection/manifest.csv` (SHA-256: `cbe6cb1906233481237eb89dd43e62f5f190e5f891b058a94ee88eb44df08617`)
- **Total Physical Samples Verified:** 240 files (120 genuine, 120 manipulated)
- **Audio Standardization:** 16,000 Hz mono polyphase resampled, DC offset eliminated, peak normalized to $[-1.0, 1.0]$.

### B. Source-Disjoint Partitioning (Zero Identity Leakage)
| Partition | Samples | Genuine | Manipulated | Unique Speaker Sources | Source Overlap with Other Splits |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | 140 | 70 | 70 | 47 | **0 (Strictly Disjoint)** |
| **Validation** | 50 | 25 | 25 | 23 | **0 (Strictly Disjoint)** |
| **Test** | 50 | 25 | 25 | 17 | **0 (Strictly Disjoint)** |
| **Total** | **240** | **120** | **120** | **87** | **Zero Cross-Split Leakage** |

---

## 4. Hardware & Environment Verification

- **Python Version:** 3.14.6
- **PyTorch:** `2.14.0+cu126`
- **CUDA Device:** Active & Available (`NVIDIA GPU` with CUDA 12.6 support)
- **Deterministic Random Seed:** `42`
- **Audit Conclusion:** **PASS — All datasets, partition files, and feature dimensions verified for candidate training.**
