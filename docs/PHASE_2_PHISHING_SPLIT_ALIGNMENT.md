# CYBERGUARD Phase 2 — Phishing Dataset Split Alignment Verification Report

**Document Version:** 1.0.0  
**Status:** VERIFIED & DETERMINISTIC  
**Author:** CYBERGUARD ML Lead  
**Dataset:** `datasets/cleaned_manifests/phishing_curated_manifest.parquet`  
**Execution Timestamp:** 2026-10-04T07:40:33Z  

---

## 1. Original v1.0.0 Split Strategy

The original production v1.0.0 model was trained using the pipeline defined in `services/ml-service/scripts/train_phishing_classifier.py`.
- **Composite Stratification Key:**
  ```python
  df["strata_key"] = df["dataset_source"].str.lower() + "_" + df["target"].astype(str)
  ```
- **Partitioning Algorithm:** Two-stage `StratifiedShuffleSplit` with fixed seed `42`:
  - Outer split: 80% Train, 20% Temp (Validation + Test)
  - Inner split: 50% of Temp $\to$ 10% Validation, 50% of Temp $\to$ 10% Test
- **Purpose:** Guarantees that every source sub-cohort (Nazario, Nigerian Fraud, CEAS threat, CEAS benign, Enron, SpamAssassin) is represented in exact, identical proportions across all three partitions without inter-partition leakage.

---

## 2. Initial Phase 1 Split Strategy

In Phase 1, `services/ml-service/scripts/curate_and_manifest_datasets.py` generated the initial manifest split using single-target stratification:
- **Key Used:**
  ```python
  sss1.split(df, df["label"])
  ```
- **Consequence:** The global binary class distribution was preserved (3,719 negative / 649 positive in test), but the individual source sub-cohorts drifted slightly (e.g., Nazario had 153 test samples instead of 156; Nigerian Fraud had 333 instead of 331).

---

## 3. Before vs. After Differences

| Metric / Cohort | Phase 1 Initial Manifest Split | Aligned v1.0.0 Manifest Split | Expected v1.0.0 Test Target |
|---|---|---|---|
| **Stratification Key** | `label` only | `dataset_source.lower() + "_" + label` | Composite key |
| **Total Test Samples** | 4,368 | 4,368 | 4,368 |
| **Test Negative (0)** | 3,719 | 3,719 | 3,719 |
| **Test Positive (1)** | 649 | 649 | 649 |
| **Nazario (Test)** | 153 | **156** | **156** |
| **Nigerian Fraud (Test)** | 333 | **331** | **331** |
| **CEAS 2008 (Test)** | 1,869 | **1,893** | **1,893** |
| *— CEAS 2008 Threat (1)* | 163 | **162** | **162** |
| *— CEAS 2008 Benign (0)* | 1,706 | **1,731** | **1,731** |
| **Enron (Test)** | 1,596 | **1,579** | **1,579** |
| **SpamAssassin (Test)** | 417 | **409** | **409** |

---

## 4. Final Split Counts

Every single record from the 43,680 curated dataset is accounted for with zero missing and zero overlapping records:

- **Train Partition:** 34,944 records (80.0%)
- **Validation Partition:** 4,368 records (10.0%)
- **Held-Out Test Partition:** 4,368 records (10.0%)
- **Total Records:** 43,680 records (100.0%)

```text
Intersection Checks:
- Train ∩ Validation: 0 records
- Train ∩ Test:       0 records
- Validation ∩ Test:  0 records
- Union of Splits:    43,680 records (Exact match)
```

---

## 5. Source / Label Distribution in Aligned Manifest

### 5.1 By Split and Class:
| Split | Benign (`label = 0`) | Threat (`label = 1`) | Total |
|---|---|---|---|
| **Train** | 29,750 | 5,194 | 34,944 |
| **Validation** | 3,719 | 649 | 4,368 |
| **Test** | 3,719 | 649 | 4,368 |
| **Total** | **37,188** | **6,492** | **43,680** |

### 5.2 Test Partition Sub-Cohorts (Exact Match to v1.0.0 Metadata):
- **Nazario Credential Phishing:** 156 samples (100% threat lures)
- **Nigerian Advance-Fee Fraud:** 331 samples (100% social engineering lures)
- **CEAS 2008 Mixed:** 1,893 samples (162 threat lures, 1,731 legitimate emails)
- **Enron Corporate:** 1,579 samples (100% legitimate corporate communications)
- **SpamAssassin:** 409 samples (100% legitimate personal/technical correspondence)

---

## 6. Backup Path & Checksums

Prior to performing the alignment, a full binary backup of the original Phase 1 manifest was created:
- **Backup File Path:** `datasets/cleaned_manifests/backups/phishing_curated_manifest_phase1_initial.parquet`
- **Backup File SHA-256:** `33594dedee64dfa4057d76094d5bfc0717d2d21e7bcca5cdcb00bb34997dbe3b`

---

## 7. Determinism & Integrity Verification

1. **Two-Pass Determinism Test:**
   - The split algorithm was executed twice on fresh dataframe instances using `random_state=42`.
   - The resulting row index sets for Train, Validation, and Test partitions were verified to be **100% bit-for-bit identical** across both passes.
2. **Aligned Manifest Checksum:**
   - Parquet File: `datasets/cleaned_manifests/phishing_curated_manifest.parquet`
   - Parquet SHA-256: `21afa541187266f17af47d7007c3f48d1f9bb51ec82a170b3913595e17872954`
3. **Split Assignment Signature:**
   - SHA-256 over split column sequence: `75d91078e633f8e90e139b0639b1d493d1345a32796b12ed01e2fa8af7233640`

---

## 8. Files Changed & Created

### Files Created:
1. `datasets/cleaned_manifests/backups/phishing_curated_manifest_phase1_initial.parquet` (Reproducibility backup)
2. `services/ml-service/scripts/align_phishing_manifest_split.py` (Deterministic alignment script)
3. `docs/PHASE_2_PHISHING_SPLIT_ALIGNMENT.md` (This document)

### Files Modified:
1. `datasets/cleaned_manifests/phishing_curated_manifest.parquet` (Updated `split` column only; all text, labels, and metadata remain untouched)
2. `datasets/cleaned_manifests/phishing_curated_manifest.csv.gz` (Synchronized compressed CSV)
3. `datasets/cleaned_manifests/phishing_curated_summary.json` (Updated split distribution and alignment metadata)

---

## 9. Confirmation of Production Safety

- **ZERO changes to production inference code:** `services/ml-service/app/services/message_engine.py` is unmodified.
- **ZERO changes to production model artifacts:**
  - `services/ml-service/app/models/phishing/phishing_classifier_v1.0.0.joblib` is unmodified.
  - `services/ml-service/app/models/phishing/phishing_vectorizer_v1.0.0.joblib` is unmodified.
  - `services/ml-service/app/models/phishing/phishing_metadata_v1.0.0.json` is unmodified.
  - `services/ml-service/app/models/phishing/phishing_schema_v1.0.0.json` is unmodified.
- **ZERO changes to other engines:** URL, Malware, Deepfake, Login, Network, and System engines are completely untouched.
- **ZERO changes to frontend or secret detection:** `apps/web/` and `services/backend/src/services/secretDetector.js` are completely untouched.
- **ZERO model retraining:** No training was performed; this step strictly establishes identical data partitioning conditions.

---

```text
PHASE 2 STEP 2 STATUS: SPLIT ALIGNMENT COMPLETE & VERIFIED
```
