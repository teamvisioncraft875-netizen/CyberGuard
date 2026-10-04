# PHASE 3 — MALICIOUS URL MODEL ANALYSIS & BASELINE AUDIT
**CYBERGUARD Machine Learning Workstream**  
**Document Version:** 1.0.0  
**Status:** COMPLETE (STEP 0 AUDIT)  
**Date:** 2026-10-04  

---

## 1. Executive Summary & Objective

This document establishes the formal **Step 0: Malicious URL Model Analysis & Baseline Audit** for the CYBERGUARD Malicious URL Detection Engine. Following the same gated workflow successfully executed for Phase 2 Phishing, this audit analyzes the production v1.0.0 model architecture, feature representation, preprocessing pipeline, dataset provenance, domain-aware partitioning, threshold calibration, and evaluation metrics before attempting baseline reproduction or candidate exploration.

No production models or artifacts were modified during this audit.

---

## 2. Production Model Configuration & Hyperparameters

The current production Malicious URL Detection Model is a gradient boosted decision tree classifier serialized with Joblib.

- **Artifact Path:** `services/ml-service/app/models/url/malicious_url_classifier_v1.0.0.joblib`
- **Metadata Path:** `services/ml-service/app/models/url/malicious_url_metadata_v1.0.0.json`
- **Schema Path:** `services/ml-service/app/models/url/malicious_url_schema_v1.0.0.json`
- **Model Class:** `sklearn.ensemble.HistGradientBoostingClassifier`
- **Serialization:** `joblib.dump(..., compress=3)` (File size: ~278 KB)
- **Model Version:** `v1.0.0`
- **Random Seed:** `42`
- **Exact Hyperparameters:**
  - `learning_rate`: `0.1`
  - `max_iter`: `150`
  - `max_leaf_nodes`: `31`
  - `min_samples_leaf`: `20`
  - `class_weight`: `"balanced"`
  - `loss`: `"log_loss"`
  - `scoring`: `"loss"`
  - `validation_fraction`: `0.1`
  - `n_iter_no_change`: `10`
  - `l2_regularization`: `0.0`
  - `max_bins`: `255`
  - `tol`: `1e-07`

---

## 3. Feature Representation & Ordering

The model operates on an exact dense numerical vector of **16 lexical, structural, and brand-impersonation features**, extracted deterministically without external network queries.

| Index | Feature Name | Type | Description |
|:-----:|:-------------|:-----|:------------|
| 1 | `url_length` | Float | Total character length of URL string |
| 2 | `hostname_length` | Float | Character length of parsed hostname |
| 3 | `path_length` | Float | Character length of URL path component |
| 4 | `query_length` | Float | Character length of URL query parameters |
| 5 | `num_subdomains` | Float | Number of subdomains beyond base domain + TLD |
| 6 | `dot_count` | Float | Count of period (`.`) characters in URL |
| 7 | `hyphen_count` | Float | Count of hyphen (`-`) characters in URL |
| 8 | `digit_count` | Float | Count of numeric digits (0–9) |
| 9 | `digit_ratio` | Float | Ratio of digits to total URL length |
| 10 | `special_char_count` | Float | Count of special characters (`-@?=_&%#+/:`) |
| 11 | `entropy` | Float | Shannon character entropy of URL string |
| 12 | `is_https` | Float | Binary flag (1.0 = HTTPS, 0.0 = HTTP) |
| 13 | `has_ip_address` | Float | Binary flag (1.0 if hostname is raw IPv4 address) |
| 14 | `has_suspicious_keyword` | Float | Binary flag (1.0 if any credential/threat keyword present) |
| 15 | `is_suspicious_tld` | Float | Binary flag (1.0 if TLD is in high-abuse TLD set) |
| 16 | `is_brand_impersonated` | Float | Binary flag (1.0 if brand name present but domain unauthentic) |

### Keyword, TLD, and Brand Definitions:
- **Suspicious Keywords (18):** `login`, `verify`, `account`, `banking`, `secure`, `update`, `signin`, `confirm`, `billing`, `abonnements`, `loading`, `password`, `credential`, `auth`, `wallet`, `support`, `alert`.
- **Suspicious TLDs (15):** `.pro`, `.top`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.fit`, `.work`, `.click`, `.link`, `.info`, `.club`.
- **Target Brands (12):** `amazon`, `paypal`, `microsoft`, `apple`, `google`, `facebook`, `netflix`, `chase`, `wellsfargo`, `bankofamerica`, `dhl`, `fedex`.

---

## 4. URL Preprocessing & Feature Extraction Implementation

- **Location:** `services/ml-service/app/utils/url_preprocessor.py`
- **Primary Function:** `extract_url_features(url: Optional[str]) -> Dict[str, float]`
- **Batch Transformer:** `URLPreprocessor.transform(df: pd.DataFrame, url_column: str = "url") -> pd.DataFrame`
- **Normalization Rules:**
  - Empty, null, or whitespace-only inputs return all 0.0 values.
  - If schema (`http://` or `https://`) is omitted, `http://` is prepended for `urllib.parse.urlparse` parsing.
  - Hostname normalized to lowercase.
  - Trailing punctuation (`.,;:'")>]}`) stripped from raw email body URL extracts.
- **Protocol Balancing:**
  - Historical email datasets (2002–2008) were ~93% HTTP, whereas modern phishing is >82% HTTPS.
  - To prevent spurious shortcut learning ("HTTP = benign, HTTPS = phishing"), 80% of benign URLs were converted to `https://` during dataset curation, enforcing realistic protocol distributions.

---

## 5. Dataset Composition & Label Mapping

- **Binary Label Mapping:**
  - `0`: Benign URL
  - `1`: Malicious / Phishing URL

### Source Data Breakdown in Original v1.0.0 Training:
- **Malicious Source:** `datasets/Malicious url/verified_online.csv` (PhishTank verified online threats).
  - Raw records: 74,997
  - Deduplicated clean URLs: 74,994
  - Unique malicious domains: 40,497
- **Benign Source:** Legitimate URLs extracted from authenticated email bodies in `datasets/Phishing/` (`CEAS_08.csv`, `SpamAssasin.csv`, `TREC_07.csv`) where `label == 0`.
  - Extracted benign URLs: 50,845
  - Unique benign domains: 11,704
- **Total Combined Clean URLs:** 125,839 across 52,193 unique domains.

---

## 6. Train, Validation & Test Partitioning Strategy

### Domain-Aware Group Partitioning (Zero-Leakage Guarantee):
To prevent domain-memorization and optimistic performance estimates, partitioning was conducted via `sklearn.model_selection.GroupShuffleSplit`:
1. **Domain Overlap Isolation:** 8 shared/redirector domains appeared in both benign and malicious data (`www.surveymonkey.com`, `tinyurl.com`, `www.google.com`, `docs.google.com`, `www.linkedin.com`, `web.archive.org`, `google.com`, `ad.doubleclick.net`). These were placed **strictly into the Train partition**, preventing data contamination in Validation or Test.
2. **Disjoint Partitioning:** The remaining disjoint domains were split into 80% Train, 10% Validation, and 10% Test.
3. **Partition Sample Sizes in v1.0.0:**
   - **Train:** 100,627 samples (~80.0%)
   - **Validation:** 16,492 samples (~13.1%)
   - **Test:** 8,720 samples (~6.9% across 5,219 unseen domains)
4. **Domain Leakage Assertions:**
   - $\text{Train} \cap \text{Val} = \emptyset$
   - $\text{Train} \cap \text{Test} = \emptyset$
   - $\text{Val} \cap \text{Test} = \emptyset$

---

## 7. Threshold Selection & Risk-Score Mapping

### Threshold Selection Methodology:
- Calibration evaluated **strictly on the Validation partition** across 61 candidate thresholds: `np.linspace(0.20, 0.80, 61)`.
- **Constraint:** False Positive Rate (FPR) on unseen benign domains must satisfy $\text{FPR} \le 5.0\%$.
- **Optimization Objective:** Maximize composite score: $F_1 + 0.1 \times \text{Recall}$.
- **Selected Frozen Operating Threshold:** $\tau = 0.74$.

### Runtime Risk-Score Mapping (`app/services/url_engine.py`):
```python
# Critical Phishing Heuristic Overrides
if is_critical_phishing:
    risk_level = RiskLevel.CRITICAL
    risk_score = min(100, max(90, int(ml_prob * 100))) if is_threat else 95

# Supervised Threat Decision or Moderate Heuristic Flags
elif is_threat or target_brand or suspicious_flags:
    risk_level = RiskLevel.HIGH
    risk_score = min(89, max(70, int(70 + (ml_prob - threshold) / (1.0 - threshold) * 19))) if is_threat else 75

# Benign Decision
else:
    risk_level = RiskLevel.SAFE
    risk_score = max(5, min(20, int(ml_prob * 20)))
```

---

## 8. Verified v1.0.0 Benchmark Evaluation Metrics

From `services/ml-service/app/models/url/malicious_url_metadata_v1.0.0.json` and `services/ml-service/scripts/url_evaluation_report.json`:

### Candidate Validation Comparison (at $\tau = 0.50$):
| Model Candidate | Accuracy | Balanced Acc | Precision | Recall | F1 Score | ROC-AUC |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **HistGradientBoosting** (Selected) | **86.65%** | **87.25%** | **94.33%** | 85.63% | **89.77%** | **0.9421** |
| RandomForest | 84.25% | 83.21% | 90.46% | 86.04% | 88.20% | 0.9114 |
| LogisticRegression | 61.96% | 66.06% | 83.90% | 54.93% | 66.39% | 0.7378 |

### Untouched Held-Out Test Evaluation (8,720 samples, 5,219 unseen domains, $\tau = 0.74$):
- **Accuracy:** 85.99%
- **Balanced Accuracy:** 87.88%
- **Precision:** 97.19%
- **Recall (Sensitivity):** 79.35%
- **Specificity:** 96.41%
- **F1 Score:** 87.37%
- **ROC-AUC:** 0.9635
- **PR-AUC:** 0.9767
- **False Positive Rate (FPR):** 3.59%
- **Confusion Matrix:**
  - True Negatives (TN): 3,272
  - False Positives (FP): 122
  - False Negatives (FN): 1,100
  - True Positives (TP): 4,226

---

## 9. Discrepancy Analysis: Phase 1 Manifest vs. Original v1.0.0 Training Data

A key discrepancy has been discovered between the Phase 1 curated manifest and the original v1.0.0 training pipeline:

1. **Benign URL Extraction Scope:**
   - In `services/ml-service/scripts/curate_and_manifest_datasets.py` (line 299), benign emails were capped:
     `df_src = pd.read_csv(fpath, usecols=["subject", "body"], nrows=10000)`
     This yielded only **24,980 benign URLs** (Total dataset: 99,974 records in `url_curated_manifest.parquet`).
   - In `services/ml-service/scripts/train_url_classifier.py` (lines 105–115), all rows of `CEAS_08.csv`, `SpamAssasin.csv`, and `TREC_07.csv` were processed without `nrows` truncation, yielding **50,845 benign URLs** (Total dataset: 125,839 records).
2. **Partition Split Distribution:**
   - Phase 1 Manifest (`url_curated_manifest.parquet`):
     - Train: 71,808
     - Validation: 21,975
     - Test: 6,191
   - Original v1.0.0 Training Pipeline (`train_url_classifier.py`):
     - Train: 100,627
     - Validation: 16,492
     - Test: 8,720
3. **Handling of 8 Overlapping Domains:**
   - `train_url_classifier.py` explicitly identified 8 overlapping redirection domains (`google.com`, `tinyurl.com`, etc.) and forced them strictly into the Train partition.
   - `curate_and_manifest_datasets.py` did not explicitly isolate these 8 shared domains before splitting.
4. **Resolution Path for Step 1 / Step 2:**
   - Before executing baseline reproduction, the Phase 1 URL manifest (`datasets/cleaned_manifests/url_curated_manifest.parquet`) must be aligned to contain the complete 125,839 curated URLs with the exact deterministic domain-aware splits, ensuring reproducible baseline verification.

---

## 10. Audit Conclusion & Gating Status

- All 16 architectural and pipeline items have been comprehensively identified and verified against actual code and artifacts.
- Zero production code or artifacts were modified.
- Existing URL test suite passes cleanly.
- The pipeline discrepancy has been documented with an exact blueprint for Phase 3 Step 1 alignment.

**PHASE 3 STEP 0 STATUS: PASS**
