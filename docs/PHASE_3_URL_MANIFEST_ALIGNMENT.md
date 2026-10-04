# PHASE 3 — MALICIOUS URL MANIFEST ALIGNMENT REPORT
**CYBERGUARD Machine Learning Workstream**  
**Document Version:** 1.0.0  
**Status:** COMPLETE (STEP 1 ALIGNMENT)  
**Date:** 2026-10-04  

---

## 1. Executive Summary & Objective

In accordance with the gated workflow established for the CYBERGUARD ML workstream, **Phase 3 — Step 1** resolves the dataset and split discrepancy between the initial Phase 1 URL curated manifest and the production Malicious URL Classifier v1.0.0 training corpus.

The alignment rebuilds the curated URL manifest deterministically from raw source repositories, enforcing the complete benign email corpus extraction, 80% HTTPS protocol balancing, 8-domain shared platform quarantine, and domain-aware group partitioning.

No production model artifacts or runtime services were modified.

---

## 2. Original v1.0.0 Corpus Definition vs. Phase 1 Discrepancy

| Metric / Dimension | Phase 1 Initial Manifest | Production v1.0.0 Pipeline | Aligned Manifest (Step 1) | Alignment Status |
|:---|:---:|:---:|:---:|:---:|
| **Malicious URLs** | 74,994 | 74,994 | 74,994 | Exact Match |
| **Benign URLs** | 24,980 | 50,845 | 50,845 | Exact Match |
| **Total Clean URLs** | 99,974 | 125,839 | 125,839 | Exact Match |
| **Unique Domains** | 49,270 | 52,193 | 52,193 | Exact Match |
| **Train Samples** | 71,808 | 100,627 | 100,627 | Exact Match |
| **Validation Samples** | 21,975 | 16,492 | 16,492 | Exact Match |
| **Test Samples** | 6,191 | 8,720 | 8,720 | Exact Match |
| **Unseen Test Domains** | 3,449 | 5,219 | 5,219 | Exact Match |
| **Shared Platforms Quarantined** | Unspecified | 8 in Train | 8 in Train | Exact Match |

### Root Cause of Discrepancy:
During Phase 1 dataset curation, `services/ml-service/scripts/curate_and_manifest_datasets.py` (line 299) applied `nrows=10000` when reading the email corpora (`CEAS_08.csv`, `SpamAssasin.csv`, `TREC_07.csv`) for benign URL extraction:
```python
df_src = pd.read_csv(fpath, usecols=["subject", "body"], nrows=10000)
```
This artificial truncation caused 25,865 authentic benign URLs to be omitted from the Phase 1 manifest. The original production training script (`services/ml-service/scripts/train_url_classifier.py`) read the full email corpora without `nrows` truncation.

---

## 3. Full Corpus Reconstruction & Deduplication

The corpus reconstruction was executed via [`services/ml-service/scripts/align_url_manifest_v1.py`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/scripts/align_url_manifest_v1.py):

1. **Malicious URLs (PhishTank):**
   - Source: `datasets/Malicious url/verified_online.csv`
   - Raw records read: 74,997
   - URLs filtered (< 10 chars): 0
   - Exact duplicates removed: 3
   - Final unique malicious URLs: **74,994**
   - Unique malicious domains: **40,497**
   - Protocol distribution: 46,316 HTTPS (61.76%), 28,678 HTTP (38.24%)

2. **Benign URLs (Authentic Enterprise & Ham Emails):**
   - Sources: `datasets/Phishing/CEAS_08.csv`, `datasets/Phishing/SpamAssasin.csv`, `datasets/Phishing/TREC_07.csv` (where `label == 0`)
   - Raw URL extractions: 127,497
   - Raw unique URLs: 50,861
   - URLs existing as both HTTP and HTTPS: 18 pairs
   - Protocol balancing (80% HTTPS conversion): 16 pairs collapsed into HTTPS
   - Deduplicated clean benign URLs: **50,845**
   - Unique benign domains: **11,704**
   - Protocol distribution: 40,683 HTTPS (80.01%), 10,162 HTTP (19.99%)

3. **Combined Clean Corpus:**
   - Total clean deduplicated URLs: **125,839**
   - Total unique domains: **52,193**

---

## 4. Shared-Domain Isolation & Quarantine

Eight large shared/redirection platforms appeared in both malicious phishing reports and authentic benign correspondence:
- `ad.doubleclick.net`
- `docs.google.com`
- `google.com`
- `tinyurl.com`
- `web.archive.org`
- `www.google.com`
- `www.linkedin.com`
- `www.surveymonkey.com`

**Quarantine Guarantee:** All 8 overlapping domains are assigned **strictly and exclusively to the Train partition**. Zero instances of these domains appear in Validation or Test, preventing optimistic leakage on shared infrastructure.

---

## 5. Domain-Aware Group Partitioning (Zero-Leakage)

Partitioning was executed using `sklearn.model_selection.GroupShuffleSplit` on domain groups (`extract_domain_key`):
1. **Outer Split:** Disjoint domains partitioned 80% Train, 20% Temp (`random_state=42`).
2. **Inner Split:** Temp partitioned 50% Validation, 50% Test (`random_state=42`).
3. **Shared Domains:** Appended strictly to Train partition.

### Partition Sizes & Class Balance:
| Split Partition | Total Samples | Malicious (1) | Benign (0) | Unique Domains | Domain Leakage |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Train** | **100,627** (79.96%) | 58,389 (58.0%) | 42,238 (42.0%) | **41,756** | 0 overlap with Val/Test |
| **Validation** | **16,492** (13.11%) | 11,279 (68.4%) | 5,213 (31.6%) | **5,218** | 0 overlap with Train/Test |
| **Test** | **8,720** (6.93%) | 5,326 (61.1%) | 3,394 (38.9%) | **5,219** | 0 overlap with Train/Val |
| **Total** | **125,839** | **74,994** | **50,845** | **52,193** | Strict Disjointness |

### Zero-Leakage Mathematical Proof:
$$\text{Train Domains} \cap \text{Val Domains} = \emptyset \quad (\text{Overlap} = 0)$$
$$\text{Train Domains} \cap \text{Test Domains} = \emptyset \quad (\text{Overlap} = 0)$$
$$\text{Val Domains} \cap \text{Test Domains} = \emptyset \quad (\text{Overlap} = 0)$$

---

## 6. Determinism & Cryptographic Signatures

The alignment process was executed across two independent Python process runs with fresh interpreters. Both runs produced identical record counts, partition assignments, and cryptographic signatures.

- **Split Deterministic SHA-256:**
  `ffb085da3ea88fe6bbf1ea7c1061bff23775e6fb7e7f02288f61e22ba30ea5e1`
- **Output Manifest Artifacts:**
  - `datasets/cleaned_manifests/url_curated_manifest.parquet` (4.93 MB)
  - `datasets/cleaned_manifests/url_curated_manifest.csv.gz` (2.85 MB)
  - `datasets/cleaned_manifests/url_curated_summary.json` (1.45 KB)

---

## 7. Backup Information

Prior to modifying the Phase 1 manifest, an exact immutable backup of the original Phase 1 artifact was created:
- **Backup Path:** [`datasets/cleaned_manifests/backups/url_curated_manifest_phase1_initial.parquet`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/datasets/cleaned_manifests/backups/url_curated_manifest_phase1_initial.parquet)
- **File Size:** 4,154,576 bytes (99,974 records)
- **SHA-256 Checksum:** `898f08468f5e3c6865e4770430c3245dffc18ea2beeebd5e3d37f5a623bd1791`

---

## 8. Files Created / Modified

- **Created:**
  - [`services/ml-service/scripts/align_url_manifest_v1.py`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/services/ml-service/scripts/align_url_manifest_v1.py) (Reproducible corpus builder and partitioner)
  - [`datasets/cleaned_manifests/backups/url_curated_manifest_phase1_initial.parquet`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/datasets/cleaned_manifests/backups/url_curated_manifest_phase1_initial.parquet) (Immutable backup)
  - [`docs/PHASE_3_URL_MANIFEST_ALIGNMENT.md`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/docs/PHASE_3_URL_MANIFEST_ALIGNMENT.md) (This deliverable)
- **Updated Manifests:**
  - [`datasets/cleaned_manifests/url_curated_manifest.parquet`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/datasets/cleaned_manifests/url_curated_manifest.parquet)
  - [`datasets/cleaned_manifests/url_curated_manifest.csv.gz`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/datasets/cleaned_manifests/url_curated_manifest.csv.gz)
  - [`datasets/cleaned_manifests/url_curated_summary.json`](file:///d:/cyberguard%20project%20%20work%20su/CyberGuard/datasets/cleaned_manifests/url_curated_summary.json)
- **Production Code Untouched:**
  - `services/ml-service/app/services/url_engine.py` (Unchanged)
  - `services/ml-service/app/models/url/*` (Unchanged)
  - `apps/web/` (Unchanged)

---

## 9. Test Safety & Suite Status

1. **Focused URL Test Suite:**
   - Command: `pytest services/ml-service/tests/ -k url -q`
   - Result: **56 passed, 174 deselected in 15.35s (100% PASS)**
2. **Full ML Service Regression Suite:**
   - Command: `pytest services/ml-service/tests/ -q`
   - Result: **230 passed in 40.51s (100% PASS)**

---

## 10. Conclusion & Step 1 Gating Status

Phase 3 — Step 1 has completed successfully. The cleaned URL manifest now exactly represents the full 125,839 clean URLs, 52,193 unique domains, 8 quarantined shared platforms, and deterministic domain-aware splits corresponding to the conditions under which v1.0.0 was trained.

**PHASE 3 STEP 1 STATUS: PASS**
