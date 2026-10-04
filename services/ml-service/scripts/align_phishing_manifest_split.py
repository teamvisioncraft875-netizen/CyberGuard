"""
CYBERGUARD — Phase 2 Step 2: Phishing Manifest Split Alignment Script
Aligns the Phase 1 phishing manifest split column to match the original v1.0.0
composite stratification key (dataset_source + "_" + label, seed 42) exactly.
Does NOT modify any text content, labels, sources, or production code.
"""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_DIR = REPO_ROOT / "datasets" / "cleaned_manifests"
BACKUP_DIR = MANIFEST_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

ORIGINAL_PARQUET = MANIFEST_DIR / "phishing_curated_manifest.parquet"
BACKUP_PARQUET = BACKUP_DIR / "phishing_curated_manifest_phase1_initial.parquet"

RANDOM_SEED = 42

print("=== [1] Backing up Current Manifest ===")
assert ORIGINAL_PARQUET.exists(), f"Original manifest not found at {ORIGINAL_PARQUET}"
shutil.copy2(ORIGINAL_PARQUET, BACKUP_PARQUET)
print(f"Backup created at: {BACKUP_PARQUET}")

with open(BACKUP_PARQUET, "rb") as f:
    backup_hash = hashlib.sha256(f.read()).hexdigest()
print(f"Backup SHA-256: {backup_hash}")

print("\n=== [2] Loading Manifest and Regenerating Split ===")
df = pd.read_parquet(ORIGINAL_PARQUET)
assert len(df) == 43680, f"Expected 43680 rows, got {len(df)}"

# Store old split for diffing
old_split_counts = df["split"].value_counts().to_dict()
old_test_cohorts = df[df["split"] == "test"]["dataset_source"].value_counts().to_dict()

# Use exact v1.0.0 composite strata key
df["strata_key"] = df["dataset_source"].str.lower() + "_" + df["label"].astype(str)

# Outer split: 80% train, 20% temp (val + test)
sss_outer = StratifiedShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_SEED)
train_idx, temp_idx = next(sss_outer.split(df, df["strata_key"]))

temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

# Inner split: 50% of temp -> 10% val, 50% of temp -> 10% test
sss_inner = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=RANDOM_SEED)
val_sub_idx, test_sub_idx = next(sss_inner.split(temp_df, temp_df["strata_key"]))

# Map back to original dataframe indices
val_idx = temp_idx[val_sub_idx]
test_idx = temp_idx[test_sub_idx]

# Assign splits
df["split"] = "unassigned"
df.iloc[train_idx, df.columns.get_loc("split")] = "train"
df.iloc[val_idx, df.columns.get_loc("split")] = "val"
df.iloc[test_idx, df.columns.get_loc("split")] = "test"

# Drop temporary strata key
df.drop(columns=["strata_key"], inplace=True)

print("\n=== [3] Validating Aligned Split ===")
assert (df["split"] == "unassigned").sum() == 0, "Found unassigned records!"
train_cnt = (df["split"] == "train").sum()
val_cnt = (df["split"] == "val").sum()
test_cnt = (df["split"] == "test").sum()

print(f"Train count: {train_cnt} (Expected: 34944)")
print(f"Val count:   {val_cnt} (Expected: 4368)")
print(f"Test count:  {test_cnt} (Expected: 4368)")
assert train_cnt == 34944 and val_cnt == 4368 and test_cnt == 4368

# Check for index overlap
train_set = set(train_idx)
val_set = set(val_idx)
test_set = set(test_idx)
assert len(train_set.intersection(val_set)) == 0, "Train and Val overlap!"
assert len(train_set.intersection(test_set)) == 0, "Train and Test overlap!"
assert len(val_set.intersection(test_set)) == 0, "Val and Test overlap!"
assert len(train_set) + len(val_set) + len(test_set) == 43680, "Count mismatch!"

# Test cohort counts validation
test_df = df[df["split"] == "test"]
new_test_cohorts = test_df["dataset_source"].value_counts().to_dict()
ceas_split = test_df[test_df["dataset_source"] == "CEAS_08"]["label"].value_counts().to_dict()

print("\nNew Test Cohort Counts:")
print(f"Nazario:        {new_test_cohorts.get('Nazario')} (Expected: 156)")
print(f"Nigerian Fraud: {new_test_cohorts.get('Nigerian_Fraud')} (Expected: 331)")
print(f"CEAS 2008:      {new_test_cohorts.get('CEAS_08')} (Expected: 1893 -> threat: 162, benign: 1731)")
print(f"  - Threat:     {ceas_split.get(1)} (Expected: 162)")
print(f"  - Benign:     {ceas_split.get(0)} (Expected: 1731)")
print(f"Enron:          {new_test_cohorts.get('Enron')} (Expected: 1579)")
print(f"SpamAssassin:   {new_test_cohorts.get('SpamAssassin')} (Expected: 409)")

assert new_test_cohorts.get("Nazario") == 156
assert new_test_cohorts.get("Nigerian_Fraud") == 331
assert new_test_cohorts.get("CEAS_08") == 1893
assert ceas_split.get(1) == 162
assert ceas_split.get(0) == 1731
assert new_test_cohorts.get("Enron") == 1579
assert new_test_cohorts.get("SpamAssassin") == 409

print("\n=== [4] Determinism Verification ===")
# Run identical split routine a second time on fresh copy to verify exact determinism
df2 = pd.read_parquet(BACKUP_PARQUET)
df2["strata_key"] = df2["dataset_source"].str.lower() + "_" + df2["label"].astype(str)
train_idx2, temp_idx2 = next(sss_outer.split(df2, df2["strata_key"]))
temp_df2 = df2.iloc[temp_idx2].copy().reset_index(drop=True)
val_sub_idx2, test_sub_idx2 = next(sss_inner.split(temp_df2, temp_df2["strata_key"]))

assert list(train_idx) == list(train_idx2), "Train indices not deterministic!"
assert list(val_idx) == list(temp_idx2[val_sub_idx2]), "Val indices not deterministic!"
assert list(test_idx) == list(temp_idx2[test_sub_idx2]), "Test indices not deterministic!"
print("Determinism Verified: Two independent split executions produced 100% identical row index assignments.")

print("\n=== [5] Saving Aligned Manifest ===")
df.to_parquet(ORIGINAL_PARQUET, index=False)
df.to_csv(MANIFEST_DIR / "phishing_curated_manifest.csv.gz", index=False, compression="gzip")

with open(ORIGINAL_PARQUET, "rb") as f:
    aligned_hash = hashlib.sha256(f.read()).hexdigest()
print(f"Aligned Parquet SHA-256: {aligned_hash}")

# Compute split assignment signature
split_signature = hashlib.sha256("".join(df["split"].tolist()).encode("utf-8")).hexdigest()
print(f"Split Assignment Signature (SHA-256): {split_signature}")

# Update summary JSON
summary_file = MANIFEST_DIR / "phishing_curated_summary.json"
if summary_file.exists():
    with open(summary_file, "r", encoding="utf-8") as f:
        summary_data = json.load(f)
    summary_data["split_distribution"] = df["split"].value_counts().to_dict()
    summary_data["split_alignment"] = {
        "status": "ALIGNED_WITH_V1.0.0_COMPOSITE_STRATIFICATION",
        "composite_strata_key": "dataset_source.str.lower() + '_' + label.astype(str)",
        "random_seed": 42,
        "backup_path": str(BACKUP_PARQUET.relative_to(REPO_ROOT)),
        "aligned_parquet_hash": aligned_hash,
        "split_signature_hash": split_signature,
        "test_cohorts": {
            "Nazario": int(new_test_cohorts["Nazario"]),
            "Nigerian_Fraud": int(new_test_cohorts["Nigerian_Fraud"]),
            "CEAS_08_total": int(new_test_cohorts["CEAS_08"]),
            "CEAS_08_threat": int(ceas_split[1]),
            "CEAS_08_benign": int(ceas_split[0]),
            "Enron": int(new_test_cohorts["Enron"]),
            "SpamAssassin": int(new_test_cohorts["SpamAssassin"])
        }
    }
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)
    print("Updated phishing_curated_summary.json with split alignment metadata.")

print("\nSplit alignment completed successfully.")
