"""
CYBERGUARD — Supervised Phishing & Social Engineering Classifier Training Pipeline
Phase 1: Enforces semantic positive-class filtering, source-aware partitioning,
sub-cohort evaluation, and strict test-set protection.
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.svm import LinearSVC

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.phishing_trainer")

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

PHISHING_KEYWORDS_PATTERN = re.compile(
    r"\b(password|credential|verify|account|security|update|suspend|locked|unauthorized|"
    r"banking|login|signin|confirm|auth|wallet|irs|tax|wire|transfer|urgent|immediate|"
    r"action required|claim|beneficiary|funds|confidential|helpdesk|mailbox)\b",
    re.IGNORECASE,
)


def clean_email_text(subject: Any, body: Any) -> str:
    """Combines and normalizes subject and body into clean tokenizable text."""
    s = str(subject) if pd.notna(subject) else ""
    b = str(body) if pd.notna(body) else ""
    
    # Strip mbox internal folder artifacts if present
    if "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA" in s:
        s = ""
    if "This text is part of the internal format of your mail folder" in b[:120]:
        b = b[120:]
        
    combined = f"{s}\n\n{b}".strip()
    # Normalize multiple whitespaces
    combined = re.sub(r"[ \t]+", " ", combined)
    combined = re.sub(r"\n{3,}", "\n\n", combined)
    return combined


def load_curated_phishing_dataset(dataset_dir: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Loads and curates datasets according to strict semantic cyber-threat definitions.
    Generic commercial spam (Enron spam, SpamAssassin spam, Ling spam) is excluded from
    the positive phishing class per architectural decision.
    """
    logger.info("Loading and curating phishing datasets from %s ...", dataset_dir)
    records: List[Dict[str, Any]] = []
    audit_stats: Dict[str, Any] = {
        "raw_counts": {},
        "excluded_generic_spam": {},
        "included_samples": {},
    }

    # 1. Nazario (Pure Credential Phishing)
    nazario_path = dataset_dir / "Nazario.csv"
    if nazario_path.exists():
        df_naz = pd.read_csv(nazario_path, low_memory=False)
        audit_stats["raw_counts"]["Nazario"] = len(df_naz)
        for _, r in df_naz.iterrows():
            text = clean_email_text(r.get("subject"), r.get("body"))
            if len(text) > 15:
                records.append({
                    "text": text,
                    "target": 1,
                    "dataset_source": "nazario",
                    "threat_subclass": "credential_phishing",
                })
        audit_stats["included_samples"]["Nazario"] = sum(1 for r in records if r["dataset_source"] == "nazario")

    # 2. Nigerian Fraud (Pure Social Engineering / 419 Advance-Fee Pretexting)
    nig_path = dataset_dir / "Nigerian_Fraud.csv"
    if nig_path.exists():
        df_nig = pd.read_csv(nig_path, low_memory=False)
        audit_stats["raw_counts"]["Nigerian_Fraud"] = len(df_nig)
        for _, r in df_nig.iterrows():
            text = clean_email_text(r.get("subject"), r.get("body"))
            if len(text) > 15:
                records.append({
                    "text": text,
                    "target": 1,
                    "dataset_source": "nigerian_fraud",
                    "threat_subclass": "social_engineering_fraud",
                })
        audit_stats["included_samples"]["Nigerian_Fraud"] = sum(1 for r in records if r["dataset_source"] == "nigerian_fraud")

    # 3. CEAS 2008 (Collaborative Phishing / Spam Benchmark)
    ceas_path = dataset_dir / "CEAS_08.csv"
    if ceas_path.exists():
        df_ceas = pd.read_csv(ceas_path, low_memory=False)
        audit_stats["raw_counts"]["CEAS_08"] = len(df_ceas)
        ceas_threat_count = 0
        ceas_excluded_spam = 0
        ceas_benign_count = 0

        for _, r in df_ceas.iterrows():
            text = clean_email_text(r.get("subject"), r.get("body"))
            if len(text) <= 15:
                continue
            orig_label = int(r.get("label", 0))
            if orig_label == 0:
                # Verified legitimate corporate / academic correspondence
                records.append({
                    "text": text,
                    "target": 0,
                    "dataset_source": "ceas_08",
                    "threat_subclass": "benign_corporate",
                })
                ceas_benign_count += 1
            else:
                # Semantic check: only retain if genuine phishing/credential/urgency threat
                if PHISHING_KEYWORDS_PATTERN.search(text):
                    records.append({
                        "text": text,
                        "target": 1,
                        "dataset_source": "ceas_08",
                        "threat_subclass": "credential_phishing_lure",
                    })
                    ceas_threat_count += 1
                else:
                    ceas_excluded_spam += 1

        audit_stats["included_samples"]["CEAS_08_threat"] = ceas_threat_count
        audit_stats["included_samples"]["CEAS_08_benign"] = ceas_benign_count
        audit_stats["excluded_generic_spam"]["CEAS_08_generic_spam"] = ceas_excluded_spam

    # 4. Enron (Legitimate Corporate Baseline; generic spam excluded from threat class)
    enron_path = dataset_dir / "Enron.csv"
    if enron_path.exists():
        df_enron = pd.read_csv(enron_path, low_memory=False)
        audit_stats["raw_counts"]["Enron"] = len(df_enron)
        enron_benign = 0
        enron_spam_excluded = 0
        for _, r in df_enron.iterrows():
            text = clean_email_text(r.get("subject"), r.get("body"))
            if len(text) <= 15:
                continue
            orig_label = int(r.get("label", 0))
            if orig_label == 0:
                records.append({
                    "text": text,
                    "target": 0,
                    "dataset_source": "enron",
                    "threat_subclass": "benign_corporate",
                })
                enron_benign += 1
            else:
                enron_spam_excluded += 1
        audit_stats["included_samples"]["Enron_benign"] = enron_benign
        audit_stats["excluded_generic_spam"]["Enron_marketing_spam"] = enron_spam_excluded

    # 5. SpamAssassin (Technical / Mailing List Benign Baseline; bulk spam excluded)
    sa_path = dataset_dir / "SpamAssasin.csv"
    if sa_path.exists():
        df_sa = pd.read_csv(sa_path, low_memory=False)
        audit_stats["raw_counts"]["SpamAssassin"] = len(df_sa)
        sa_benign = 0
        sa_spam_excluded = 0
        for _, r in df_sa.iterrows():
            text = clean_email_text(r.get("subject"), r.get("body"))
            if len(text) <= 15:
                continue
            orig_label = int(r.get("label", 0))
            if orig_label == 0:
                records.append({
                    "text": text,
                    "target": 0,
                    "dataset_source": "spamassassin",
                    "threat_subclass": "benign_technical",
                })
                sa_benign += 1
            else:
                sa_spam_excluded += 1
        audit_stats["included_samples"]["SpamAssassin_benign"] = sa_benign
        audit_stats["excluded_generic_spam"]["SpamAssassin_bulk_spam"] = sa_spam_excluded

    df = pd.DataFrame(records)
    logger.info("Total raw extracted records: %d", len(df))

    # Deduplication
    initial_len = len(df)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    audit_stats["deduplicated_count"] = initial_len - len(df)
    logger.info("Dropped %d exact duplicate texts. Remaining clean samples: %d", audit_stats["deduplicated_count"], len(df))
    logger.info("Class distribution:\n%s", df["target"].value_counts().to_dict())
    logger.info("Source breakdown:\n%s", df.groupby(["dataset_source", "target"]).size().to_dict())

    return df, audit_stats


def create_source_stratified_splits(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Creates 80% Train, 10% Validation, 10% Test partitions stratified by (dataset_source, target).
    Guarantees no data leakage across partitions.
    """
    # Create composite stratification key
    df["strata_key"] = df["dataset_source"] + "_" + df["target"].astype(str)

    # First split: 80% train, 20% temp (val + test)
    sss_outer = StratifiedShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_SEED)
    train_idx, temp_idx = next(sss_outer.split(df, df["strata_key"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

    # Second split: 50% of temp -> 10% val, 50% of temp -> 10% test
    sss_inner = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=RANDOM_SEED)
    val_idx, test_idx = next(sss_inner.split(temp_df, temp_df["strata_key"]))

    val_df = temp_df.iloc[val_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_idx].copy().reset_index(drop=True)

    # Clean up strata key
    train_df.drop(columns=["strata_key"], inplace=True)
    val_df.drop(columns=["strata_key"], inplace=True)
    test_df.drop(columns=["strata_key"], inplace=True)

    logger.info("Split created: Train=%d, Val=%d, Test=%d", len(train_df), len(val_df), len(test_df))
    return train_df, val_df, test_df


def train_and_evaluate_phishing():
    repo_root = Path(__file__).resolve().parents[3]
    dataset_dir = repo_root / "datasets" / "Phishing"

    start_time = time.time()
    df, audit_stats = load_curated_phishing_dataset(dataset_dir)

    train_df, val_df, test_df = create_source_stratified_splits(df)

    # 1. Feature Extraction (Fitted strictly on Train only)
    logger.info("Fitting TF-IDF Vectorizer on Train partition...")
    vectorizer = TfidfVectorizer(
        max_features=25000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=3,
        max_df=0.90,
        strip_accents="unicode",
        token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.]{2,}\b",
    )

    X_train = vectorizer.fit_transform(train_df["text"])
    y_train = train_df["target"].values

    X_val = vectorizer.transform(val_df["text"])
    y_val = val_df["target"].values

    X_test = vectorizer.transform(test_df["text"])
    y_test = test_df["target"].values

    logger.info("TF-IDF Matrix shape: Train=%s, Val=%s, Test=%s", X_train.shape, X_val.shape, X_test.shape)

    # 2. Candidate Model Evaluation on Validation Set
    logger.info("Evaluating candidate models on Validation split...")
    candidates = {
        "Calibrated_LinearSVC": CalibratedClassifierCV(
            LinearSVC(C=1.0, random_state=RANDOM_SEED, dual="auto", max_iter=2000),
            cv=3,
        ),
        "Balanced_LogisticRegression": LogisticRegression(
            C=3.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=RANDOM_SEED,
            solver="saga",
        ),
    }

    val_comparisons: Dict[str, Any] = {}
    best_candidate_name = None
    best_candidate_model = None
    best_candidate_f1 = -1.0

    for name, model in candidates.items():
        logger.info("Fitting candidate: %s ...", name)
        model.fit(X_train, y_train)
        val_probs = model.predict_proba(X_val)[:, 1]
        val_preds = (val_probs >= 0.50).astype(int)

        val_acc = float(accuracy_score(y_val, val_preds))
        val_bal_acc = float(balanced_accuracy_score(y_val, val_preds))
        val_f1 = float(f1_score(y_val, val_preds, zero_division=0))
        val_prec = float(precision_score(y_val, val_preds, zero_division=0))
        val_rec = float(recall_score(y_val, val_preds, zero_division=0))
        val_roc = float(roc_auc_score(y_val, val_probs))

        val_comparisons[name] = {
            "accuracy": round(val_acc, 4),
            "balanced_accuracy": round(val_bal_acc, 4),
            "precision": round(val_prec, 4),
            "recall": round(val_rec, 4),
            "f1": round(val_f1, 4),
            "roc_auc": round(val_roc, 4),
        }
        logger.info("Candidate %s -> Val Acc: %.4f, Bal Acc: %.4f, F1: %.4f, ROC-AUC: %.4f",
                    name, val_acc, val_bal_acc, val_f1, val_roc)

        if val_f1 > best_candidate_f1:
            best_candidate_f1 = val_f1
            best_candidate_name = name
            best_candidate_model = model

    logger.info("Selected best candidate: %s with Val F1: %.4f", best_candidate_name, best_candidate_f1)

    # 3. Threshold Selection on Validation Set ONLY
    logger.info("Searching optimal threshold on Validation data only...")
    val_probs = best_candidate_model.predict_proba(X_val)[:, 1]
    threshold_candidates = np.linspace(0.20, 0.80, 61)

    best_threshold = 0.50
    best_thresh_score = -1.0
    val_threshold_records: List[Dict[str, Any]] = []

    for t in threshold_candidates:
        preds = (val_probs >= t).astype(int)
        f1 = f1_score(y_val, preds, zero_division=0)
        rec = recall_score(y_val, preds, zero_division=0)
        prec = precision_score(y_val, preds, zero_division=0)

        # Check FPR on corporate Enron within validation set
        enron_val_mask = (val_df["dataset_source"] == "enron") & (val_df["target"] == 0)
        enron_val_fps = int(np.sum(preds[enron_val_mask] == 1))
        enron_val_total = int(np.sum(enron_val_mask))
        enron_fpr = enron_val_fps / enron_val_total if enron_val_total > 0 else 0.0

        val_threshold_records.append({
            "threshold": round(float(t), 2),
            "f1": round(float(f1), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "enron_corporate_fpr": round(float(enron_fpr), 4),
        })

        # Selection criteria: maximize F1 while strictly enforcing enron_fpr <= 0.03
        if enron_fpr <= 0.03:
            composite = f1 + (rec * 0.2)
            if composite > best_thresh_score:
                best_thresh_score = composite
                best_threshold = float(t)

    logger.info("Frozen Operating Threshold selected from Validation: %.2f", best_threshold)

    # 4. Final Evaluation on Untouched TEST Partition
    logger.info("Evaluating selected model and frozen threshold on untouched TEST partition...")
    test_probs = best_candidate_model.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= best_threshold).astype(int)

    cm = confusion_matrix(y_test, test_preds)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    test_acc = float(accuracy_score(y_test, test_preds))
    test_bal_acc = float(balanced_accuracy_score(y_test, test_preds))
    test_prec = float(precision_score(y_test, test_preds, zero_division=0))
    test_rec = float(recall_score(y_test, test_preds, zero_division=0))
    test_spec = float(tn / (tn + fp) if (tn + fp) > 0 else 0.0)
    test_f1 = float(f1_score(y_test, test_preds, zero_division=0))
    test_roc_auc = float(roc_auc_score(y_test, test_probs))

    precision_curve, recall_curve, _ = precision_recall_curve(y_test, test_probs)
    test_pr_auc = float(auc(recall_curve, precision_curve))

    logger.info("-" * 60)
    logger.info("FINAL UNTOUCHED TEST SET METRICS (Threshold: %.2f):", best_threshold)
    logger.info("Accuracy:            %.4f", test_acc)
    logger.info("Balanced Accuracy:   %.4f", test_bal_acc)
    logger.info("Precision:           %.4f", test_prec)
    logger.info("Recall (Sensitivity):%.4f", test_rec)
    logger.info("Specificity:         %.4f", test_spec)
    logger.info("F1 Score:            %.4f", test_f1)
    logger.info("ROC-AUC:             %.4f", test_roc_auc)
    logger.info("PR-AUC:              %.4f", test_pr_auc)
    logger.info("Confusion Matrix:    TN=%d, FP=%d, FN=%d, TP=%d", tn, fp, fn, tp)
    logger.info("-" * 60)

    # 5. Sub-Cohort Test Set Evaluation
    logger.info("Evaluating sub-cohort slices on TEST partition...")
    sub_cohort_results: Dict[str, Any] = {}

    for source in ["nazario", "nigerian_fraud", "ceas_08", "enron", "spamassassin"]:
        source_mask = test_df["dataset_source"] == source
        if not np.any(source_mask):
            continue

        s_y_true = y_test[source_mask]
        s_y_pred = test_preds[source_mask]
        s_probs = test_probs[source_mask]
        total_s = int(len(s_y_true))

        pos_count = int(np.sum(s_y_true == 1))
        neg_count = int(np.sum(s_y_true == 0))

        sub_stats = {
            "total_test_samples": total_s,
            "positive_samples": pos_count,
            "negative_samples": neg_count,
        }

        if pos_count > 0:
            rec = float(recall_score(s_y_true, s_y_pred, zero_division=0))
            sub_stats["recall"] = round(rec, 4)
            logger.info("Sub-cohort [%s] Positive Recall: %.4f (%d samples)", source, rec, pos_count)

        if neg_count > 0:
            fp_cnt = int(np.sum((s_y_true == 0) & (s_y_pred == 1)))
            fpr = float(fp_cnt / neg_count)
            sub_stats["false_positive_count"] = fp_cnt
            sub_stats["false_positive_rate"] = round(fpr, 4)
            logger.info("Sub-cohort [%s] Negative False-Positive Rate: %.4f (%d/%d)", source, fpr, fp_cnt, neg_count)

        sub_cohort_results[source] = sub_stats

    # 6. Save Artifacts
    models_dir = repo_root / "services" / "ml-service" / "app" / "models" / "phishing"
    models_dir.mkdir(parents=True, exist_ok=True)

    classifier_path = models_dir / "phishing_classifier_v1.0.0.joblib"
    vectorizer_path = models_dir / "phishing_vectorizer_v1.0.0.joblib"
    schema_path = models_dir / "phishing_schema_v1.0.0.json"
    metadata_path = models_dir / "phishing_metadata_v1.0.0.json"
    report_path = repo_root / "services" / "ml-service" / "scripts" / "phishing_evaluation_report.json"

    logger.info("Saving model checkpoint to %s ...", classifier_path)
    joblib.dump(best_candidate_model, classifier_path, compress=3)

    logger.info("Saving vectorizer to %s ...", vectorizer_path)
    joblib.dump(vectorizer, vectorizer_path, compress=3)

    schema_data = {
        "model_name": "CYBERGUARD Supervised Phishing & Social Engineering Classifier",
        "version": "1.0.0",
        "input_type": "raw_text_string",
        "vectorizer": "TfidfVectorizer",
        "max_features": 25000,
        "ngram_range": [1, 2],
        "output_format": {
            "prediction": "binary_integer (0: benign, 1: threat)",
            "threat_probability": "float (0.0 to 1.0)",
            "calibrated_threshold": best_threshold,
        },
    }
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema_data, f, indent=2)

    metadata_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_name": "CYBERGUARD Phishing & Social Engineering Classifier",
        "model_version": "v1.0.0",
        "algorithm": best_candidate_name,
        "random_seed": RANDOM_SEED,
        "operating_threshold": round(best_threshold, 2),
        "training_duration_seconds": round(time.time() - start_time, 2),
        "dataset_composition": {
            "total_clean_samples": len(df),
            "train_samples": len(train_df),
            "validation_samples": len(val_df),
            "test_samples": len(test_df),
            "source_audit": audit_stats,
        },
        "candidate_comparison": val_comparisons,
        "test_benchmark_metrics": {
            "accuracy": round(test_acc, 4),
            "balanced_accuracy": round(test_bal_acc, 4),
            "precision": round(test_prec, 4),
            "recall": round(test_rec, 4),
            "specificity": round(test_spec, 4),
            "f1_score": round(test_f1, 4),
            "roc_auc": round(test_roc_auc, 4),
            "pr_auc": round(test_pr_auc, 4),
            "confusion_matrix": {
                "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            },
        },
        "sub_cohort_test_performance": sub_cohort_results,
        "design_decisions_and_limitations": (
            "1. Generic commercial spam (Enron/SpamAssassin/Ling marketing) was explicitly excluded from the "
            "positive cyber-threat class to prevent penalizing standard business terminology. "
            "2. Positive class strictly represents targeted Credential Phishing, Social Engineering Fraud, and "
            "weaponized credential lures. 3. Threshold tuned on Validation partition only with Enron corporate "
            "FPR constrained to <= 3%."
        ),
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata_data, f, indent=2)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metadata_data, f, indent=2)

    logger.info("Phase 1 artifacts successfully saved to %s", models_dir)
    return metadata_data


if __name__ == "__main__":
    train_and_evaluate_phishing()
