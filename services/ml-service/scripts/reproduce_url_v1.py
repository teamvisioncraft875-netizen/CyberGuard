"""
CYBERGUARD — Malicious URL v1.0.0 Baseline Reproduction & Verification Script
Phase 3 Step 2: Gated baseline reproduction from the aligned Phase 1 URL manifest.

- Evaluates strictly on Train partition (100,627 samples)
- Verifies threshold selection on Validation partition (16,492 samples) at tau = 0.74
- Single-pass evaluation on untouched Test partition (8,720 samples across 5,219 unseen domains)
- Direct comparison with existing production v1.0.0 artifact
- Zero domain leakage assertion and shared domain quarantine verification
- Determinism pass asserting identical parameters and predictions
- Saves experiment artifacts strictly under services/ml-service/experiments/url_exp_<timestamp>/
"""

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
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

# Ensure app is importable
repo_root = Path(__file__).resolve().parents[3]
ml_service_path = repo_root / "services" / "ml-service"
if str(ml_service_path) not in sys.path:
    sys.path.insert(0, str(ml_service_path))

from app.utils.url_preprocessor import URLPreprocessor, URL_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.url_baseline_reproduction")

RANDOM_SEED = 42
OPERATING_THRESHOLD = 0.74

MANIFEST_PATH = repo_root / "datasets" / "cleaned_manifests" / "url_curated_manifest.parquet"
PROD_MODELS_DIR = ml_service_path / "app" / "models" / "url"
PROD_CLASSIFIER_PATH = PROD_MODELS_DIR / "malicious_url_classifier_v1.0.0.joblib"
PROD_METADATA_PATH = PROD_MODELS_DIR / "malicious_url_metadata_v1.0.0.json"
PROD_SCHEMA_PATH = PROD_MODELS_DIR / "malicious_url_schema_v1.0.0.json"

RUN_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
EXP_DIR = ml_service_path / "experiments" / f"url_exp_{RUN_TIMESTAMP}"
EXP_DIR.mkdir(parents=True, exist_ok=True)


def load_and_verify_manifest() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Loads aligned manifest and strictly validates domain-aware partitioning."""
    logger.info("Loading aligned URL manifest from %s ...", MANIFEST_PATH)
    df = pd.read_parquet(MANIFEST_PATH)

    train_df = df[df["split"] == "train"].copy().reset_index(drop=True)
    val_df = df[df["split"] == "val"].copy().reset_index(drop=True)
    test_df = df[df["split"] == "test"].copy().reset_index(drop=True)

    logger.info("Split sizes: Train=%d, Val=%d, Test=%d (Total=%d)", len(train_df), len(val_df), len(test_df), len(df))
    assert len(train_df) == 100627, f"Expected 100,627 train samples, got {len(train_df)}"
    assert len(val_df) == 16492, f"Expected 16,492 val samples, got {len(val_df)}"
    assert len(test_df) == 8720, f"Expected 8,720 test samples, got {len(test_df)}"
    assert len(df) == 125839, f"Expected 125,839 total samples, got {len(df)}"

    train_doms = set(train_df["domain"])
    val_doms = set(val_df["domain"])
    test_doms = set(test_df["domain"])

    assert len(train_doms.intersection(val_doms)) == 0, "Train-Val domain leakage detected!"
    assert len(train_doms.intersection(test_doms)) == 0, "Train-Test domain leakage detected!"
    assert len(val_doms.intersection(test_doms)) == 0, "Val-Test domain leakage detected!"

    # Verify 8 shared platforms are strictly in Train
    expected_overlap = {
        "ad.doubleclick.net", "docs.google.com", "google.com", "tinyurl.com",
        "web.archive.org", "www.google.com", "www.linkedin.com", "www.surveymonkey.com"
    }
    assert expected_overlap.issubset(train_doms), "Shared platforms missing from Train!"
    assert len(expected_overlap.intersection(val_doms)) == 0, "Shared platforms leaked into Val!"
    assert len(expected_overlap.intersection(test_doms)) == 0, "Shared platforms leaked into Test!"

    domain_stats = {
        "train_domains": len(train_doms),
        "val_domains": len(val_doms),
        "test_domains": len(test_doms),
        "total_unique_domains": df["domain"].nunique(),
        "shared_platforms": sorted(list(expected_overlap)),
        "domain_leakage": "0 overlap verified",
    }
    logger.info("Domain statistics: %s", domain_stats)
    return train_df, val_df, test_df, domain_stats


def extract_features(
    train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame
) -> Tuple[pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray]:
    """Extracts 16 dense lexical/structural features via existing URLPreprocessor."""
    logger.info("Extracting features using production URLPreprocessor...")
    preprocessor = URLPreprocessor()

    t0 = time.time()
    X_train = preprocessor.transform(train_df, url_column="url")
    y_train = train_df["label"].values.astype(int)

    X_val = preprocessor.transform(val_df, url_column="url")
    y_val = val_df["label"].values.astype(int)

    X_test = preprocessor.transform(test_df, url_column="url")
    y_test = test_df["label"].values.astype(int)

    logger.info("Feature extraction completed in %.2f seconds.", time.time() - t0)
    assert list(X_train.columns) == URL_FEATURE_COLUMNS, "Feature columns mismatch!"
    return X_train, y_train, X_val, y_val, X_test, y_test


def train_model(X_train: pd.DataFrame, y_train: np.ndarray) -> Tuple[HistGradientBoostingClassifier, float]:
    """Trains HistGradientBoostingClassifier using exact production configuration."""
    logger.info("Training HistGradientBoostingClassifier (max_iter=150, lr=0.1, leaf_nodes=31, balanced)...")
    clf = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.1,
        max_leaf_nodes=31,
        min_samples_leaf=20,
        random_state=RANDOM_SEED,
        class_weight="balanced",
    )

    t0 = time.time()
    clf.fit(X_train, y_train)
    duration = time.time() - t0
    logger.info("Model training completed in %.2f seconds.", duration)
    return clf, duration


def evaluate_threshold_procedure(
    clf: HistGradientBoostingClassifier, X_val: pd.DataFrame, y_val: np.ndarray
) -> Tuple[float, List[Dict[str, Any]], Dict[str, Any]]:
    """Reproduces the validation threshold search procedure from train_url_classifier.py."""
    logger.info("Reproducing validation threshold search (61 points between 0.20 and 0.80)...")
    val_probs = clf.predict_proba(X_val)[:, 1]
    threshold_candidates = np.linspace(0.20, 0.80, 61)

    best_threshold = 0.50
    best_thresh_score = -1.0
    val_records = []

    for t in threshold_candidates:
        preds = (val_probs >= t).astype(int)
        f1 = f1_score(y_val, preds, zero_division=0)
        rec = recall_score(y_val, preds, zero_division=0)
        prec = precision_score(y_val, preds, zero_division=0)

        benign_val_mask = y_val == 0
        benign_fps = int(np.sum(preds[benign_val_mask] == 1))
        benign_total = int(np.sum(benign_val_mask))
        benign_fpr = benign_fps / benign_total if benign_total > 0 else 0.0

        val_records.append({
            "threshold": round(float(t), 2),
            "f1": round(float(f1), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "benign_domain_fpr": round(float(benign_fpr), 4),
        })

        if benign_fpr <= 0.05:
            composite = f1 + (rec * 0.1)
            if composite > best_thresh_score:
                best_thresh_score = composite
                best_threshold = float(t)

    logger.info("Selected optimal validation threshold: %.2f (Production frozen threshold = %.2f)",
                best_threshold, OPERATING_THRESHOLD)

    # Evaluate validation split at operating threshold
    val_preds_op = (val_probs >= OPERATING_THRESHOLD).astype(int)
    cm_val = confusion_matrix(y_val, val_preds_op)
    tn_v, fp_v, fn_v, tp_v = [int(x) for x in cm_val.ravel()]

    p_curve_v, r_curve_v, _ = precision_recall_curve(y_val, val_probs)
    val_pr_auc = float(auc(r_curve_v, p_curve_v))

    val_metrics = {
        "threshold": OPERATING_THRESHOLD,
        "accuracy": round(float(accuracy_score(y_val, val_preds_op)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_val, val_preds_op)), 4),
        "precision": round(float(precision_score(y_val, val_preds_op, zero_division=0)), 4),
        "recall": round(float(recall_score(y_val, val_preds_op, zero_division=0)), 4),
        "specificity": round(float(tn_v / (tn_v + fp_v) if (tn_v + fp_v) > 0 else 0.0), 4),
        "f1_score": round(float(f1_score(y_val, val_preds_op, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_val, val_probs)), 4),
        "pr_auc": round(val_pr_auc, 4),
        "fpr": round(float(fp_v / (tn_v + fp_v) if (tn_v + fp_v) > 0 else 0.0), 4),
        "confusion_matrix": {"tn": tn_v, "fp": fp_v, "fn": fn_v, "tp": tp_v},
        "prob_distribution": {
            "min": round(float(np.min(val_probs)), 4),
            "p25": round(float(np.percentile(val_probs, 25)), 4),
            "median": round(float(np.median(val_probs)), 4),
            "p75": round(float(np.percentile(val_probs, 75)), 4),
            "max": round(float(np.max(val_probs)), 4),
            "mean": round(float(np.mean(val_probs)), 4),
        },
    }
    return best_threshold, val_records, val_metrics


def evaluate_test_set(
    clf: HistGradientBoostingClassifier, X_test: pd.DataFrame, y_test: np.ndarray, threshold: float = OPERATING_THRESHOLD
) -> Tuple[Dict[str, Any], np.ndarray, np.ndarray]:
    """Single-pass test evaluation on untouched test partition."""
    logger.info("Executing single-pass evaluation on untouched Test partition (threshold = %.2f)...", threshold)
    test_probs = clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= threshold).astype(int)

    cm = confusion_matrix(y_test, test_preds)
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]

    p_curve, r_curve, _ = precision_recall_curve(y_test, test_probs)
    test_pr_auc = float(auc(r_curve, p_curve))

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, test_preds)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, test_preds)), 4),
        "precision": round(float(precision_score(y_test, test_preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, test_preds, zero_division=0)), 4),
        "specificity": round(float(tn / (tn + fp) if (tn + fp) > 0 else 0.0), 4),
        "f1_score": round(float(f1_score(y_test, test_preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, test_probs)), 4),
        "pr_auc": round(test_pr_auc, 4),
        "fpr": round(float(fp / (tn + fp) if (tn + fp) > 0 else 0.0), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }

    logger.info("Test Metrics: Accuracy=%.4f, BalAcc=%.4f, Precision=%.4f, Recall=%.4f, F1=%.4f, ROC-AUC=%.4f, PR-AUC=%.4f",
                metrics["accuracy"], metrics["balanced_accuracy"], metrics["precision"], metrics["recall"],
                metrics["f1_score"], metrics["roc_auc"], metrics["pr_auc"])
    return metrics, test_probs, test_preds


def compare_with_production_model(
    reproduced_clf: HistGradientBoostingClassifier,
    X_test: pd.DataFrame,
    test_probs_repro: np.ndarray,
    test_preds_repro: np.ndarray,
) -> Dict[str, Any]:
    """Compares the reproduced model against the frozen production v1.0.0 model artifact."""
    logger.info("Loading production v1.0.0 model from %s ...", PROD_CLASSIFIER_PATH)
    prod_clf = joblib.load(PROD_CLASSIFIER_PATH)

    logger.info("Running inference with production model on Test feature matrix...")
    prod_probs = prod_clf.predict_proba(X_test)[:, 1]
    prod_preds = (prod_probs >= OPERATING_THRESHOLD).astype(int)

    # Agreement and correlation
    exact_matches = int(np.sum(test_preds_repro == prod_preds))
    agreement_rate = exact_matches / len(prod_preds)

    abs_prob_diff = np.abs(test_probs_repro - prod_probs)
    mean_abs_diff = float(np.mean(abs_prob_diff))
    max_abs_diff = float(np.max(abs_prob_diff))

    pearson_corr = float(np.corrcoef(test_probs_repro, prod_probs)[0, 1])

    # Mismatches
    mismatch_idx = np.where(test_preds_repro != prod_preds)[0]
    mismatch_records = []
    for idx in mismatch_idx[:20]:
        mismatch_records.append({
            "index": int(idx),
            "reproduced_prob": round(float(test_probs_repro[idx]), 4),
            "production_prob": round(float(prod_probs[idx]), 4),
            "reproduced_pred": int(test_preds_repro[idx]),
            "production_pred": int(prod_preds[idx]),
            "diff": round(float(abs_prob_diff[idx]), 4),
        })

    comparison_results = {
        "total_test_samples": len(prod_preds),
        "exact_prediction_matches": exact_matches,
        "prediction_agreement_pct": round(agreement_rate * 100.0, 2),
        "probability_pearson_correlation": round(pearson_corr, 6),
        "probability_mean_absolute_difference": round(mean_abs_diff, 6),
        "probability_max_absolute_difference": round(max_abs_diff, 6),
        "mismatches_count": len(mismatch_idx),
        "sample_mismatches": mismatch_records,
    }

    logger.info("Artifact Comparison: Agreement=%.2f%% (%d/%d), Pearson=%.6f, MeanAbsDiff=%.6f",
                comparison_results["prediction_agreement_pct"], exact_matches, len(prod_preds),
                pearson_corr, mean_abs_diff)
    return comparison_results


def run_determinism_test(X_train: pd.DataFrame, y_train: np.ndarray, X_test: pd.DataFrame, original_probs: np.ndarray) -> Dict[str, Any]:
    """Fits an independent second model and asserts 100% numerical equality."""
    logger.info("Executing determinism verification pass...")
    clf2 = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.1,
        max_leaf_nodes=31,
        min_samples_leaf=20,
        random_state=RANDOM_SEED,
        class_weight="balanced",
    )
    clf2.fit(X_train, y_train)
    probs2 = clf2.predict_proba(X_test)[:, 1]

    diff = np.max(np.abs(probs2 - original_probs))
    is_identical = bool(diff == 0.0)
    hash1 = hashlib.sha256(original_probs.tobytes()).hexdigest()
    hash2 = hashlib.sha256(probs2.tobytes()).hexdigest()

    assert is_identical and hash1 == hash2, "Determinism check failed!"
    logger.info("Determinism test PASSED: Max prob diff = 0.0, SHA-256 = %s", hash1)
    return {
        "determinism_pass": is_identical,
        "max_prob_difference": float(diff),
        "probability_vector_sha256": hash1,
    }


def main():
    start_time = time.time()
    logger.info("Starting Phase 3 Step 2: URL Baseline Reproduction...")

    train_df, val_df, test_df, domain_stats = load_and_verify_manifest()
    X_train, y_train, X_val, y_val, X_test, y_test = extract_features(train_df, val_df, test_df)

    clf, train_duration = train_model(X_train, y_train)

    best_thresh, val_records, val_metrics = evaluate_threshold_procedure(clf, X_val, y_val)
    test_metrics, test_probs, test_preds = evaluate_test_set(clf, X_test, y_test, OPERATING_THRESHOLD)

    comparison = compare_with_production_model(clf, X_test, test_probs, test_preds)
    determinism = run_determinism_test(X_train, y_train, X_test, test_probs)

    # Save reproduced artifacts in experiments/
    model_artifact_path = EXP_DIR / "reproduced_url_classifier_v1.joblib"
    metadata_artifact_path = EXP_DIR / "reproduced_url_metadata.json"
    schema_artifact_path = EXP_DIR / "reproduced_url_schema.json"
    metrics_artifact_path = EXP_DIR / "reproduced_url_test_metrics.json"

    logger.info("Saving reproduced model to %s ...", model_artifact_path)
    joblib.dump(clf, model_artifact_path, compress=3)

    schema_data = {
        "model_name": "CYBERGUARD Supervised Malicious URL Classifier (Reproduced Baseline)",
        "version": "1.0.0-reproduced",
        "features": URL_FEATURE_COLUMNS,
        "feature_count": len(URL_FEATURE_COLUMNS),
        "operating_threshold": OPERATING_THRESHOLD,
    }
    with open(schema_artifact_path, "w", encoding="utf-8") as f:
        json.dump(schema_data, f, indent=2)

    metadata_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_name": "CYBERGUARD Supervised Malicious URL Classifier",
        "version": "1.0.0-reproduced",
        "algorithm": "HistGradientBoosting",
        "random_seed": RANDOM_SEED,
        "operating_threshold": OPERATING_THRESHOLD,
        "training_duration_seconds": round(train_duration, 2),
        "total_duration_seconds": round(time.time() - start_time, 2),
        "domain_statistics": domain_stats,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "production_comparison": comparison,
        "determinism": determinism,
    }
    with open(metadata_artifact_path, "w", encoding="utf-8") as f:
        json.dump(metadata_data, f, indent=2)

    with open(metrics_artifact_path, "w", encoding="utf-8") as f:
        json.dump(test_metrics, f, indent=2)

    logger.info("Reproduction experiment successfully finished in %.2f seconds.", time.time() - start_time)
    logger.info("All artifacts saved to %s", EXP_DIR)
    return metadata_data


if __name__ == "__main__":
    main()
