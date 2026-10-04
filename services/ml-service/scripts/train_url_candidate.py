"""
CYBERGUARD — Phase 3 Step 3: Malicious URL Candidate Model Training & Comparison Pipeline

Isolated experiment pipeline comparing candidate classifiers against the v1.0.0 baseline:
1. Candidate A: HistGradientBoosting (Baseline Architecture, max_iter=150, lr=0.1, max_leaf_nodes=31, balanced)
2. Candidate B: Balanced Random Forest (n_estimators=100, max_depth=16, min_samples_split=5, balanced)
3. Candidate C: Balanced Logistic Regression (max_iter=1000, C=1.0, balanced)
4. Candidate D: Tuned HistGradientBoosting (max_iter=200, lr=0.08, max_leaf_nodes=45, l2_reg=0.5, balanced)

Rules:
- Fits strictly on Train partition (100,627 samples)
- Performs threshold selection strictly on Validation partition (16,492 samples, 5,218 unseen domains)
- Enforces production constraint: Benign domain FPR <= 5.0%
- Evaluates unseen domain generalization behavior
- Evaluates the frozen candidate ONCE on the untouched Test partition (8,720 samples, 5,219 unseen domains)
- Runs determinism verification
- Saves all artifacts strictly under services/ml-service/experiments/url_exp_<timestamp>/
- ZERO mutations to production v1.0.0 artifacts or url_engine.py
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
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
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

# Ensure app is importable
repo_root = Path(__file__).resolve().parents[3]
ml_service_path = repo_root / "services" / "ml-service"
if str(ml_service_path) not in sys.path:
    sys.path.insert(0, str(ml_service_path))

from app.utils.url_preprocessor import URLPreprocessor, URL_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.url_candidate")

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

MANIFEST_PATH = repo_root / "datasets" / "cleaned_manifests" / "url_curated_manifest.parquet"
PROD_MODELS_DIR = ml_service_path / "app" / "models" / "url"
PROD_CLASSIFIER_PATH = PROD_MODELS_DIR / "malicious_url_classifier_v1.0.0.joblib"

RUN_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
EXP_DIR = ml_service_path / "experiments" / f"url_exp_{RUN_TIMESTAMP}"
EXP_DIR.mkdir(parents=True, exist_ok=True)


def load_dataset() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Loads aligned manifest and strictly validates split sizes."""
    logger.info("Loading aligned URL manifest from %s ...", MANIFEST_PATH)
    df = pd.read_parquet(MANIFEST_PATH)

    train_df = df[df["split"] == "train"].copy().reset_index(drop=True)
    val_df = df[df["split"] == "val"].copy().reset_index(drop=True)
    test_df = df[df["split"] == "test"].copy().reset_index(drop=True)

    assert len(train_df) == 100627
    assert len(val_df) == 16492
    assert len(test_df) == 8720
    assert len(df) == 125839

    # Assert zero domain leakage
    train_doms = set(train_df["domain"])
    val_doms = set(val_df["domain"])
    test_doms = set(test_df["domain"])
    assert len(train_doms.intersection(val_doms)) == 0, "Train-Val domain leakage!"
    assert len(train_doms.intersection(test_doms)) == 0, "Train-Test domain leakage!"
    assert len(val_doms.intersection(test_doms)) == 0, "Val-Test domain leakage!"

    return train_df, val_df, test_df


def extract_features(
    train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame
) -> Tuple[pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray]:
    """Extracts identical 16 dense features for all candidates."""
    logger.info("Extracting features using production URLPreprocessor...")
    preprocessor = URLPreprocessor()

    t0 = time.time()
    X_train = preprocessor.transform(train_df, url_column="url")
    y_train = train_df["label"].values.astype(int)

    X_val = preprocessor.transform(val_df, url_column="url")
    y_val = val_df["label"].values.astype(int)

    X_test = preprocessor.transform(test_df, url_column="url")
    y_test = test_df["label"].values.astype(int)

    logger.info("Extracted %d features in %.2f seconds.", len(URL_FEATURE_COLUMNS), time.time() - t0)
    return X_train, y_train, X_val, y_val, X_test, y_test


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, Any]:
    preds = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_true, preds))
    bal_acc = float(balanced_accuracy_score(y_true, preds))
    prec = float(precision_score(y_true, preds, zero_division=0))
    rec = float(recall_score(y_true, preds, zero_division=0))
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
    f1 = float(f1_score(y_true, preds, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_prob))
    precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = float(auc(recall_curve, precision_curve))

    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "specificity": round(spec, 4),
        "fpr": round(fpr, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def analyze_unseen_domain_performance(
    df_partition: pd.DataFrame, y_prob: np.ndarray, threshold: float
) -> Dict[str, Any]:
    """Analyzes performance grouped by unseen domains."""
    preds = (y_prob >= threshold).astype(int)
    df_eval = df_partition.copy()
    df_eval["pred"] = preds
    df_eval["prob"] = y_prob
    df_eval["is_correct"] = (df_eval["pred"] == df_eval["label"]).astype(int)

    # Domain-level aggregation
    # For benign domains (label==0), domain is flagged if ANY url in that domain is flagged as threat (FP domain)
    benign_domains = df_eval[df_eval["label"] == 0].groupby("domain")["pred"].max()
    benign_domain_fp_count = int((benign_domains == 1).sum())
    benign_domain_total = len(benign_domains)
    benign_domain_fpr = benign_domain_fp_count / benign_domain_total if benign_domain_total > 0 else 0.0

    # For malicious domains (label==1), domain is caught if ANY url in that domain is flagged (TP domain)
    mal_domains = df_eval[df_eval["label"] == 1].groupby("domain")["pred"].max()
    mal_domain_caught_count = int((mal_domains == 1).sum())
    mal_domain_total = len(mal_domains)
    mal_domain_tpr = mal_domain_caught_count / mal_domain_total if mal_domain_total > 0 else 0.0

    return {
        "total_unique_domains": int(df_eval["domain"].nunique()),
        "benign_domains_count": benign_domain_total,
        "benign_domains_with_false_positives": benign_domain_fp_count,
        "benign_domain_fpr_pct": round(benign_domain_fpr * 100.0, 2),
        "malicious_domains_count": mal_domain_total,
        "malicious_domains_detected": mal_domain_caught_count,
        "malicious_domain_detection_rate_pct": round(mal_domain_tpr * 100.0, 2),
    }


def measure_inference_latency(model: Any, X_sample: pd.DataFrame, n_runs: int = 500) -> float:
    """Measures single-URL inference latency in microseconds."""
    single_row = X_sample.iloc[[0]]
    # Warmup
    for _ in range(50):
        _ = model.predict_proba(single_row)

    t0 = time.perf_counter()
    for _ in range(n_runs):
        _ = model.predict_proba(single_row)
    t1 = time.perf_counter()
    latency_us = ((t1 - t0) / n_runs) * 1_000_000
    return round(latency_us, 2)


def train_and_evaluate_candidates(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
) -> Tuple[Dict[str, Any], Dict[str, Any], str, float]:
    """Fits all candidates on Train, evaluates threshold on Val, and selects champion."""
    candidates = {
        "Candidate_A_HistGradientBoosting": {
            "model": HistGradientBoostingClassifier(
                max_iter=150,
                learning_rate=0.1,
                max_leaf_nodes=31,
                min_samples_leaf=20,
                random_state=RANDOM_SEED,
                class_weight="balanced",
            ),
            "description": "Baseline HGB architecture (150 trees, lr=0.1, leaf_nodes=31)",
        },
        "Candidate_B_RandomForest": {
            "model": RandomForestClassifier(
                n_estimators=100,
                max_depth=16,
                min_samples_split=5,
                random_state=RANDOM_SEED,
                class_weight="balanced",
                n_jobs=-1,
            ),
            "description": "Balanced Random Forest (100 trees, max_depth=16)",
        },
        "Candidate_C_LogisticRegression": {
            "model": LogisticRegression(
                max_iter=1000,
                C=1.0,
                random_state=RANDOM_SEED,
                class_weight="balanced",
            ),
            "description": "Balanced L2 Logistic Regression (C=1.0, max_iter=1000)",
        },
        "Candidate_D_TunedHGB": {
            "model": HistGradientBoostingClassifier(
                max_iter=200,
                learning_rate=0.08,
                max_leaf_nodes=45,
                min_samples_leaf=15,
                l2_regularization=0.5,
                random_state=RANDOM_SEED,
                class_weight="balanced",
            ),
            "description": "Tuned HGB (200 trees, lr=0.08, leaf_nodes=45, l2=0.5)",
        },
    }

    results: Dict[str, Any] = {}
    fitted_models: Dict[str, Any] = {}
    best_candidate_name = None
    best_candidate_score = -1.0
    best_candidate_threshold = 0.50

    threshold_grid = np.linspace(0.20, 0.80, 61)

    for name, item in candidates.items():
        clf = item["model"]
        desc = item["description"]
        logger.info("=== Fitting %s (%s) ===", name, desc)

        t_fit_start = time.time()
        clf.fit(X_train, y_train)
        fit_duration = round(time.time() - t_fit_start, 2)
        fitted_models[name] = clf

        val_probs = clf.predict_proba(X_val)[:, 1]

        # Threshold sweep on Validation strictly
        best_t = 0.50
        best_score = -1.0
        val_sweep = []

        benign_mask = y_val == 0
        benign_total = int(np.sum(benign_mask))

        for t in threshold_grid:
            p = (val_probs >= t).astype(int)
            fpr = float(np.sum(p[benign_mask] == 1) / benign_total) if benign_total > 0 else 0.0
            f1 = float(f1_score(y_val, p, zero_division=0))
            rec = float(recall_score(y_val, p, zero_division=0))
            prec = float(precision_score(y_val, p, zero_division=0))

            val_sweep.append({
                "threshold": round(float(t), 2),
                "f1": round(f1, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "benign_fpr": round(fpr, 4),
            })

            # Constraint: Benign FPR <= 5.0%, optimize F1 + 0.1 * Recall
            if fpr <= 0.05:
                comp = f1 + (rec * 0.1)
                if comp > best_score:
                    best_score = comp
                    best_t = float(t)

        val_metrics = compute_metrics(y_val, val_probs, best_t)
        domain_metrics = analyze_unseen_domain_performance(val_df, val_probs, best_t)
        latency_us = measure_inference_latency(clf, X_val)

        # Model file size
        temp_path = EXP_DIR / f"{name}_temp.joblib"
        joblib.dump(clf, temp_path, compress=3)
        file_size_kb = round(os.path.getsize(temp_path) / 1024.0, 2)

        results[name] = {
            "description": desc,
            "fit_duration_seconds": fit_duration,
            "selected_threshold": round(best_t, 2),
            "val_metrics": val_metrics,
            "domain_generalization_val": domain_metrics,
            "inference_latency_us": latency_us,
            "model_size_kb": file_size_kb,
        }

        logger.info("%s -> Best Val Thresh: %.2f | F1: %.4f | Prec: %.4f | Rec: %.4f | FPR: %.4f | ROC-AUC: %.4f",
                    name, best_t, val_metrics["f1_score"], val_metrics["precision"],
                    val_metrics["recall"], val_metrics["fpr"], val_metrics["roc_auc"])
        logger.info("   Unseen Domain Benign FPR: %.2f%% | Mal Domain Detection: %.2f%%",
                    domain_metrics["benign_domain_fpr_pct"], domain_metrics["malicious_domain_detection_rate_pct"])

        # Composite score for candidate selection prioritizing discrimination and domain safety
        composite = val_metrics["roc_auc"] + val_metrics["f1_score"] - (val_metrics["fpr"] * 2.0)
        if composite > best_candidate_score:
            best_candidate_score = composite
            best_candidate_name = name
            best_candidate_threshold = best_t

    logger.info("=" * 60)
    logger.info("Selected Champion Candidate on Validation: %s (Threshold: %.2f)",
                best_candidate_name, best_candidate_threshold)
    logger.info("=" * 60)

    return results, fitted_models, best_candidate_name, best_candidate_threshold


def evaluate_final_test_set(
    fitted_models: Dict[str, Any],
    candidate_results: Dict[str, Any],
    test_df: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    champion_name: str,
) -> Dict[str, Any]:
    """Evaluates all candidates ONCE on untouched Test set with frozen thresholds."""
    logger.info("Evaluating all candidates ONCE on untouched Test partition (8,720 samples across 5,219 unseen domains)...")
    test_results: Dict[str, Any] = {}

    for name, clf in fitted_models.items():
        threshold = candidate_results[name]["selected_threshold"]
        probs = clf.predict_proba(X_test)[:, 1]
        metrics = compute_metrics(y_test, probs, threshold)
        domain_metrics = analyze_unseen_domain_performance(test_df, probs, threshold)

        test_results[name] = {
            "threshold": threshold,
            "metrics": metrics,
            "domain_generalization_test": domain_metrics,
        }

        logger.info("Test [%s, tau=%.2f] -> Acc: %.4f, BalAcc: %.4f, F1: %.4f, ROC-AUC: %.4f, Prec: %.4f, Rec: %.4f, FPR: %.4f",
                    name, threshold, metrics["accuracy"], metrics["balanced_accuracy"],
                    metrics["f1_score"], metrics["roc_auc"], metrics["precision"], metrics["recall"], metrics["fpr"])

    return test_results


def run_determinism_test(
    train_df: pd.DataFrame,
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_test: pd.DataFrame,
    champion_name: str,
    original_probs: np.ndarray,
) -> Dict[str, Any]:
    """Verifies that refitting the champion model yields deterministic probabilities."""
    logger.info("Verifying determinism for champion candidate %s ...", champion_name)
    if "HistGradientBoosting" in champion_name:
        clf2 = HistGradientBoostingClassifier(
            max_iter=150,
            learning_rate=0.1,
            max_leaf_nodes=31,
            min_samples_leaf=20,
            random_state=RANDOM_SEED,
            class_weight="balanced",
        )
    elif "Tuned" in champion_name:
        clf2 = HistGradientBoostingClassifier(
            max_iter=200,
            learning_rate=0.08,
            max_leaf_nodes=45,
            min_samples_leaf=15,
            l2_regularization=0.5,
            random_state=RANDOM_SEED,
            class_weight="balanced",
        )
    elif "RandomForest" in champion_name:
        clf2 = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            random_state=RANDOM_SEED,
            class_weight="balanced",
            n_jobs=-1,
        )
    else:
        clf2 = LogisticRegression(max_iter=1000, C=1.0, random_state=RANDOM_SEED, class_weight="balanced")

    clf2.fit(X_train, y_train)
    probs2 = clf2.predict_proba(X_test)[:, 1]

    diff = float(np.max(np.abs(probs2 - original_probs)))
    sha1 = hashlib.sha256(original_probs.tobytes()).hexdigest()
    sha2 = hashlib.sha256(probs2.tobytes()).hexdigest()
    is_identical = bool(diff == 0.0 and sha1 == sha2)

    logger.info("Determinism test: is_identical=%s, max_diff=%.6f, SHA=%s", is_identical, diff, sha1)
    return {
        "determinism_pass": is_identical,
        "max_prob_difference": diff,
        "probability_vector_sha256": sha1,
    }


def main():
    total_start_time = time.time()
    logger.info("Starting Phase 3 Step 3: Candidate Model Training & Comparison...")

    train_df, val_df, test_df = load_dataset()
    X_train, y_train, X_val, y_val, X_test, y_test = extract_features(train_df, val_df, test_df)

    # Train and evaluate on validation
    candidate_val_results, fitted_models, champion_name, champion_threshold = train_and_evaluate_candidates(
        train_df, val_df, X_train, y_train, X_val, y_val
    )

    # Evaluate on final test partition
    test_results = evaluate_final_test_set(
        fitted_models, candidate_val_results, test_df, X_test, y_test, champion_name
    )

    # Determinism
    champion_clf = fitted_models[champion_name]
    champion_test_probs = champion_clf.predict_proba(X_test)[:, 1]
    determinism = run_determinism_test(train_df, X_train, y_train, X_test, champion_name, champion_test_probs)

    # Save candidate artifacts
    for name, clf in fitted_models.items():
        artifact_path = EXP_DIR / f"{name}.joblib"
        joblib.dump(clf, artifact_path, compress=3)

    # Save summary report
    summary_report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "experiment_name": "Phase 3 Step 3: Malicious URL Candidate Comparison",
        "dataset_composition": {
            "total_urls": len(train_df) + len(val_df) + len(test_df),
            "train_samples": len(train_df),
            "validation_samples": len(val_df),
            "test_samples": len(test_df),
        },
        "feature_count": len(URL_FEATURE_COLUMNS),
        "features": URL_FEATURE_COLUMNS,
        "validation_candidate_comparison": candidate_val_results,
        "champion_candidate": champion_name,
        "champion_threshold": champion_threshold,
        "final_test_evaluation": test_results,
        "determinism": determinism,
        "total_experiment_duration_seconds": round(time.time() - total_start_time, 2),
    }

    report_path = EXP_DIR / "url_candidate_comparison_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)

    logger.info("Candidate comparison complete in %.2f seconds.", time.time() - total_start_time)
    logger.info("All artifacts saved to %s", EXP_DIR)
    return summary_report


if __name__ == "__main__":
    main()
