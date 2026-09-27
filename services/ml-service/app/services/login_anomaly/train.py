"""
CYBERGUARD — Login Anomaly Model Training Pipeline (Phase B)

Trains, validates, and serializes the unsupervised Isolation Forest model
for behavioral authentication anomaly detection.
Uses the Phase A Cowrie preprocessed feature datasets:
- services/ml-service/data/login/train_login_features.parquet
- services/ml-service/data/login/test_login_features.parquet

Adheres strictly to scientific validation:
- Zero fabrication of fake supervised labels (supervised model status: UNAVAILABLE)
- Strictly isolated holdout test sensor (172_234_228_9 never touched during training)
- Bounded, monotonic, deterministic anomaly score normalization
- Complete metadata and feature schema tracking
"""

import json
import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("cyberguard.login_anomaly.train")

# Explicit, ordered numerical model features (metadata strictly excluded)
LOGIN_MODEL_FEATURES = [
    "failed_attempts_count",
    "successful_attempts_count",
    "total_attempts",
    "attempt_frequency_hz",
    "unique_usernames_count",
    "unique_usernames_ratio",
    "password_entropy",
    "unique_password_count",
    "password_reuse_ratio",
    "session_duration",
    "login_hour",
    "login_hour_sin",
    "login_hour_cos",
    "day_of_week",
    "proto_ssh",
    "proto_telnet",
    "proto_other",
    "has_client_version",
    "has_hassh",
    "success_after_failure",
]

# Decision function boundaries for monotonic normalization
# Calibrated strictly on training baseline distributions
SCORE_NORMAL_BOUND = 0.15   # Decision function >= 0.15 -> anomaly_score = 0.0 (baseline normal)
SCORE_ANOMALY_BOUND = -0.25 # Decision function <= -0.25 -> anomaly_score = 1.0 (extreme outlier)


def normalize_anomaly_score(decision_scores: np.ndarray) -> np.ndarray:
    """
    Transforms raw Isolation Forest decision_function outputs into a normalized,
    monotonic, bounded anomaly score in [0.0, 1.0].
    
    In scikit-learn IsolationForest:
      decision_function(X) > 0 indicates inliers (normal)
      decision_function(X) < 0 indicates outliers (anomalies)

    Formula:
      clipped_score = clip((SCORE_NORMAL_BOUND - decision_score) / (SCORE_NORMAL_BOUND - SCORE_ANOMALY_BOUND), 0.0, 1.0)
    
    Characteristics:
      - Strictly deterministic and monotonic
      - Bounded in [0.0, 1.0]
      - 0.0 = completely normal baseline
      - 1.0 = highly anomalous outlier
      - Not a probability (no claim of P(attack))
    """
    score_span = SCORE_NORMAL_BOUND - SCORE_ANOMALY_BOUND
    normalized = (SCORE_NORMAL_BOUND - decision_scores) / score_span
    return np.clip(normalized, 0.0, 1.0)


class LoginModelTrainer:
    """
    Orchestrates data loading, validation, Isolation Forest fitting,
    held-out evaluation, and artifact persistence for the Login Engine.
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        models_dir: Optional[Path] = None,
        random_state: int = 42,
        n_estimators: int = 100,
        contamination: float = 0.04,
        holdout_sensor: str = "172_234_228_9",
    ):
        ml_service_dir = Path(__file__).resolve().parents[3]
        self.data_dir = Path(data_dir or (ml_service_dir / "data" / "login"))
        self.models_dir = Path(models_dir or (ml_service_dir / "app" / "models"))
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.holdout_sensor = holdout_sensor

        self.train_path = self.data_dir / "train_login_features.parquet"
        self.test_path = self.data_dir / "test_login_features.parquet"

        self.model: Optional[IsolationForest] = None
        self.training_metadata: Dict[str, Any] = {}

    def load_and_validate_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Loads training and test Parquet files and verifies data integrity
        and strict zero-leakage sensor isolation.
        """
        if not self.train_path.exists():
            raise FileNotFoundError(f"Training dataset not found: {self.train_path}")
        if not self.test_path.exists():
            raise FileNotFoundError(f"Test dataset not found: {self.test_path}")

        train_df = pd.read_parquet(self.train_path)
        test_df = pd.read_parquet(self.test_path)

        # 1. Feature presence check
        for feat in LOGIN_MODEL_FEATURES:
            if feat not in train_df.columns:
                raise ValueError(f"Feature '{feat}' missing from training dataset.")
            if feat not in test_df.columns:
                raise ValueError(f"Feature '{feat}' missing from test dataset.")

        # 2. NaN / Inf validation
        train_nans = int(train_df[LOGIN_MODEL_FEATURES].isna().sum().sum())
        test_nans = int(test_df[LOGIN_MODEL_FEATURES].isna().sum().sum())
        if train_nans > 0 or test_nans > 0:
            raise ValueError(f"Found NaN values in datasets (train={train_nans}, test={test_nans}).")

        train_infs = int(np.isinf(train_df[LOGIN_MODEL_FEATURES]).sum().sum())
        test_infs = int(np.isinf(test_df[LOGIN_MODEL_FEATURES]).sum().sum())
        if train_infs > 0 or test_infs > 0:
            raise ValueError(f"Found Infinite values in datasets (train={train_infs}, test={test_infs}).")

        # 3. Strict sensor leakage audit
        train_sensors = set(train_df["sensor_id"].unique())
        test_sensors = set(test_df["sensor_id"].unique())

        if self.holdout_sensor in train_sensors:
            raise ValueError(f"CRITICAL LEAKAGE: Held-out sensor '{self.holdout_sensor}' found in training data!")

        overlap = train_sensors.intersection(test_sensors)
        if len(overlap) > 0:
            raise ValueError(f"CRITICAL LEAKAGE: Sensor overlap detected: {overlap}")

        return train_df, test_df

    def audit_supervised_target(self, train_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Inspects whether a defensible ground-truth target is available for supervised learning.
        Per Phase B instructions: We do NOT manufacture fake labels.
        """
        potential_labels = ["is_threat", "label", "attack", "is_attack"]
        found_labels = [col for col in potential_labels if col in train_df.columns]

        if not found_labels:
            return {
                "supervised_model": "HistGradientBoostingClassifier",
                "status": "NOT_TRAINED",
                "reason": "A defensible supervised target is unavailable in the current Cowrie dataset.",
                "explanation": (
                    "Cowrie honeypot logs capture unfiltered adversary probing without enterprise employee "
                    "ground truth. In accordance with Phase B rules, no artificial binary labels were fabricated."
                ),
            }

        return {
            "supervised_model": "HistGradientBoostingClassifier",
            "status": "AVAILABLE",
            "target_column": found_labels[0],
        }

    def train_isolation_forest(self, train_df: pd.DataFrame) -> IsolationForest:
        """
        Trains the Isolation Forest model on numerical features from the training dataset.
        Applies a defensible provisional baseline filter to lower-intensity behavioral records.
        """
        # Feature matrix extraction with deterministic column ordering
        X_train_full = train_df[LOGIN_MODEL_FEATURES]

        # Define provisional baseline: standard-intensity sessions (non-burst, single/low username counts)
        baseline_mask = (
            (train_df["failed_attempts_count"] <= 1)
            & (train_df["unique_usernames_count"] <= 1)
            & (train_df["success_after_failure"] == 0)
            & (train_df["attempt_frequency_hz"] <= 1.5)
        )
        X_baseline = X_train_full[baseline_mask]
        logger.info(
            f"Filtered training baseline: {len(X_baseline):,} rows ({len(X_baseline)/len(train_df)*100:.2f}%) "
            f"from total {len(train_df):,} training rows."
        )

        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
            n_jobs=-1,
        )

        logger.info("Fitting Isolation Forest model...")
        model.fit(X_baseline)
        self.model = model
        return model

    def benchmark_latency(self, X_sample: pd.DataFrame, n_iterations: int = 1000) -> Dict[str, float]:
        """
        Benchmarks inference latency over n_iterations using pre-extracted feature vectors.
        Excludes model load time and file I/O.
        """
        if self.model is None:
            raise RuntimeError("Model is not trained yet.")

        # Single-row vector benchmark
        sample_vec = X_sample.iloc[[0]][LOGIN_MODEL_FEATURES]

        # Warm-up run
        _ = self.model.decision_function(sample_vec)

        latencies_ms: List[float] = []
        for _ in range(n_iterations):
            t0 = time.perf_counter()
            _ = self.model.decision_function(sample_vec)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        latencies_arr = np.array(latencies_ms)
        return {
            "mean_ms": float(np.mean(latencies_arr)),
            "median_ms": float(np.median(latencies_arr)),
            "p95_ms": float(np.percentile(latencies_arr, 95)),
            "p99_ms": float(np.percentile(latencies_arr, 99)),
        }

    def evaluate_held_out_sensor(self, test_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluates the Isolation Forest on the strictly held-out sensor test partition.
        Computes anomaly score distribution and outlier detection rate.
        """
        if self.model is None:
            raise RuntimeError("Model is not trained yet.")

        X_test = test_df[LOGIN_MODEL_FEATURES]
        raw_decisions = self.model.decision_function(X_test)
        preds = self.model.predict(X_test)  # 1 for inliers, -1 for outliers
        norm_scores = normalize_anomaly_score(raw_decisions)

        outlier_count = int(np.sum(preds == -1))
        inlier_count = int(np.sum(preds == 1))

        return {
            "test_rows": len(test_df),
            "test_sensor": self.holdout_sensor,
            "raw_decision_mean": float(np.mean(raw_decisions)),
            "raw_decision_std": float(np.std(raw_decisions)),
            "anomaly_score_mean": float(np.mean(norm_scores)),
            "anomaly_score_median": float(np.median(norm_scores)),
            "anomaly_score_p95": float(np.percentile(norm_scores, 95)),
            "anomaly_score_p99": float(np.percentile(norm_scores, 99)),
            "outliers_flagged": outlier_count,
            "inliers_flagged": inlier_count,
            "outlier_rate": float(outlier_count / len(test_df)),
            "classification_metrics": "N/A — ground truth unavailable",
        }

    def save_artifacts(
        self,
        supervised_audit: Dict[str, Any],
        held_out_eval: Dict[str, Any],
        latency_benchmark: Dict[str, float],
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
    ) -> Dict[str, Path]:
        """
        Persists fitted Isolation Forest, feature schema, and comprehensive training metadata.
        """
        if self.model is None:
            raise RuntimeError("Cannot save artifacts without a fitted model.")

        self.models_dir.mkdir(parents=True, exist_ok=True)

        model_artifact_path = self.models_dir / "login_anomaly_forest.joblib"
        schema_path = self.models_dir / "login_feature_schema.json"
        metadata_path = self.models_dir / "login_training_metadata.json"

        # 1. Save Isolation Forest checkpoint
        joblib.dump(self.model, model_artifact_path)
        logger.info(f"Saved Isolation Forest artifact to: {model_artifact_path}")

        # 2. Save deterministic feature schema
        feature_schema = {
            "feature_names": LOGIN_MODEL_FEATURES,
            "feature_count": len(LOGIN_MODEL_FEATURES),
            "score_normal_bound": SCORE_NORMAL_BOUND,
            "score_anomaly_bound": SCORE_ANOMALY_BOUND,
        }
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(feature_schema, f, indent=2)

        # 3. Save comprehensive training metadata
        training_metadata = {
            "model_type": "IsolationForest",
            "training_timestamp": datetime.now(timezone.utc).isoformat(),
            "random_seed": self.random_state,
            "feature_names": LOGIN_MODEL_FEATURES,
            "feature_count": len(LOGIN_MODEL_FEATURES),
            "training_row_count": len(train_df),
            "validation_row_count": 0,
            "held_out_test_row_count": len(test_df),
            "training_sensors": sorted(list(train_df["sensor_id"].unique())),
            "held_out_sensor": self.holdout_sensor,
            "hyperparameters": {
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "max_samples": "auto",
                "random_state": self.random_state,
            },
            "supervised_audit": supervised_audit,
            "held_out_evaluation": held_out_eval,
            "inference_latency": latency_benchmark,
            "thresholds": {
                "score_normal_bound": SCORE_NORMAL_BOUND,
                "score_anomaly_bound": SCORE_ANOMALY_BOUND,
            },
            "normalization_strategy": "piecewise_linear_bounded",
            "limitations": [
                "Dataset originates from public Cowrie honeypots and lacks genuine enterprise employee traffic.",
                "A defensible supervised target is unavailable; HistGradientBoosting was deliberately not trained.",
                "Isolation Forest anomaly scores are statistical outlier metrics, not attack probabilities P(attack).",
            ],
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(training_metadata, f, indent=2)

        self.training_metadata = training_metadata

        return {
            "model": model_artifact_path,
            "schema": schema_path,
            "metadata": metadata_path,
        }

    def run(self) -> Dict[str, Any]:
        """
        Executes end-to-end Phase B training pipeline.
        """
        logger.info("Loading and validating datasets...")
        train_df, test_df = self.load_and_validate_data()

        logger.info("Auditing supervised target availability...")
        supervised_audit = self.audit_supervised_target(train_df)

        logger.info("Fitting unsupervised Isolation Forest model...")
        self.train_isolation_forest(train_df)

        logger.info("Benchmarking inference latency...")
        latency_benchmark = self.benchmark_latency(train_df)

        logger.info("Evaluating on held-out sensor...")
        held_out_eval = self.evaluate_held_out_sensor(test_df)

        logger.info("Saving model artifacts and metadata...")
        saved_paths = self.save_artifacts(
            supervised_audit=supervised_audit,
            held_out_eval=held_out_eval,
            latency_benchmark=latency_benchmark,
            train_df=train_df,
            test_df=test_df,
        )

        return {
            "train_rows": len(train_df),
            "test_rows": len(test_df),
            "training_sensors": sorted(list(train_df["sensor_id"].unique())),
            "held_out_sensor": self.holdout_sensor,
            "supervised_audit": supervised_audit,
            "held_out_evaluation": held_out_eval,
            "latency_benchmark": latency_benchmark,
            "saved_paths": saved_paths,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    print("=" * 70)
    print("CYBERGUARD — Phase B: Login Anomaly Model Training & Validation")
    print("=" * 70)

    trainer = LoginModelTrainer()
    results = trainer.run()

    print("\n" + "=" * 70)
    print("SUPERVISED MODEL AUDIT")
    print("=" * 70)
    audit = results["supervised_audit"]
    print(f"Supervised Model: {audit['supervised_model']}")
    print(f"Status:           {audit['status']}")
    print(f"Reason:           {audit.get('reason')}")

    print("\n" + "=" * 70)
    print("ISOLATION FOREST TRAINING & EVALUATION")
    print("=" * 70)
    print(f"Training rows:    {results['train_rows']:,}")
    print(f"Testing rows:     {results['test_rows']:,}")
    print(f"Training sensors: {results['training_sensors']}")
    print(f"Held-out sensor:  {results['held_out_sensor']}")

    eval_res = results["held_out_evaluation"]
    print(f"\nHeld-Out Evaluation ({results['held_out_sensor']}):")
    print(f"  Anomaly Score Mean:   {eval_res['anomaly_score_mean']:.4f}")
    print(f"  Anomaly Score Median: {eval_res['anomaly_score_median']:.4f}")
    print(f"  Anomaly Score P95:    {eval_res['anomaly_score_p95']:.4f}")
    print(f"  Outliers Flagged:     {eval_res['outliers_flagged']:,} ({eval_res['outlier_rate']*100:.2f}%)")
    print(f"  Classification:       {eval_res['classification_metrics']}")

    latency = results["latency_benchmark"]
    print(f"\nInference Latency (Single vector benchmark):")
    print(f"  Mean:   {latency['mean_ms']:.4f} ms")
    print(f"  Median: {latency['median_ms']:.4f} ms")
    print(f"  P95:    {latency['p95_ms']:.4f} ms")
    print(f"  P99:    {latency['p99_ms']:.4f} ms")

    print("\n" + "=" * 70)
    print("SAVED ARTIFACTS")
    print("=" * 70)
    for k, p in results["saved_paths"].items():
        print(f"  {k:<10}: {p} ({p.stat().st_size / 1024:.1f} KB)")
    print("=" * 70)
