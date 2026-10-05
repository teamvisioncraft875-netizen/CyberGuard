#!/usr/bin/env python3
"""
CYBERGUARD Phase 8.3: Audio Deepfake Candidate Training & Validation Script.
Trains and compares controlled audio deepfake detection candidates using the expanded
28-feature forensic acoustic schema:
- Candidate A: StandardScaler + LogisticRegression (C=1.0, max_iter=1000)
- Candidate B: StandardScaler + RandomForestClassifier (n_estimators=100, max_depth=5, min_samples_split=4, min_samples_leaf=2)
- Candidate C: StandardScaler + HistGradientBoostingClassifier (max_depth=3, min_samples_leaf=10, l2_regularization=1.0)

Training and validation strictly utilize:
  Train: 140 samples (70 real / 70 fake, 47 unique speakers)
  Val:   50 samples  (25 real / 25 fake, 23 unique speakers)

The frozen test set (50 samples, 25 real / 25 fake, 17 unseen speakers) is evaluated EXACTLY ONCE
only after the winning candidate is selected and its threshold is frozen on validation data.
"""

import io
import os
import sys
import json
import time
import math
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple

import joblib
import numpy as np
import pandas as pd
import scipy.signal as signal
import scipy.fft as fft
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
AUDIO_DATASET_DIR = REPO_ROOT / "datasets" / "deepfake-audio-detection"
MANIFEST_PATH = AUDIO_DATASET_DIR / "manifest.csv"
TIMESTAMP_STR = time.strftime("%Y%m%d_%H%M%S")
EXPERIMENT_DIR = ML_SERVICE_DIR / "experiments" / f"audio_candidates_phase8_{TIMESTAMP_STR}"

if str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

from app.services.media_anomaly.audio_detector import _load_audio_data, _compute_pitch_jitter

# ==============================================================================
# 28-FEATURE FORENSIC ACOUSTIC SCHEMA
# ==============================================================================
FEATURE_NAMES = [
    # Base 13 features
    "zero_crossing_rate",
    "spectral_centroid_hz",
    "spectral_rolloff_85_hz",
    "spectral_rolloff_95_hz",
    "spectral_flux",
    "subband_ratio_4k_to_8k",
    "subband_ratio_2k_to_4k",
    "high_freq_ratio_4k",
    "spectral_flatness",
    "high_freq_cutoff_detected",
    "mean_f0_hz",
    "pitch_jitter_pct",
    "anomaly_score",
    # Additional 15 features
    "mfcc_1_mean",
    "mfcc_2_mean",
    "mfcc_3_mean",
    "mfcc_4_mean",
    "mfcc_5_mean",
    "mfcc_6_mean",
    "mfcc_7_mean",
    "mfcc_8_mean",
    "mfcc_9_mean",
    "mfcc_10_mean",
    "spectral_contrast_b1",
    "spectral_contrast_b2",
    "spectral_contrast_b3",
    "spectral_contrast_b4",
    "spectral_bandwidth_hz",
]


def hz_to_mel(hz: float) -> float:
    return 2595.0 * np.log10(1.0 + hz / 700.0)


def mel_to_hz(mel: float) -> float:
    return 700.0 * (10.0 ** (mel / 2595.0) - 1.0)


def get_mel_filterbank(sr: int, n_fft: int, n_mels: int = 26, fmin: float = 20.0, fmax: float = 8000.0) -> np.ndarray:
    mel_min = hz_to_mel(fmin)
    mel_max = hz_to_mel(fmax)
    mel_points = np.linspace(mel_min, mel_max, n_mels + 2)
    hz_points = mel_to_hz(mel_points)
    bin_points = np.floor((n_fft + 1) * hz_points / sr).astype(int)

    filters = np.zeros((n_mels, n_fft // 2 + 1))
    for m in range(1, n_mels + 1):
        f_m_minus = bin_points[m - 1]
        f_m = bin_points[m]
        f_m_plus = bin_points[m + 1]

        for k in range(f_m_minus, f_m):
            if f_m != f_m_minus:
                filters[m - 1, k] = (k - f_m_minus) / (f_m - f_m_minus)
        for k in range(f_m, f_m_plus):
            if f_m_plus != f_m:
                filters[m - 1, k] = (f_m_plus - k) / (f_m_plus - f_m)
    return filters


def extract_28_audio_features(audio_path: str) -> Dict[str, float]:
    sr, audio = _load_audio_data(audio_path)
    if len(audio) < 256:
        raise ValueError("Audio clip too short for analysis")

    # 1. Base features
    zcr = float(np.mean(np.abs(np.diff(np.signbit(audio)))))
    nperseg = min(1024, len(audio))
    noverlap = nperseg // 2
    freqs, times, Sxx = signal.spectrogram(audio, fs=sr, nperseg=nperseg, noverlap=noverlap)
    power = np.abs(Sxx)
    total_power_per_frame = power.sum(axis=0) + 1e-12
    total_power = float(power.sum()) + 1e-12

    # Centroid
    centroids = (freqs[:, None] * power).sum(axis=0) / total_power_per_frame
    mean_centroid = float(np.mean(centroids))

    # Rolloffs
    cum_power = np.cumsum(power, axis=0) / total_power_per_frame[None, :]
    r85_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.85), 0, cum_power)
    r95_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.95), 0, cum_power)
    rolloff_85 = float(np.mean(freqs[np.clip(r85_idx, 0, len(freqs) - 1)]))
    rolloff_95 = float(np.mean(freqs[np.clip(r95_idx, 0, len(freqs) - 1)]))

    # Flux
    if power.shape[1] > 1:
        norm_power = power / total_power_per_frame[None, :]
        spectral_flux = float(np.mean(np.sqrt(np.sum(np.diff(norm_power, axis=1) ** 2, axis=0))))
    else:
        spectral_flux = 0.0

    # Subband ratios
    mask_4k_8k = (freqs >= 4000) & (freqs <= 7600)
    subband_ratio_4k_to_8k = float(np.sum(power[mask_4k_8k, :]) / total_power)
    mask_2k_4k = (freqs >= 2000) & (freqs < 4000)
    subband_ratio_2k_to_4k = float(np.sum(power[mask_2k_4k, :]) / total_power)
    hf_mask_4k = freqs >= 4000
    hf_ratio_4k = float(np.sum(power[hf_mask_4k, :]) / total_power)

    # Flatness
    p_mean_spectrum = np.mean(power, axis=1) + 1e-12
    log_geom = float(np.mean(np.log(p_mean_spectrum)))
    geom_mean = float(np.exp(np.clip(log_geom, -50.0, 50.0)))
    arith_mean = float(np.mean(p_mean_spectrum))
    spectral_flatness = float(np.clip(geom_mean / (arith_mean + 1e-12), 0.0, 1.0))

    # Cutoff detection
    has_steep_cutoff = bool(rolloff_95 < 4600.0 and subband_ratio_4k_to_8k < 0.008)

    # Pitch & Jitter
    mean_f0, jitter_pct = _compute_pitch_jitter(audio, sr)

    # Anomaly score
    score_cutoff = 0.85 if has_steep_cutoff else 0.15
    score_pitch = 0.20
    if jitter_pct > 0.0:
        if jitter_pct < 0.65:
            score_pitch = 0.80
        elif jitter_pct > 5.0:
            score_pitch = 0.75
    score_flux = float(np.clip(spectral_flux / 0.60, 0.1, 0.9))
    score_centroid = 0.75 if (mean_centroid < 800 or mean_centroid > 3800) else 0.25
    score_flatness = float(np.clip(abs(spectral_flatness - 0.12) / 0.15, 0.1, 0.9))
    raw_anomaly = (
        0.30 * score_cutoff
        + 0.25 * score_pitch
        + 0.15 * score_flux
        + 0.15 * score_centroid
        + 0.15 * score_flatness
    )
    anomaly_score = float(np.clip(raw_anomaly, 0.05, 0.95))

    # 2. Additional 15 features
    # Spectral Bandwidth
    diff_freqs = (freqs[:, None] - mean_centroid) ** 2
    bandwidth_per_frame = np.sqrt(np.sum(diff_freqs * power, axis=0) / total_power_per_frame)
    spectral_bandwidth_hz = float(np.mean(bandwidth_per_frame))

    # Spectral Contrast across 4 subbands
    bands = [(200, 800), (800, 2000), (2000, 4000), (4000, 8000)]
    contrast_vals = []
    for b_low, b_high in bands:
        b_mask = (freqs >= b_low) & (freqs < b_high)
        if np.any(b_mask):
            band_power = power[b_mask, :]
            peak = np.percentile(band_power, 85)
            valley = np.percentile(band_power, 15) + 1e-12
            c = float(np.log10(peak + 1e-12) - np.log10(valley))
        else:
            c = 0.0
        contrast_vals.append(c)

    # MFCCs (10 coefficients)
    fbank = get_mel_filterbank(sr=sr, n_fft=nperseg, n_mels=26, fmin=20.0, fmax=8000.0)
    mel_energy = np.dot(fbank, power)
    log_mel = np.log(mel_energy + 1e-10)
    dct_coeffs = fft.dct(log_mel, type=2, axis=0, norm="ortho")
    mfcc_means = [float(np.mean(dct_coeffs[i, :])) for i in range(1, 11)]

    feats = {
        "zero_crossing_rate": round(zcr, 4),
        "spectral_centroid_hz": round(mean_centroid, 1),
        "spectral_rolloff_85_hz": round(rolloff_85, 1),
        "spectral_rolloff_95_hz": round(rolloff_95, 1),
        "spectral_flux": round(spectral_flux, 4),
        "subband_ratio_4k_to_8k": round(subband_ratio_4k_to_8k, 4),
        "subband_ratio_2k_to_4k": round(subband_ratio_2k_to_4k, 4),
        "high_freq_ratio_4k": round(hf_ratio_4k, 4),
        "spectral_flatness": round(spectral_flatness, 4),
        "high_freq_cutoff_detected": 1.0 if has_steep_cutoff else 0.0,
        "mean_f0_hz": round(mean_f0, 1),
        "pitch_jitter_pct": round(jitter_pct, 2),
        "anomaly_score": round(anomaly_score, 4),
        "mfcc_1_mean": round(mfcc_means[0], 4),
        "mfcc_2_mean": round(mfcc_means[1], 4),
        "mfcc_3_mean": round(mfcc_means[2], 4),
        "mfcc_4_mean": round(mfcc_means[3], 4),
        "mfcc_5_mean": round(mfcc_means[4], 4),
        "mfcc_6_mean": round(mfcc_means[5], 4),
        "mfcc_7_mean": round(mfcc_means[6], 4),
        "mfcc_8_mean": round(mfcc_means[7], 4),
        "mfcc_9_mean": round(mfcc_means[8], 4),
        "mfcc_10_mean": round(mfcc_means[9], 4),
        "spectral_contrast_b1": round(contrast_vals[0], 4),
        "spectral_contrast_b2": round(contrast_vals[1], 4),
        "spectral_contrast_b3": round(contrast_vals[2], 4),
        "spectral_contrast_b4": round(contrast_vals[3], 4),
        "spectral_bandwidth_hz": round(spectral_bandwidth_hz, 1),
    }
    return feats


# ==============================================================================
# METRICS & THRESHOLD SEARCH
# ==============================================================================
def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.50) -> Dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5

    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "specificity": round(spec, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def find_best_threshold(y_val: np.ndarray, val_probs: np.ndarray) -> Tuple[float, Dict[str, Any]]:
    best_thresh = 0.50
    best_score = -1.0
    best_metrics = None

    for t in np.linspace(0.05, 0.95, 91):
        m = compute_metrics(y_val, val_probs, threshold=float(t))
        if m["specificity"] >= 0.80:
            score = m["balanced_accuracy"] + 0.1 * m["recall"]
            if score > best_score:
                best_score = score
                best_thresh = float(t)
                best_metrics = m

    if best_metrics is None:
        best_score = -1.0
        for t in np.linspace(0.05, 0.95, 91):
            m = compute_metrics(y_val, val_probs, threshold=float(t))
            if m["balanced_accuracy"] > best_score:
                best_score = m["balanced_accuracy"]
                best_thresh = float(t)
                best_metrics = m

    return float(best_thresh), best_metrics


def measure_inference_latency_ms(model: Any, sample_vec: np.ndarray, iterations: int = 500) -> float:
    # Warmup
    for _ in range(50):
        model.predict_proba(sample_vec)
    t0 = time.perf_counter()
    for _ in range(iterations):
        model.predict_proba(sample_vec)
    t1 = time.perf_counter()
    return ((t1 - t0) / iterations) * 1000.0


# ==============================================================================
# MAIN TRAINING PIPELINE
# ==============================================================================
def main():
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 80)
    print("CYBERGUARD — PHASE 8.3: AUDIO DEEPFAKE CANDIDATE TRAINING & VALIDATION")
    print(f"Output Directory: {EXPERIMENT_DIR}")
    print("=" * 80)

    # 1. Dataset Verification
    assert MANIFEST_PATH.exists(), f"Missing manifest: {MANIFEST_PATH}"
    df = pd.read_csv(MANIFEST_PATH)
    print(f"\nManifest loaded: {len(df)} total samples.")
    print(f"  Split counts:\n{df['split'].value_counts().to_dict()}")

    train_df = df[df["split"] == "train"].copy().reset_index(drop=True)
    val_df = df[df["split"] == "validation"].copy().reset_index(drop=True)
    test_df = df[df["split"] == "test"].copy().reset_index(drop=True)

    assert len(train_df) == 140, f"Expected 140 train samples, got {len(train_df)}"
    assert len(val_df) == 50, f"Expected 50 val samples, got {len(val_df)}"
    assert len(test_df) == 50, f"Expected 50 test samples, got {len(test_df)}"

    train_sources = set(train_df["source_id"])
    val_sources = set(val_df["source_id"])
    test_sources = set(test_df["source_id"])

    assert len(train_sources & val_sources) == 0, "Train-Val speaker overlap detected!"
    assert len(train_sources & test_sources) == 0, "Train-Test speaker overlap detected!"
    assert len(val_sources & test_sources) == 0, "Val-Test speaker overlap detected!"
    print(f"  Speaker disjointness verified: Train={len(train_sources)}, Val={len(val_sources)}, Test={len(test_sources)} unseen speakers.")

    # 2. Extract 28 forensic features for all splits
    print("\nExtracting 28 forensic acoustic features for Train (140) and Validation (50)...")
    t0_extract = time.time()

    def build_feature_matrix(split_df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
        X_list = []
        y_list = []
        raw_records = []
        for idx, row in split_df.iterrows():
            fpath = AUDIO_DATASET_DIR / row["path"]
            feats = extract_28_audio_features(str(fpath))
            vec = [feats[col] for col in FEATURE_NAMES]
            target = 1 if row["label"] == "manipulated" else 0
            X_list.append(vec)
            y_list.append(target)
            raw_records.append(feats)
        return np.array(X_list, dtype=np.float64), np.array(y_list, dtype=int), raw_records

    X_train, y_train, train_records = build_feature_matrix(train_df)
    X_val, y_val, val_records = build_feature_matrix(val_df)
    print(f"  Train matrix: {X_train.shape} | Val matrix: {X_val.shape} (Time: {time.time() - t0_extract:.2f}s)")

    # Integrity verification
    assert not np.isnan(X_train).any(), "NaN detected in X_train!"
    assert not np.isnan(X_val).any(), "NaN detected in X_val!"
    assert not np.isinf(X_train).any(), "Inf detected in X_train!"
    assert not np.isinf(X_val).any(), "Inf detected in X_val!"
    print("  Feature matrix integrity: Zero NaNs and Zero Infs.")

    # 3. Fit Preprocessing: StandardScaler fitted ONLY on X_train
    print("\nFitting StandardScaler strictly on X_train...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    print(f"  Scaler fitted on {X_train.shape[0]} training samples across {X_train.shape[1]} features.")
    print("  CONFIRMATION: Test set remains completely isolated.")

    # 4. Define Candidates
    candidates_def = [
        {
            "name": "Candidate A (StandardScaler + LogisticRegression)",
            "estimator": LogisticRegression(C=1.0, max_iter=1000, random_state=42),
            "type": "linear",
            "desc": "Corrected feature scaling with 28-feature representation"
        },
        {
            "name": "Candidate B (StandardScaler + RandomForest)",
            "estimator": RandomForestClassifier(
                n_estimators=100, max_depth=5, min_samples_split=4, min_samples_leaf=2, random_state=42
            ),
            "type": "tree_ensemble",
            "desc": "Calibrated tree ensemble with controlled depth to prevent overfitting"
        },
        {
            "name": "Candidate C (StandardScaler + HistGradientBoosting)",
            "estimator": HistGradientBoostingClassifier(
                max_depth=3, min_samples_leaf=10, l2_regularization=1.0, random_state=42
            ),
            "type": "gradient_boosting",
            "desc": "Conservative gradient boosting with L2 regularization for small sample regime"
        }
    ]

    candidate_results = []

    print("\n" + "=" * 80)
    print("TRAINING AND VALIDATING AUDIO CANDIDATES")
    print("=" * 80)

    for cdef in candidates_def:
        name = cdef["name"]
        clf = cdef["estimator"]
        print(f"\nTraining {name}...")
        t0 = time.time()
        clf.fit(X_train_scaled, y_train)
        train_time = time.time() - t0

        # Predict probabilities on validation data
        val_probs = clf.predict_proba(X_val_scaled)[:, 1]

        # Validation threshold tuning
        best_thresh, best_metrics = find_best_threshold(y_val, val_probs)
        lat_ms = measure_inference_latency_ms(clf, X_val_scaled[0:1])

        # Save candidate artifact (bundled with scaler and feature schema)
        artifact_data = {
            "model": clf,
            "scaler": scaler,
            "feature_names": FEATURE_NAMES,
            "threshold": best_thresh,
            "val_metrics": best_metrics,
            "metadata": {
                "name": name,
                "train_samples": len(X_train),
                "val_samples": len(X_val),
                "feature_count": len(FEATURE_NAMES),
                "train_time_sec": round(train_time, 4),
                "latency_ms": round(lat_ms, 4),
                "random_state": 42
            }
        }

        cand_filename = name.split("(")[0].strip().lower().replace(" ", "_") + ".joblib"
        artifact_path = EXPERIMENT_DIR / cand_filename
        joblib.dump(artifact_data, artifact_path)
        cand_size = artifact_path.stat().st_size
        cand_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

        print(f"  Finished in {train_time:.3f}s | Selected tau = {best_thresh:.4f}")
        print(f"  Val BalAcc: {best_metrics['balanced_accuracy']*100:.2f}% | Recall: {best_metrics['recall']*100:.2f}% | Spec: {best_metrics['specificity']*100:.2f}% | F1: {best_metrics['f1']:.4f} | ROC-AUC: {best_metrics['roc_auc']:.4f}")

        candidate_results.append({
            "name": name,
            "classifier": clf,
            "threshold": best_thresh,
            "val_metrics": best_metrics,
            "val_probs": val_probs,
            "train_time_sec": round(train_time, 4),
            "latency_ms": round(lat_ms, 4),
            "size_bytes": cand_size,
            "artifact_path": str(artifact_path),
            "sha256": cand_sha
        })

    # 5. Validation Candidate Comparison Table
    print("\n" + "=" * 80)
    print("VALIDATION COMPARISON TABLE (Frozen Test Set NOT Touched)")
    print("=" * 80)
    header = f"| {'Candidate':<46s} | {'Thresh':>6s} | {'Acc':>7s} | {'BalAcc':>7s} | {'Prec':>7s} | {'Recall':>7s} | {'Spec':>7s} | {'F1':>7s} | {'FPR':>7s} | {'ROC-AUC':>7s} |"
    print(header)
    print("|" + "-" * 48 + "|" + "-" * 8 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|")

    for c in candidate_results:
        m = c["val_metrics"]
        row = f"| {c['name']:<46s} | {c['threshold']:>6.4f} | {m['accuracy']*100:>6.2f}% | {m['balanced_accuracy']*100:>6.2f}% | {m['precision']*100:>6.2f}% | {m['recall']*100:>6.2f}% | {m['specificity']*100:>6.2f}% | {m['f1']:>7.4f} | {m['fpr']*100:>6.2f}% | {m['roc_auc']:>7.4f} |"
        print(row)

    # 6. Candidate Selection Decision
    # Criterion: Maximize Balanced Accuracy subject to Specificity >= 80%, tie-break on F1
    best_candidate = max(
        candidate_results,
        key=lambda c: (c["val_metrics"]["balanced_accuracy"] + 0.1 * c["val_metrics"]["f1"])
    )

    print(f"\nWINNING CANDIDATE SELECTED FROM VALIDATION: {best_candidate['name']}")
    print(f"  Validation Balanced Accuracy: {best_candidate['val_metrics']['balanced_accuracy']*100:.2f}%")
    print(f"  Validation Recall:            {best_candidate['val_metrics']['recall']*100:.2f}%")
    print(f"  Validation Specificity:       {best_candidate['val_metrics']['specificity']*100:.2f}%")
    print(f"  Validation F1 Score:          {best_candidate['val_metrics']['f1']:.4f}")
    print(f"  Operating Threshold:          tau = {best_candidate['threshold']:.4f}")

    # 7. Final Test Gate: Untouched Test Evaluation (EXACTLY ONCE)
    print("\n" + "=" * 80)
    print("FINAL TEST GATE: EVALUATING WINNING CANDIDATE ONCE ON FROZEN TEST SET")
    print(f"Evaluating {best_candidate['name']} with frozen tau = {best_candidate['threshold']:.4f}")
    print("=" * 80)

    print("Extracting features for frozen test set (50 samples, 17 unseen speakers)...")
    X_test, y_test, test_records = build_feature_matrix(test_df)
    X_test_scaled = scaler.transform(X_test)

    best_clf = best_candidate["classifier"]
    test_probs = best_clf.predict_proba(X_test_scaled)[:, 1]
    test_metrics = compute_metrics(y_test, test_probs, threshold=best_candidate["threshold"])
    test_lat_ms = measure_inference_latency_ms(best_clf, X_test_scaled[0:1])

    # Current Production Baseline Metrics (v1.0.0, 13 features, tau=0.50)
    baseline_metrics = {
        "model": "LogisticRegression (13 features, unscaled, v1.0.0)",
        "threshold": 0.5000,
        "accuracy": 0.7200,
        "balanced_accuracy": 0.7200,
        "precision": 0.7200,
        "recall": 0.7200,
        "specificity": 0.7200,
        "fpr": 0.2800,
        "f1": 0.7200,
        "roc_auc": 0.7856,
        "pr_auc": 0.8317,
        "confusion_matrix": {"tn": 18, "fp": 7, "fn": 7, "tp": 18},
        "latency_ms": 0.0820,
        "size_bytes": 1056
    }

    print("\n" + "-" * 85)
    print("FINAL TEST COMPARISON: CURRENT PRODUCTION (v1.0.0) vs PROMOTABLE CANDIDATE")
    print("-" * 85)
    print(f"{'Metric':<25s} | {'Current Production (v1.0.0)':<30s} | {'Phase 8 Selected Candidate':<30s} | {'Delta':<15s}")
    print("-" * 105)

    comp_rows = [
        ("Architecture", baseline_metrics["model"], best_candidate["name"], ""),
        ("Threshold (tau)", f"{baseline_metrics['threshold']:.4f}", f"{test_metrics['threshold']:.4f}", ""),
        ("Accuracy", f"{baseline_metrics['accuracy']*100:.2f}%", f"{test_metrics['accuracy']*100:.2f}%", f"{(test_metrics['accuracy'] - baseline_metrics['accuracy'])*100:+.2f}%"),
        ("Balanced Accuracy", f"{baseline_metrics['balanced_accuracy']*100:.2f}%", f"{test_metrics['balanced_accuracy']*100:.2f}%", f"{(test_metrics['balanced_accuracy'] - baseline_metrics['balanced_accuracy'])*100:+.2f}%"),
        ("Recall", f"{baseline_metrics['recall']*100:.2f}%", f"{test_metrics['recall']*100:.2f}%", f"{(test_metrics['recall'] - baseline_metrics['recall'])*100:+.2f}%"),
        ("Precision", f"{baseline_metrics['precision']*100:.2f}%", f"{test_metrics['precision']*100:.2f}%", f"{(test_metrics['precision'] - baseline_metrics['precision'])*100:+.2f}%"),
        ("Specificity", f"{baseline_metrics['specificity']*100:.2f}%", f"{test_metrics['specificity']*100:.2f}%", f"{(test_metrics['specificity'] - baseline_metrics['specificity'])*100:+.2f}%"),
        ("F1 Score", f"{baseline_metrics['f1']:.4f}", f"{test_metrics['f1']:.4f}", f"{(test_metrics['f1'] - baseline_metrics['f1']):+.4f}"),
        ("FPR", f"{baseline_metrics['fpr']*100:.2f}%", f"{test_metrics['fpr']*100:.2f}%", f"{(test_metrics['fpr'] - baseline_metrics['fpr'])*100:+.2f}%"),
        ("ROC-AUC", f"{baseline_metrics['roc_auc']:.4f}", f"{test_metrics['roc_auc']:.4f}", f"{(test_metrics['roc_auc'] - baseline_metrics['roc_auc']):+.4f}"),
        ("PR-AUC", f"{baseline_metrics['pr_auc']:.4f}", f"{test_metrics['pr_auc']:.4f}", f"{(test_metrics['pr_auc'] - baseline_metrics['pr_auc']):+.4f}"),
        ("False Negatives", f"{baseline_metrics['confusion_matrix']['fn']:,}", f"{test_metrics['confusion_matrix']['fn']:,}", f"{test_metrics['confusion_matrix']['fn'] - baseline_metrics['confusion_matrix']['fn']:+,d}"),
        ("False Positives", f"{baseline_metrics['confusion_matrix']['fp']:,}", f"{test_metrics['confusion_matrix']['fp']:,}", f"{test_metrics['confusion_matrix']['fp'] - baseline_metrics['confusion_matrix']['fp']:+,d}"),
        ("Inference Latency", f"{baseline_metrics['latency_ms']:.3f} ms", f"{test_lat_ms:.3f} ms", f"{test_lat_ms - baseline_metrics['latency_ms']:+.3f} ms"),
    ]

    for label, base_val, cand_val, delta in comp_rows:
        print(f"{label:<25s} | {base_val:<30s} | {cand_val:<30s} | {delta:<15s}")

    print("-" * 105)
    print(f"Candidate Test Confusion Matrix: TN={test_metrics['confusion_matrix']['tn']}, FP={test_metrics['confusion_matrix']['fp']}, FN={test_metrics['confusion_matrix']['fn']}, TP={test_metrics['confusion_matrix']['tp']}")

    # 8. Save Full Evaluation Report JSON
    experiment_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "PHASE 8.3 — AUDIO DEEPFAKE CANDIDATE TRAINING & VALIDATION",
        "dataset": {
            "path": str(AUDIO_DATASET_DIR.relative_to(REPO_ROOT)),
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "test_samples": len(test_df),
            "train_speakers": len(train_sources),
            "val_speakers": len(val_sources),
            "test_speakers": len(test_sources),
            "speaker_disjointness_verified": True,
            "feature_count": len(FEATURE_NAMES),
            "feature_schema": FEATURE_NAMES
        },
        "candidates_evaluated": [
            {
                "name": c["name"],
                "train_time_sec": c["train_time_sec"],
                "selected_threshold": c["threshold"],
                "val_metrics": c["val_metrics"],
                "latency_ms": c["latency_ms"],
                "size_bytes": c["size_bytes"],
                "sha256": c["sha256"]
            }
            for c in candidate_results
        ],
        "winning_candidate": {
            "name": best_candidate["name"],
            "selected_threshold": best_candidate["threshold"],
            "val_metrics": best_candidate["val_metrics"],
            "final_test_metrics": test_metrics,
            "latency_ms": round(test_lat_ms, 4),
            "size_bytes": best_candidate["size_bytes"],
            "artifact_path": best_candidate["artifact_path"],
            "sha256": best_candidate["sha256"]
        },
        "baseline_metrics": baseline_metrics
    }

    report_path = EXPERIMENT_DIR / "audio_candidate_evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(experiment_report, f, indent=2)

    print(f"\nExperiment evaluation report saved to: {report_path}")


if __name__ == "__main__":
    main()
