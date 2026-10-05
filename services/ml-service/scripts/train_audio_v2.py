#!/usr/bin/env python3
"""
CYBERGUARD Phase 9: Audio Deepfake V2 Candidate Training & Validation.
Trains and compares 5 controlled audio deepfake candidates using the 28-feature forensic acoustic schema:
- Candidate A: StandardScaler + CalibratedClassifierCV(LogisticRegression(C=0.5), cv=5)
- Candidate B: StandardScaler + CalibratedClassifierCV(SVC(kernel='rbf', C=1.0), cv=5)
- Candidate C: StandardScaler + RandomForestClassifier(n_estimators=100, max_depth=4, min_samples_leaf=2)
- Candidate D: StandardScaler + MLPClassifier(hidden_layer_sizes=(64, 32), alpha=0.01, max_iter=500)
- Candidate E: StandardScaler + HistGradientBoostingClassifier(max_depth=3, min_samples_leaf=5, l2_regularization=2.0)

Training and validation strictly utilize:
  Train: 140 samples (70 real / 70 fake, 47 unique speakers)
  Val:   50 samples  (25 real / 25 fake, 23 unique speakers)
The 50 frozen test samples remain isolated and untouched during candidate training and threshold selection.
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
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, confusion_matrix
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = REPO_ROOT / "services" / "ml-service"
AUDIO_DATASET_DIR = REPO_ROOT / "datasets" / "deepfake-audio-detection"
MANIFEST_PATH = AUDIO_DATASET_DIR / "manifest.csv"
EXP_DIR = ML_SERVICE_DIR / "experiments" / "deepfake_v2_20261004_223500"

if str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

from app.services.media_anomaly.audio_detector import _load_audio_data, _compute_pitch_jitter

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

def extract_28_features(audio_path: str) -> Dict[str, float]:
    sr, audio = _load_audio_data(audio_path)
    if len(audio) < 256:
        raise ValueError("Audio clip too short")

    # Base features
    zcr = float(np.mean(np.abs(np.diff(np.signbit(audio)))))
    nperseg = min(1024, len(audio))
    noverlap = nperseg // 2
    freqs, times, Sxx = signal.spectrogram(audio, fs=sr, nperseg=nperseg, noverlap=noverlap)
    power = np.abs(Sxx)
    total_power_per_frame = power.sum(axis=0) + 1e-12
    total_power = float(power.sum()) + 1e-12

    centroids = (freqs[:, None] * power).sum(axis=0) / total_power_per_frame
    mean_centroid = float(np.mean(centroids))

    cum_power = np.cumsum(power, axis=0) / total_power_per_frame[None, :]
    r85_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.85), 0, cum_power)
    r95_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.95), 0, cum_power)
    rolloff_85 = float(np.mean(freqs[np.clip(r85_idx, 0, len(freqs) - 1)]))
    rolloff_95 = float(np.mean(freqs[np.clip(r95_idx, 0, len(freqs) - 1)]))

    if power.shape[1] > 1:
        norm_power = power / total_power_per_frame[None, :]
        spectral_flux = float(np.mean(np.sqrt(np.sum(np.diff(norm_power, axis=1) ** 2, axis=0))))
    else:
        spectral_flux = 0.0

    mask_4k_8k = (freqs >= 4000) & (freqs <= 7600)
    subband_ratio_4k_to_8k = float(np.sum(power[mask_4k_8k, :]) / total_power)
    mask_2k_4k = (freqs >= 2000) & (freqs < 4000)
    subband_ratio_2k_to_4k = float(np.sum(power[mask_2k_4k, :]) / total_power)
    hf_mask_4k = freqs >= 4000
    hf_ratio_4k = float(np.sum(power[hf_mask_4k, :]) / total_power)

    p_mean_spectrum = np.mean(power, axis=1) + 1e-12
    log_geom = float(np.mean(np.log(p_mean_spectrum)))
    geom_mean = float(np.exp(np.clip(log_geom, -50.0, 50.0)))
    arith_mean = float(np.mean(p_mean_spectrum))
    spectral_flatness = float(np.clip(geom_mean / (arith_mean + 1e-12), 0.0, 1.0))

    has_steep_cutoff = bool(rolloff_95 < 4600.0 and subband_ratio_4k_to_8k < 0.008)
    mean_f0, jitter_pct = _compute_pitch_jitter(audio, sr)

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

    # Additional 15 features
    diff_freqs = (freqs[:, None] - mean_centroid) ** 2
    bandwidth_per_frame = np.sqrt(np.sum(diff_freqs * power, axis=0) / total_power_per_frame)
    spectral_bandwidth_hz = float(np.mean(bandwidth_per_frame))

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
        "mean_f0_hz": mean_f0,
        "pitch_jitter_pct": jitter_pct,
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

def find_best_threshold(y_val: np.ndarray, val_probs: np.ndarray, min_spec: float = 0.88) -> Tuple[float, Dict[str, Any]]:
    """
    Selects operating threshold on validation data.
    Enforces minimum specificity (default 88%) to strictly control false positives on unseen speakers,
    while maximizing Balanced Accuracy + 0.1 * Recall.
    """
    best_thresh = 0.50
    best_score = -1.0
    best_metrics = None

    for t in np.linspace(0.10, 0.90, 81):
        m = compute_metrics(y_val, val_probs, threshold=float(t))
        if m["specificity"] >= min_spec:
            score = m["balanced_accuracy"] + 0.1 * m["recall"]
            if score > best_score:
                best_score = score
                best_thresh = float(t)
                best_metrics = m

    if best_metrics is None:
        # Fallback to min_spec = 0.80
        for t in np.linspace(0.10, 0.90, 81):
            m = compute_metrics(y_val, val_probs, threshold=float(t))
            if m["specificity"] >= 0.80:
                score = m["balanced_accuracy"] + 0.1 * m["recall"]
                if score > best_score:
                    best_score = score
                    best_thresh = float(t)
                    best_metrics = m

    return best_thresh, best_metrics

def main():
    print("=== CYBERGUARD Phase 9 Audio V2 Candidate Suite ===")
    df = pd.read_csv(MANIFEST_PATH)
    train_df = df[df["split"] == "train"].copy()
    val_df = df[df["split"] == "validation"].copy()

    cache_file = EXP_DIR / "audio_features_cache.joblib"
    if cache_file.exists():
        print(f"Loading cached features from {cache_file}...")
        cache = joblib.load(cache_file)
        X_train_df = cache["X_train"]
        y_train = cache["y_train"]
        X_val_df = cache["X_val"]
        y_val = cache["y_val"]
    else:
        print("Extracting 28 acoustic features for Train and Val sets...")
        train_rows = []
        for idx, row in train_df.iterrows():
            p = AUDIO_DATASET_DIR / row["path"]
            feats = extract_28_features(str(p))
            train_rows.append([feats[fn] for fn in FEATURE_NAMES])

        val_rows = []
        for idx, row in val_df.iterrows():
            p = AUDIO_DATASET_DIR / row["path"]
            feats = extract_28_features(str(p))
            val_rows.append([feats[fn] for fn in FEATURE_NAMES])

        X_train_df = pd.DataFrame(train_rows, columns=FEATURE_NAMES)
        y_train = (train_df["label"] == "manipulated").astype(int).values
        X_val_df = pd.DataFrame(val_rows, columns=FEATURE_NAMES)
        y_val = (val_df["label"] == "manipulated").astype(int).values

        joblib.dump({
            "X_train": X_train_df, "y_train": y_train,
            "X_val": X_val_df, "y_val": y_val
        }, cache_file)
        print(f"Cached features saved to {cache_file}")

    print(f"Train: {X_train_df.shape}, Val: {X_val_df.shape}")

    # Define Candidate Models
    candidates = {
        "Candidate A (Calibrated Logistic Regression)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", CalibratedClassifierCV(LogisticRegression(C=0.5, max_iter=1000, random_state=42), cv=5))
        ]),
        "Candidate B (Calibrated RBF Support Vector Machine)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", CalibratedClassifierCV(SVC(kernel="rbf", C=1.0, probability=True, random_state=42), cv=5))
        ]),
        "Candidate C (Regularized Random Forest)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=100, max_depth=4, min_samples_leaf=2, random_state=42))
        ]),
        "Candidate D (Multi-Layer Perceptron Neural Net)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", MLPClassifier(hidden_layer_sizes=(64, 32), alpha=0.01, max_iter=500, random_state=42))
        ]),
        "Candidate E (HistGradientBoosting Classifier)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", HistGradientBoostingClassifier(max_depth=3, min_samples_leaf=5, l2_regularization=2.0, random_state=42))
        ]),
    }

    results = []
    for name, pipeline in candidates.items():
        t0 = time.time()
        pipeline.fit(X_train_df, y_train)
        fit_time = time.time() - t0

        # Val prediction
        val_probs = pipeline.predict_proba(X_val_df)[:, 1]
        best_tau, val_metrics = find_best_threshold(y_val, val_probs, min_spec=0.88)

        # Benchmark latency
        latencies = []
        single_row = X_val_df.iloc[[0]]
        for _ in range(100):
            t_start = time.perf_counter()
            _ = pipeline.predict_proba(single_row)
            latencies.append((time.perf_counter() - t_start) * 1000.0)
        p50_lat = float(np.median(latencies))

        # Save artifact
        safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "").replace("-", "_")
        art_path = EXP_DIR / f"{safe_name}.joblib"
        joblib.dump(pipeline, art_path)
        art_size = art_path.stat().st_size
        sha = hashlib.sha256(art_path.read_bytes()).hexdigest()

        res = {
            "name": name,
            "train_time_sec": round(fit_time, 4),
            "selected_threshold": best_tau,
            "val_metrics": val_metrics,
            "latency_ms": round(p50_lat, 4),
            "size_bytes": art_size,
            "artifact_path": str(art_path),
            "sha256": sha
        }
        results.append(res)
        print(f"\n[{name}]")
        print(f"  Val ROC-AUC: {val_metrics['roc_auc']:.4f}, PR-AUC: {val_metrics['pr_auc']:.4f}")
        print(f"  Threshold: {best_tau:.4f}")
        print(f"  BalAcc: {val_metrics['balanced_accuracy']*100:.2f}%, Rec: {val_metrics['recall']*100:.2f}%, Spec: {val_metrics['specificity']*100:.2f}%, FPR: {val_metrics['fpr']*100:.2f}%, F1: {val_metrics['f1']:.4f}")
        print(f"  CM: {val_metrics['confusion_matrix']}")
        print(f"  Latency: {p50_lat:.3f} ms, Size: {art_size/1024:.1f} KB, SHA: {sha[:12]}...")

    # Write evaluation manifest
    out_file = EXP_DIR / "audio_candidate_comparison.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nAudio Candidate Comparison written to {out_file}")

if __name__ == "__main__":
    main()
