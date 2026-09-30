"""
CYBERGUARD — Media & Deepfake Detection Engine Validation & Audit Test Suite.

Validates:
1. Strict anti-fabrication rules: Podonos private gold labels are never invented.
2. Metric calculation correctness: confusion matrix, precision, recall, F1, balanced accuracy, specificity.
3. Data leakage prevention: source-level grouping and split integrity.
4. Determinism, score bounds [0, 100], and absence of NaN/Inf in forensic outputs.
5. Threshold boundary behavior and risk tier transitions.
6. Validation script execution and artifact generation.
"""

import json
from pathlib import Path
import numpy as np
import pytest

from app.services.media_anomaly.image_detector import extract_image_forensic_features
from app.services.media_anomaly.audio_detector import extract_audio_forensic_features
from app.services.media_engine import _score_to_risk
from app.schemas.analyze import RiskLevel

from scripts.evaluate_media_detector import (
    audit_podonos_audio_dataset,
    audit_faceforensics_dataset,
    compute_binary_metrics,
    run_full_validation_audit,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
REAL_IMAGE_PATH = PROJECT_ROOT / "datasets" / "FaceForensics" / "images" / "ex_deepfakes.png"
REAL_AUDIO_PATH = PROJECT_ROOT / "datasets" / "audio-dfd-benchmark" / "dataset" / "100.wav"


def test_podonos_labels_anti_fabrication_audit():
    """Verifies that audit correctly detects private labels and does NOT invent labels."""
    audit = audit_podonos_audio_dataset()
    assert audit["has_public_labels"] is False
    assert audit["status"] == "BLOCKED_PRIVATE_LABELS"
    assert "private" in audit["limitation_note"].lower()
    assert audit["total_files_found"] > 10000


def test_faceforensics_audit_catalog_and_exclusion_of_non_media():
    """Verifies FaceForensics audit catalogs media and excludes non-media (masks/figures)."""
    audit, samples = audit_faceforensics_dataset()
    assert audit["status"] == "AUDITED"
    assert audit["preview_sample_count"] == len(samples)

    sample_ids = [s["sample_id"] for s in samples]
    # Masks and paper figures must be excluded from evaluation candidates
    assert "table4_faceshifter.png" not in sample_ids
    assert "teaser.png" not in sample_ids
    assert "ex_deepfakes_mask.png" not in sample_ids
    assert "ex_neuraltextures_mask.png" not in sample_ids

    # Real evaluation candidates must be present
    assert "ex_original.png" in sample_ids
    assert "ex_deepfakes.png" in sample_ids
    assert "face2face.gif" in sample_ids


def test_metrics_calculation_perfect_prediction():
    """Verifies metric computation logic on synthetic ground-truth arrays with known values."""
    y_true = np.array([1, 1, 1, 0, 0, 0])
    y_scores = np.array([0.9, 0.8, 0.7, 0.2, 0.3, 0.1])
    metrics = compute_binary_metrics(y_true, y_scores, threshold=0.50)

    assert metrics["tp"] == 3
    assert metrics["tn"] == 3
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0
    assert metrics["accuracy"] == 1.0
    assert metrics["balanced_accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["roc_auc"] == 1.0


def test_metrics_calculation_imbalanced_class_skew():
    """Verifies balanced accuracy exposes class skew when raw accuracy is misleading."""
    # 9 positive samples, 1 negative sample. Model predicts positive for all 10.
    y_true = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 0])
    y_scores = np.array([0.8] * 10)
    metrics = compute_binary_metrics(y_true, y_scores, threshold=0.50)

    assert metrics["tp"] == 9
    assert metrics["tn"] == 0
    assert metrics["fp"] == 1
    assert metrics["fn"] == 0
    assert metrics["accuracy"] == 0.90  # Misleadingly high raw accuracy
    assert metrics["specificity"] == 0.0  # Zero specificity
    assert metrics["balanced_accuracy"] == 0.50  # Correctly identifies failure on negative class ((1.0 + 0.0) / 2)
    assert metrics["recall"] == 1.0


def test_metrics_zero_division_safety():
    """Verifies metrics computation does not crash or emit NaN on empty or extreme arrays."""
    y_true = np.array([0, 0, 0])
    y_scores = np.array([0.1, 0.2, 0.3])
    # No positive cases
    metrics = compute_binary_metrics(y_true, y_scores, threshold=0.50)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
    assert not np.isnan(metrics["accuracy"])


def test_source_level_data_leakage_detection():
    """Verifies detection of shared-source overlap across candidate samples."""
    audit, samples = audit_faceforensics_dataset()
    # Group samples by source_id
    sources = {}
    for s in samples:
        src = s["source_id"]
        sources.setdefault(src, []).append(s["sample_id"])

    # Confirm that ex_original.png and ex_deepfakes.png share the exact same source
    assert "src_video_sample_1" in sources
    shared_samples = sources["src_video_sample_1"]
    assert "ex_original.png" in shared_samples
    assert "ex_deepfakes.png" in shared_samples
    assert "ex_neuraltextures.png" in shared_samples

    # This confirms source leakage would occur if randomly split into train/test
    # and validates our rule preventing random frame-level splitting.
    assert len(shared_samples) >= 3


def test_detector_inference_determinism_and_no_nan():
    """Verifies deterministic output and absence of NaN/Inf on real sample."""
    with open(REAL_IMAGE_PATH, "rb") as f:
        data = f.read()

    feat1 = extract_image_forensic_features(data)
    feat2 = extract_image_forensic_features(data)

    assert feat1["anomaly_score"] == feat2["anomaly_score"]
    assert feat1["spectral_decay_slope"] == feat2["spectral_decay_slope"]
    assert feat1["periodic_peak_count"] == feat2["periodic_peak_count"]

    # Check for NaN / Inf
    for k, v in feat1.items():
        if isinstance(v, (int, float)):
            assert not np.isnan(v), f"Feature {k} returned NaN"
            assert not np.isinf(v), f"Feature {k} returned Inf"


def test_threshold_and_risk_tier_boundaries():
    """Verifies score-to-risk calibration transitions cleanly across all 5 tiers."""
    cases = [
        (0.00, 0, RiskLevel.SAFE),
        (0.14, 14, RiskLevel.SAFE),
        (0.15, 15, RiskLevel.LOW),
        (0.34, 34, RiskLevel.LOW),
        (0.35, 35, RiskLevel.MEDIUM),
        (0.54, 54, RiskLevel.MEDIUM),
        (0.55, 55, RiskLevel.HIGH),
        (0.74, 74, RiskLevel.HIGH),
        (0.75, 75, RiskLevel.CRITICAL),
        (1.00, 100, RiskLevel.CRITICAL),
    ]
    for score, expected_risk, expected_level in cases:
        r_score, r_level, conf = _score_to_risk(score)
        assert r_score == expected_risk, f"Score {score} expected risk {expected_risk}, got {r_score}"
        assert r_level == expected_level, f"Score {score} expected level {expected_level}, got {r_level}"
        assert 0.50 <= conf <= 1.0


def test_reproducible_validation_audit_execution():
    """Verifies execution of the validation audit and reports status NOT ESTABLISHED."""
    report = run_full_validation_audit()
    assert report["status"] == "NOT ESTABLISHED"
    assert "NOT ESTABLISHED" in report["validation_claim"]
    assert "podonos_audio_benchmark" in report
    assert "faceforensics_visual_benchmark" in report
    assert report["production_threshold"] == 0.50
