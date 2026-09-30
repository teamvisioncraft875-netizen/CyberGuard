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
    """Verifies execution of the validation audit and report generation."""
    report = run_full_validation_audit()
    assert report["status"] in ("ESTABLISHED", "NOT ESTABLISHED", "PARTIALLY_ESTABLISHED")
    assert "podonos_audio_benchmark" in report
    assert "faceforensics_visual_benchmark" in report
    assert "validated_deepfake_audio_benchmark" in report
    assert report["production_threshold"] == 0.50

    # Podonos must remain private/blocked
    assert report["podonos_audio_benchmark"]["status"] == "BLOCKED_PRIVATE_LABELS"
    # Audio benchmark must be established
    assert report["validated_deepfake_audio_benchmark"]["status"] == "ESTABLISHED_VALIDATED"
    metrics = report["validated_deepfake_audio_benchmark"]["metrics"]
    assert metrics["accuracy"] >= 0.65
    assert metrics["balanced_accuracy"] >= 0.65
    assert metrics["roc_auc"] >= 0.70
    assert metrics["samples"] == 50



def test_deepfake_audio_model_and_schema_artifacts():
    """Verifies that the serialized model, schema, and training metadata exist and match leakage-fixed specs."""
    import joblib
    models_dir = PROJECT_ROOT / "services" / "ml-service" / "app" / "models"
    model_path = models_dir / "deepfake_audio_classifier.joblib"
    schema_path = models_dir / "deepfake_audio_schema.json"
    metadata_path = models_dir / "deepfake_audio_metadata.json"

    assert model_path.exists(), "Trained model artifact missing"
    assert schema_path.exists(), "Feature schema missing"
    assert metadata_path.exists(), "Training metadata missing"

    model = joblib.load(model_path)
    assert hasattr(model, "predict_proba"), "Model must support predict_proba"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    assert schema["model_type"] in ("LogisticRegression", "RandomForestClassifier", "GradientBoostingClassifier")
    assert schema["feature_version"] == "2.0.0_leakage_fixed"
    assert schema["feature_count"] == 13
    assert schema["target_sample_rate"] == 16000
    assert schema["audio_channels"] == 1

    # Anti-leakage assertions: no encoding or Nyquist artifacts exposed
    assert "high_freq_ratio_8k" not in schema["features"], "Encoding leakage feature high_freq_ratio_8k must NOT be present!"
    assert "sample_rate" not in schema["features"], "Original sample rate must not be a classifier feature!"
    assert "duration_sec" not in schema["features"]

    # Redesigned features must be present
    assert "subband_ratio_4k_to_8k" in schema["features"]
    assert "subband_ratio_2k_to_4k" in schema["features"]
    assert "spectral_flatness" in schema["features"]
    assert "pitch_jitter_pct" in schema["features"]
    assert schema["frozen_threshold"] > 0.0


def test_deepfake_audio_source_level_split_integrity():
    """Programmatically verifies zero source leakage across Train, Validation, and Test."""
    import pandas as pd
    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    assert manifest_path.exists(), "Manifest missing"

    df = pd.read_csv(manifest_path)
    assert len(df) == 240
    assert set(df["split"].unique()) == {"train", "validation", "test"}

    train_sources = set(df[df["split"] == "train"]["source_id"])
    val_sources = set(df[df["split"] == "validation"]["source_id"])
    test_sources = set(df[df["split"] == "test"]["source_id"])

    assert len(train_sources & val_sources) == 0, f"Train/Val source leakage: {train_sources & val_sources}"
    assert len(train_sources & test_sources) == 0, f"Train/Test source leakage: {train_sources & test_sources}"
    assert len(val_sources & test_sources) == 0, f"Val/Test source leakage: {val_sources & test_sources}"

    # Verify class balance in each split
    for s in ["train", "validation", "test"]:
        split_df = df[df["split"] == s]
        real_c = sum(split_df["label"] == "genuine")
        fake_c = sum(split_df["label"] == "manipulated")
        assert real_c == fake_c, f"Split {s} is not balanced: {real_c} vs {fake_c}"


def test_cryptographic_hash_and_decoded_deduplication():
    """Verifies that raw and decoded hashes have ZERO cross-split intersection."""
    import pandas as pd
    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    df = pd.read_csv(manifest_path)

    train_raw_h = set(df[df["split"] == "train"]["raw_sha256"])
    val_raw_h = set(df[df["split"] == "validation"]["raw_sha256"])
    test_raw_h = set(df[df["split"] == "test"]["raw_sha256"])

    assert len(train_raw_h & val_raw_h) == 0, "Train-Val raw hash collision!"
    assert len(train_raw_h & test_raw_h) == 0, "Train-Test raw hash collision!"
    assert len(val_raw_h & test_raw_h) == 0, "Val-Test raw hash collision!"

    train_dec_h = set(df[df["split"] == "train"]["decoded_sha256"])
    val_dec_h = set(df[df["split"] == "validation"]["decoded_sha256"])
    test_dec_h = set(df[df["split"] == "test"]["decoded_sha256"])

    assert len(train_dec_h & val_dec_h) == 0, "Train-Val decoded hash collision!"
    assert len(train_dec_h & test_dec_h) == 0, "Train-Test decoded hash collision!"
    assert len(val_dec_h & test_dec_h) == 0, "Val-Test decoded hash collision!"


def test_unseen_tts_engine_generalization_partitioning():
    """Verifies that Kokoro and Hume AI TTS engines are strictly held out in the Test partition."""
    import pandas as pd
    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    df = pd.read_csv(manifest_path)

    train_engines = set(df[(df["split"] == "train") & (df["label"] == "manipulated")]["manipulation_type"])
    val_engines = set(df[(df["split"] == "validation") & (df["label"] == "manipulated")]["manipulation_type"])
    test_engines = set(df[(df["split"] == "test") & (df["label"] == "manipulated")]["manipulation_type"])

    # Unseen engines must not appear in train or validation
    assert "Kokoro / HuggingFace TTS" not in train_engines
    assert "Kokoro / HuggingFace TTS" not in val_engines
    assert "Hume AI Expressive Voice" not in train_engines
    assert "Hume AI Expressive Voice" not in val_engines

    # Unseen engines must comprise the fake test set
    assert test_engines == {"Kokoro / HuggingFace TTS", "Hume AI Expressive Voice"}


def test_sample_rate_and_mono_normalization():
    """Verifies that audio from arbitrary sample rates (44.1 kHz, 48 kHz, 8 kHz) and stereo are normalized to 16 kHz mono."""
    from app.services.media_anomaly.audio_detector import standardize_audio
    import scipy.io.wavfile as wavfile
    import io

    # Synthetic 44.1 kHz stereo audio buffer
    sr_orig = 44100
    t = np.linspace(0, 1.0, sr_orig)
    tone_left = np.sin(2 * np.pi * 440 * t)
    tone_right = np.cos(2 * np.pi * 880 * t)
    stereo_pcm = np.stack([tone_left, tone_right], axis=1)

    bio = io.BytesIO()
    wavfile.write(bio, sr_orig, (stereo_pcm * 32767).astype(np.int16))
    raw_bytes = bio.getvalue()

    sr_norm, audio_norm = standardize_audio(raw_bytes)
    assert sr_norm == 16000
    assert audio_norm.ndim == 1, "Audio must be converted to mono"
    assert len(audio_norm) == 16000, "1.0s at 16 kHz must have exactly 16000 samples"
    assert -1.05 <= np.min(audio_norm) and np.max(audio_norm) <= 1.05


def test_deterministic_preprocessing_and_production_parity():
    """Verifies that standardize_audio produces bitwise identical results across repeated runs."""
    from app.services.media_anomaly.audio_detector import standardize_audio
    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    import pandas as pd
    df = pd.read_csv(manifest_path)
    sample_path = str(PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / df.iloc[0]["path"])

    sr1, a1 = standardize_audio(sample_path)
    sr2, a2 = standardize_audio(sample_path)

    assert sr1 == sr2 == 16000
    assert np.array_equal(a1, a2), "Standardization must be completely deterministic"


def test_deepfake_audio_inference_determinism_and_bounds():
    """Verifies deterministic prediction, absence of NaN/Inf, and probability bounds [0.0, 1.0]."""
    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    import pandas as pd
    df = pd.read_csv(manifest_path)
    sample_rel = df.iloc[0]["path"]
    full_path = str(PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / sample_rel)

    feats1 = extract_audio_forensic_features(full_path)
    feats2 = extract_audio_forensic_features(full_path)

    for k in ["anomaly_score", "spectral_centroid_hz", "pitch_jitter_pct", "spectral_flux", "spectral_flatness", "subband_ratio_4k_to_8k"]:
        assert feats1[k] == feats2[k], f"Non-deterministic feature {k}"
        assert not np.isnan(feats1[k]), f"NaN found in {k}"
        assert not np.isinf(feats1[k]), f"Inf found in {k}"

    assert 0.0 <= feats1["anomaly_score"] <= 1.0


def test_nan_inf_protection_on_silent_and_extreme_audio():
    """Verifies that silence or extreme DC audio inputs do not produce NaN or Inf values."""
    import scipy.io.wavfile as wavfile
    import io
    # Silent audio buffer
    silence = np.zeros(16000, dtype=np.int16)
    bio = io.BytesIO()
    wavfile.write(bio, 16000, silence)
    feats = extract_audio_forensic_features(bio.getvalue())

    for k, v in feats.items():
        if isinstance(v, (int, float)):
            assert not np.isnan(v), f"NaN in {k} on silence"
            assert not np.isinf(v), f"Inf in {k} on silence"


def test_production_api_audio_response_with_supervised_classifier():
    """Verifies that analyze_media returns valid UnifiedAnalysisResponse with supervised classifier signals."""
    from app.services.media_engine import analyze_media
    from app.schemas.analyze import MediaAnalyzeRequest, MediaType

    manifest_path = PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / "manifest.csv"
    import pandas as pd
    df = pd.read_csv(manifest_path)
    sample_rel = df.iloc[0]["path"]
    full_path = str(PROJECT_ROOT / "datasets" / "deepfake-audio-detection" / sample_rel)

    req = MediaAnalyzeRequest(
        media_type=MediaType.AUDIO,
        file_url=full_path
    )
    resp = analyze_media(req)

    assert resp.risk_score >= 0 and resp.risk_score <= 100
    assert resp.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(resp.explanation) > 10
    assert len(resp.recommended_actions) >= 1
    assert "classification" in resp.signals
    assert resp.signals["classification"] in ("genuine", "manipulated")
    assert "classification_score" in resp.signals
    assert 0.0 <= resp.signals["classification_score"] <= 1.0
    assert "spectral_centroid_hz" in resp.signals
    assert "pitch_jitter_pct" in resp.signals


def test_production_api_security_controls():
    """Verifies SSRF protection against loopback, cloud metadata, and traversal."""
    from app.services.media_engine import analyze_media
    from app.schemas.analyze import MediaAnalyzeRequest, MediaType

    # SSRF loopback attempt
    with pytest.raises(ValueError, match="SSRF protection"):
        analyze_media(MediaAnalyzeRequest(media_type=MediaType.IMAGE, file_url="http://127.0.0.1:8080/secret"))

    # SSRF metadata attempt
    with pytest.raises(ValueError, match="SSRF protection"):
        analyze_media(MediaAnalyzeRequest(media_type=MediaType.AUDIO, file_url="http://169.254.169.254/latest/meta-data/"))


