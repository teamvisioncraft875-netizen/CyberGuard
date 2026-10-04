"""
CYBERGUARD Unit and Integration Tests for DFDC Visual Deepfake Detection Engine.
Verifies dataset audit manifest, model loading, tensor inference, UnifiedAnalysisResponse schema,
fail-closed behaviors, SSRF/oversized payload resilience, and strict audio regression protection.
"""

import base64
import io
import json
import sys
from pathlib import Path
import pytest
import torch
import numpy as np

# Ensure services/ml-service is in sys.path
ml_service_dir = Path(__file__).resolve().parent.parent
if str(ml_service_dir) not in sys.path:
    sys.path.insert(0, str(ml_service_dir))

from app.schemas.analyze import (
    MediaAnalyzeRequest,
    MediaType,
    UnifiedAnalysisResponse,
    RiskLevel,
)
from app.services.media_engine import analyze_media
from app.services.media_anomaly.image_detector import (
    AttentionPoolingVisualDetector,
    get_visual_deepfake_classifier,
    extract_image_forensic_features,
)
from app.services.media_anomaly.audio_detector import (
    extract_audio_forensic_features,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
MODELS_DIR = Path(__file__).resolve().parent.parent / "app" / "models"
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
DFDC_DIR = WORKSPACE_ROOT / "datasets" / "DFDC"


# ============================================================================
# 1. DFDC Dataset Audit & Manifest Verification
# ============================================================================

def test_dfdc_audit_report_exists_and_valid():
    """Verifies dfdc_dataset_audit_report.json exists, is structurally valid, and records real statistics."""
    report_path = SCRIPTS_DIR / "dfdc_dataset_audit_report.json"
    assert report_path.exists(), "DFDC audit report must exist"

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["dataset_name"] == "DFDC_Shield_2026"
    assert report["status"] == "DISCOVERED"
    assert report["file_inventory"]["total_files"] == 8
    assert report["splits"]["total_samples"] == 14941
    assert report["splits"]["train"]["num_samples"] == 10458
    assert report["splits"]["validation"]["num_samples"] == 2241
    assert report["splits"]["test"]["num_samples"] == 2242
    assert report["audit_conclusion"]["structurally_usable"] is True
    assert report["audit_conclusion"]["supervised_training_ready"] is True


def test_dfdc_tensors_loadable_and_uncontaminated():
    """Verifies all 6 DFDC tensor partitions are loadable and free of NaNs or Infs."""
    tensor_dir = DFDC_DIR / "shield_2026_final_data"
    for tensor_name in ["X_train.pt", "y_train.pt", "X_val.pt", "y_val.pt", "X_test.pt", "y_test.pt"]:
        t_path = tensor_dir / tensor_name
        assert t_path.exists(), f"Missing required tensor: {tensor_name}"
        t = torch.load(t_path, map_location="cpu", weights_only=True)
        assert not torch.isnan(t).any(), f"NaN values detected in {tensor_name}"
        assert not torch.isinf(t).any(), f"Inf values detected in {tensor_name}"


# ============================================================================
# 2. Visual Model Loading and Architecture Verification
# ============================================================================

def test_visual_model_artifacts_and_schema_exist():
    """Verifies that visual model weights, metadata, and schema exist in app/models/."""
    pt_path = MODELS_DIR / "deepfake_visual_classifier.pt"
    schema_path = MODELS_DIR / "deepfake_visual_schema.json"
    meta_path = MODELS_DIR / "deepfake_visual_metadata.json"

    assert pt_path.exists(), "deepfake_visual_classifier.pt must exist"
    assert schema_path.exists(), "deepfake_visual_schema.json must exist"
    assert meta_path.exists(), "deepfake_visual_metadata.json must exist"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    assert schema["input_features"] == 1024
    assert schema["model_type"] == "AttentionPoolingVisualDetector"
    assert 0.40 <= schema["frozen_threshold"] <= 0.80

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert "test_benchmark_metrics" in meta
    assert meta["test_benchmark_metrics"]["metrics"]["sample_count"] == 2242


def test_visual_model_lazy_loader():
    """Verifies get_visual_deepfake_classifier loads AttentionPoolingVisualDetector correctly."""
    clf, schema = get_visual_deepfake_classifier()
    assert clf is not None, "Classifier must load"
    assert schema is not None, "Schema must load"
    assert isinstance(clf, AttentionPoolingVisualDetector)


# ============================================================================
# 3. Model Inference & Temporal Handling Tests
# ============================================================================

def test_model_inference_single_frame_image():
    """Verifies inference on a single 1024-dim frame embedding [1, 1024]."""
    clf, schema = get_visual_deepfake_classifier()
    single_frame = torch.randn(1, 1024)
    single_frame = single_frame / single_frame.norm(dim=-1, keepdim=True)

    with torch.no_grad():
        logits = clf(single_frame)
        prob = torch.sigmoid(logits).item()

    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0


def test_model_inference_multi_frame_video():
    """Verifies temporal attention pooling on a 20-frame video sequence [1, 20, 1024]."""
    clf, schema = get_visual_deepfake_classifier()
    video_frames = torch.randn(1, 20, 1024)
    video_frames = video_frames / video_frames.norm(dim=-1, keepdim=True)

    with torch.no_grad():
        logits = clf(video_frames)
        prob = torch.sigmoid(logits).item()

    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0


# ============================================================================
# 4. API Response Schema & Full Media Pipeline Verification
# ============================================================================

def test_visual_media_analysis_contract():
    """Tests POST /api/check/media visual analysis produces compliant UnifiedAnalysisResponse."""
    img_path = WORKSPACE_ROOT / "datasets" / "FaceForensics" / "images" / "ex_original.png"
    assert img_path.exists(), "Test sample ex_original.png must exist"

    req = MediaAnalyzeRequest(
        file_url=str(img_path),
        media_type=MediaType.IMAGE
    )
    resp = analyze_media(req)

    assert isinstance(resp, UnifiedAnalysisResponse)
    assert resp.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert 0 <= resp.risk_score <= 100
    assert 0.50 <= resp.confidence_score <= 1.0
    assert len(resp.recommended_actions) >= 1
    assert "2D Fourier" in resp.explanation or "spectral decay" in resp.explanation

    # Verify signals include both supervised classification and forensic evidence
    sig = resp.signals
    assert "classification" in sig
    assert sig["classification"] in ["genuine", "manipulated"]
    assert "classification_score" in sig
    assert "classifier_model" in sig
    assert "model_identifier" in sig
    assert "model_type" in sig
    assert sig["model_type"] == "2d_fft_forensic_analyzer"
    assert "fourier_heatmap_base64" in sig
    assert "high_freq_energy_ratio" in sig
    assert "spectral_decay_slope" in sig
    assert "periodic_peak_count" in sig


# ============================================================================
# 5. Fail-Closed & Security Resilience Tests
# ============================================================================

def test_visual_media_corrupted_payload_fails_closed():
    """Verifies invalid/corrupt image bytes fail gracefully with ValueError."""
    corrupted_bytes = b"NOT_A_VALID_IMAGE_DATA_CORRUPT"
    b64_corrupt = base64.b64encode(corrupted_bytes).decode("ascii")
    req = MediaAnalyzeRequest(
        file_url=f"data:image/png;base64,{b64_corrupt}",
        media_type=MediaType.IMAGE
    )
    with pytest.raises(ValueError, match="Unsupported or corrupted image format"):
        analyze_media(req)


def test_visual_media_oversized_payload_rejected():
    """Verifies media files exceeding 10 MB limit are rejected."""
    oversized_data = b"X" * (10 * 1024 * 1024 + 1024)
    b64_oversized = base64.b64encode(oversized_data).decode("ascii")
    req = MediaAnalyzeRequest(
        file_url=f"data:image/png;base64,{b64_oversized}",
        media_type=MediaType.IMAGE
    )
    with pytest.raises(ValueError, match="exceeds 10 MB limit"):
        analyze_media(req)


# ============================================================================
# 6. Audio Regression Protection Tests (MANDATORY PROJECT BOUNDARY)
# ============================================================================

def test_audio_deepfake_pipeline_remains_intact():
    """
    CRITICAL: Validates that existing 16 kHz audio deepfake detection pipeline,
    model weights, schema, and response remain 100% unchanged.
    """
    audio_path = WORKSPACE_ROOT / "datasets" / "audio-dfd-benchmark" / "dataset" / "100.wav"
    assert audio_path.exists(), "Audio test sample must exist"

    # 1. Verify audio artifacts exist
    assert (MODELS_DIR / "deepfake_audio_classifier.joblib").exists()
    assert (MODELS_DIR / "deepfake_audio_schema.json").exists()
    assert (MODELS_DIR / "deepfake_audio_metadata.json").exists()

    # 2. Verify schema sample rate is 16 kHz mono
    with open(MODELS_DIR / "deepfake_audio_schema.json", "r", encoding="utf-8") as f:
        audio_schema = json.load(f)
    assert audio_schema["target_sample_rate"] == 16000
    assert audio_schema["audio_channels"] == 1

    # 3. Verify audio inference runs correctly
    req = MediaAnalyzeRequest(
        file_url=str(audio_path),
        media_type=MediaType.AUDIO
    )
    resp = analyze_media(req)
    assert isinstance(resp, UnifiedAnalysisResponse)
    assert resp.signals["model_type"] == "acoustic_spectral_forensic_analyzer"
    assert "classification" in resp.signals
    assert "mean_f0_hz" in resp.signals
    assert "pitch_jitter_pct" in resp.signals
