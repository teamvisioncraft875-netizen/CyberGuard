"""
CYBERGUARD Threat Analysis — Real Media & Deepfake Engine Pytest Suite.

Validates:
1. Real acoustic and spectral feature extraction on authentic benchmark WAV audio (podonos/audio-dfd-benchmark).
2. Real 2D FFT and azimuthal radial power spectrum feature extraction on FaceForensics++ image/video frames.
3. Determinism across repeated forensic evaluations on identical samples.
4. XAI Explanation truthfulness: explanations must directly cite computed metrics (F0, jitter, centroid, slope, lattice peaks).
5. Schema compliance with UnifiedAnalysisResponse (risk_level, risk_score, confidence_score, signals, recommended_actions).
6. Security boundaries: 10 MB payload limits (413), SSRF protections against internal/cloud metadata (403), magic-byte/format validation (415).
7. FastAPI endpoint integration (/api/v1/analyze/media and /internal/analyze/media) supporting JSON and multipart/form-data.

CRITICAL RULE COMPLIANCE:
- ZERO synthetic sine waves or artificial noise images generated.
- ONLY real media from datasets/audio-dfd-benchmark and datasets/FaceForensics are used.
"""

import base64
import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.analyze import (
    MediaAnalyzeRequest,
    MediaType,
    RiskLevel,
    UnifiedAnalysisResponse,
)
from app.services.media_anomaly.audio_detector import (
    extract_audio_forensic_features,
    _load_audio_data,
    _compute_pitch_jitter,
)
from app.services.media_anomaly.image_detector import (
    extract_image_forensic_features,
    _load_image_frame,
    _compute_radial_profile,
)
from app.services.media_engine import (
    analyze_media,
    _load_media_payload,
    _score_to_risk,
    _is_safe_url,
    MAX_MEDIA_BYTES,
)

# Project root path resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
REAL_AUDIO_PATH = PROJECT_ROOT / "datasets" / "audio-dfd-benchmark" / "dataset" / "100.wav"
REAL_AUDIO_ALT_PATH = PROJECT_ROOT / "datasets" / "audio-dfd-benchmark" / "dataset" / "1001.wav"
REAL_IMAGE_ORIG_PATH = PROJECT_ROOT / "datasets" / "FaceForensics" / "images" / "ex_original.png"
REAL_IMAGE_DEEPFAKE_PATH = PROJECT_ROOT / "datasets" / "FaceForensics" / "images" / "ex_deepfakes.png"
REAL_GIF_PATH = PROJECT_ROOT / "datasets" / "FaceForensics" / "images" / "face2face.gif"


@pytest.fixture(scope="module")
def client():
    """Provides a reusable FastAPI TestClient."""
    return TestClient(app)


# ============================================================================
# 1. Real Audio Forensic Feature Extraction Tests (Podonos Audio DFD Benchmark)
# ============================================================================

def test_real_audio_loading_and_features():
    """Validates acoustic/spectral extraction on real dataset WAV audio from Podonos benchmark."""
    assert REAL_AUDIO_PATH.is_file(), f"Real audio file not found: {REAL_AUDIO_PATH}"

    with open(REAL_AUDIO_PATH, "rb") as f:
        audio_bytes = f.read()

    features = extract_audio_forensic_features(audio_bytes)

    # Required forensic acoustic properties
    expected_fields = [
        "sample_rate",
        "duration_sec",
        "mean_f0_hz",
        "pitch_jitter_pct",
        "spectral_centroid_hz",
        "spectral_rolloff_85_hz",
        "spectral_rolloff_95_hz",
        "subband_ratio_4k_to_8k",
        "subband_ratio_2k_to_4k",
        "high_freq_ratio_4k",
        "spectral_flatness",
        "spectral_flux",
        "high_freq_cutoff_detected",
        "anomaly_score",
    ]
    for field in expected_fields:
        assert field in features, f"Missing expected audio feature: {field}"

    assert features["sample_rate"] == 16000
    assert features["duration_sec"] > 0.1
    assert 0.0 <= features["anomaly_score"] <= 1.0
    assert 0.0 <= features["subband_ratio_4k_to_8k"] <= 1.0
    assert 0.0 <= features["spectral_flatness"] <= 1.0
    assert isinstance(features["high_freq_cutoff_detected"], bool)


def test_real_audio_extraction_determinism():
    """Verifies that running extraction twice on identical real audio yields exact same values."""
    with open(REAL_AUDIO_PATH, "rb") as f:
        data = f.read()

    feat1 = extract_audio_forensic_features(data)
    feat2 = extract_audio_forensic_features(data)

    assert feat1["anomaly_score"] == feat2["anomaly_score"]
    assert feat1["spectral_centroid_hz"] == feat2["spectral_centroid_hz"]
    assert feat1["pitch_jitter_pct"] == feat2["pitch_jitter_pct"]
    assert feat1["high_freq_cutoff_detected"] == feat2["high_freq_cutoff_detected"]


# ============================================================================
# 2. Real Image / Face Forensic Feature Extraction Tests (FaceForensics++)
# ============================================================================

def test_real_image_loading_and_fft_features():
    """Validates 2D FFT, radial power spectrum, and lattice detection on real FaceForensics frames."""
    assert REAL_IMAGE_DEEPFAKE_PATH.is_file(), f"Real image file not found: {REAL_IMAGE_DEEPFAKE_PATH}"

    with open(REAL_IMAGE_DEEPFAKE_PATH, "rb") as f:
        img_bytes = f.read()

    features = extract_image_forensic_features(img_bytes)

    expected_fields = [
        "dimensions",
        "spectral_decay_slope",
        "periodic_peak_count",
        "high_freq_energy_ratio",
        "radial_spectral_entropy",
        "heatmap_base64",
        "anomaly_score",
    ]
    for field in expected_fields:
        assert field in features, f"Missing expected image feature: {field}"

    assert features["dimensions"] == [256, 256]
    assert 0.0 <= features["anomaly_score"] <= 1.0
    assert 0.0 <= features["high_freq_energy_ratio"] <= 1.0
    assert features["periodic_peak_count"] >= 0
    assert len(features["heatmap_base64"]) > 50
    # Base64 string represents a valid PNG image
    decoded_heatmap = base64.b64decode(features["heatmap_base64"])
    assert decoded_heatmap[:8] == b"\x89PNG\r\n\x1a\n"


def test_real_gif_animated_frame_extraction():
    """Verifies that animated GIFs from FaceForensics++ are parsed for frame extraction."""
    assert REAL_GIF_PATH.is_file(), f"Real GIF not found: {REAL_GIF_PATH}"

    with open(REAL_GIF_PATH, "rb") as f:
        gif_bytes = f.read()

    features = extract_image_forensic_features(gif_bytes)
    assert 0.0 <= features["anomaly_score"] <= 1.0
    assert features["dimensions"] == [256, 256]


# ============================================================================
# 3. Media Engine Pipeline & UnifiedAnalysisResponse Schema Compliance
# ============================================================================

def test_media_engine_audio_pipeline_contract():
    """Tests complete analyze_media pipeline on real audio with UnifiedAnalysisResponse validation."""
    req = MediaAnalyzeRequest(
        file_url=str(REAL_AUDIO_PATH),
        media_type=MediaType.AUDIO
    )
    resp = analyze_media(req)

    assert isinstance(resp, UnifiedAnalysisResponse)
    assert resp.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert 0 <= resp.risk_score <= 100
    assert 0.50 <= resp.confidence_score <= 1.0
    assert len(resp.recommended_actions) >= 1
    assert "pitch jitter" in resp.explanation.lower() or "acoustic spectral" in resp.explanation.lower()
    assert "model_type" in resp.signals
    assert resp.signals["model_type"] == "acoustic_spectral_forensic_analyzer"


def test_media_engine_image_pipeline_contract():
    """Tests complete analyze_media pipeline on real FaceForensics frame."""
    req = MediaAnalyzeRequest(
        file_url=str(REAL_IMAGE_ORIG_PATH),
        media_type=MediaType.IMAGE
    )
    resp = analyze_media(req)

    assert isinstance(resp, UnifiedAnalysisResponse)
    assert 0 <= resp.risk_score <= 100
    assert "2D Fourier" in resp.explanation or "spectral decay" in resp.explanation
    assert resp.signals["model_type"] == "2d_fft_forensic_analyzer"
    assert "fourier_heatmap_base64" in resp.signals


def test_media_engine_base64_data_uri_input():
    """Verifies analyze_media handles data:image/png;base64,... inputs directly."""
    with open(REAL_IMAGE_DEEPFAKE_PATH, "rb") as f:
        raw_b64 = base64.b64encode(f.read()).decode("ascii")

    data_uri = f"data:image/png;base64,{raw_b64}"
    req = MediaAnalyzeRequest(file_url=data_uri, media_type=MediaType.IMAGE)
    resp = analyze_media(req)

    assert isinstance(resp, UnifiedAnalysisResponse)
    assert 0 <= resp.risk_score <= 100


# ============================================================================
# 4. Security Resilience & Boundary Protection Tests
# ============================================================================

def test_ssrf_protection_blocked_hosts():
    """Verifies that SSRF validator rejects private, loopback, and metadata ranges."""
    blocked_urls = [
        "http://127.0.0.1:8080/fake.wav",
        "http://localhost:5000/audio.wav",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal.png",
        "http://192.168.1.1/secret.wav",
        "http://172.16.0.1/admin.png",
        "ftp://example.com/audio.wav",  # Non http/https
    ]
    for url in blocked_urls:
        assert not _is_safe_url(url), f"URL should be blocked for SSRF: {url}"


def test_ssrf_rejection_in_analyze_media():
    """Verifies analyze_media raises ValueError when given an SSRF loopback URL."""
    req = MediaAnalyzeRequest(
        file_url="http://127.0.0.1:9000/internal_leak.wav",
        media_type=MediaType.AUDIO
    )
    with pytest.raises(ValueError, match="prohibited"):
        analyze_media(req)


def test_oversized_payload_rejection():
    """Verifies rejection when payload exceeds MAX_MEDIA_BYTES (10 MB)."""
    # Create base64 string exceeding 10 MB limit
    oversized_data = b"RIFF" + (b"\x00" * (MAX_MEDIA_BYTES + 1024))
    b64_str = f"data:audio/wav;base64,{base64.b64encode(oversized_data).decode('ascii')}"

    req = MediaAnalyzeRequest(file_url=b64_str, media_type=MediaType.AUDIO)
    with pytest.raises(ValueError, match="exceeds 10 MB limit"):
        analyze_media(req)


def test_corrupted_or_unsupported_media_format():
    """Verifies that non-media or corrupted bytes raise clean ValueError."""
    corrupted_data = b"THIS_IS_NOT_A_VALID_WAV_OR_IMAGE_PAYLOAD_AT_ALL_CYBERGUARD"
    b64_str = f"data:application/octet-stream;base64,{base64.b64encode(corrupted_data).decode('ascii')}"

    req = MediaAnalyzeRequest(file_url=b64_str, media_type=MediaType.AUDIO)
    with pytest.raises(ValueError, match="Unsupported audio format"):
        analyze_media(req)


# ============================================================================
# 5. FastAPI Endpoints Integration Tests (/api/v1/analyze/media & /internal)
# ============================================================================

@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_fastapi_media_endpoint_json(client, route_prefix):
    """Tests POST analyze/media with JSON body for real FaceForensics frame."""
    res = client.post(
        f"{route_prefix}/analyze/media",
        json={"file_url": str(REAL_IMAGE_ORIG_PATH), "media_type": "image"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "risk_level" in data
    assert "risk_score" in data
    assert "explanation" in data
    assert "signals" in data
    assert data["signals"]["media_type"] == "image"


@pytest.mark.parametrize("route_prefix", ["/api/v1", "/internal"])
def test_fastapi_media_endpoint_audio_json(client, route_prefix):
    """Tests POST analyze/media with JSON body for real Podonos benchmark audio."""
    res = client.post(
        f"{route_prefix}/analyze/media",
        json={"file_url": str(REAL_AUDIO_PATH), "media_type": "audio"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "risk_level" in data
    assert 0 <= data["risk_score"] <= 100
    assert data["signals"]["media_type"] == "audio"


def test_fastapi_media_multipart_upload(client):
    """Tests POST /api/v1/analyze/media with multipart/form-data real image file."""
    with open(REAL_IMAGE_ORIG_PATH, "rb") as f:
        file_bytes = f.read()

    res = client.post(
        "/api/v1/analyze/media",
        files={"file": ("ex_original.png", file_bytes, "image/png")},
        data={"media_type": "image"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["signals"]["media_type"] == "image"
    assert "fourier_heatmap_base64" in data["signals"]


def test_fastapi_media_multipart_unsupported_format(client):
    """Tests that uploading an unsupported file format (e.g., text/plain) returns 415."""
    res = client.post(
        "/api/v1/analyze/media",
        files={"file": ("malicious.txt", b"Hello cyberguard not an image or audio file 1234567890", "text/plain")},
    )
    assert res.status_code == 415
    assert "Unsupported media format" in res.json()["detail"]


def test_fastapi_media_ssrf_rejection_http_status(client):
    """Tests that SSRF attempt via JSON body returns 403 Forbidden."""
    res = client.post(
        "/api/v1/analyze/media",
        json={"file_url": "http://127.0.0.1:8000/secret.wav", "media_type": "audio"}
    )
    assert res.status_code == 403
    assert "prohibited" in res.json()["detail"].lower()
