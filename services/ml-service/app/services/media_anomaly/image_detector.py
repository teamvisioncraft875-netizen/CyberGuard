"""
CYBERGUARD Image & Face Deepfake Forensic Detector.
Performs 2D Fast Fourier Transform (FFT) analysis on facial images and video frames,
detecting GAN/Diffusion periodic grid artifacts, high-frequency energy anomalies,
and unnatural radial spectral decay.
"""

import base64
import io
import math
import numpy as np
from PIL import Image, ImageSequence
import scipy.fft as fft
from pathlib import Path
from typing import Dict, Any, Tuple
import torch
import torch.nn as nn


def _load_image_frame(image_input: str | bytes, target_size: Tuple[int, int] = (256, 256)) -> np.ndarray:
    """
    Loads an image from file path or bytes, handles static images or animated GIFs,
    converts to grayscale, and resizes to target_size. Returns float32 array in [0.0, 255.0].
    """
    try:
        if isinstance(image_input, bytes):
            pil_img = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, str):
            pil_img = Image.open(image_input)
        else:
            raise ValueError(f"Unsupported image input type: {type(image_input)}")

        # If animated GIF, extract the first representative frame
        if getattr(pil_img, "is_animated", False):
            iterator = ImageSequence.Iterator(pil_img)
            pil_img = next(iterator)

        # Convert to grayscale and resize
        gray_img = pil_img.convert("L").resize(target_size, Image.Resampling.BILINEAR)
        return np.asarray(gray_img, dtype=np.float32)
    except Exception as e:
        raise ValueError(f"Unsupported or corrupted image format: {e}")


def _compute_radial_profile(log_power_spectrum: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Computes azimuthal average of the 2D power spectrum over concentric radius rings.
    Returns (radii, radial_power).
    """
    h, w = log_power_spectrum.shape
    cy, cx = h // 2, w // 2
    y, x = np.ogrid[:h, :w]
    r = np.hypot(x - cx, y - cy).astype(np.int32)
    max_r = min(cx, cy)

    # Sum and count per radial ring
    radial_sum = np.bincount(r.ravel(), weights=log_power_spectrum.ravel())
    radial_count = np.bincount(r.ravel())
    radial_mean = radial_sum[:max_r] / np.maximum(radial_count[:max_r], 1)
    radii = np.arange(len(radial_mean))
    return radii, radial_mean


def _generate_spectrum_heatmap_base64(log_power_spectrum: np.ndarray) -> str:
    """
    Converts 2D log power spectrum into a normalized grayscale PNG encoded as base64.
    """
    min_v, max_v = np.min(log_power_spectrum), np.max(log_power_spectrum)
    if max_v > min_v:
        norm = (log_power_spectrum - min_v) / (max_v - min_v) * 255.0
    else:
        norm = np.zeros_like(log_power_spectrum)

    img_uint8 = norm.astype(np.uint8)
    pil_out = Image.fromarray(img_uint8, mode="L")
    buf = io.BytesIO()
    pil_out.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def extract_image_forensic_features(image_input: str | bytes) -> Dict[str, Any]:
    """
    Performs 2D Fourier forensic spectral feature extraction on the given image.
    """
    arr = _load_image_frame(image_input)
    h, w = arr.shape

    # 1. 2D Fast Fourier Transform
    # Apply Hanning 2D window to eliminate artificial edge discontinuity border effects
    window = np.outer(np.hanning(h), np.hanning(w))
    arr_windowed = (arr - np.mean(arr)) * window

    f_transform = fft.fft2(arr_windowed)
    f_shifted = fft.fftshift(f_transform)
    power_spectrum = np.abs(f_shifted) ** 2
    log_power = np.log1p(power_spectrum)

    # 2. Radial Frequency Profile
    radii, radial_mean = _compute_radial_profile(log_power)
    max_r = len(radii)

    # 3. High-Frequency Energy Ratio
    # Natural images have high frequencies decaying steeply; generative models exhibit elevated HF tails
    hf_start = int(0.50 * max_r)
    total_energy = float(np.sum(radial_mean) + 1e-12)
    hf_energy = float(np.sum(radial_mean[hf_start:]))
    hf_ratio = float(hf_energy / total_energy)

    # 4. Spectral Slope (Power Law Decay 1/f^alpha)
    # Fit linear regression log(P) = alpha * log(r) + beta over middle-to-high frequencies
    fit_start = max(3, int(0.08 * max_r))
    fit_end = max(fit_start + 5, int(0.85 * max_r))
    log_r = np.log(radii[fit_start:fit_end].astype(np.float64) + 1e-8)
    log_p = np.log(radial_mean[fit_start:fit_end].astype(np.float64) + 1e-8)

    if len(log_r) >= 5 and np.std(log_r) > 1e-6:
        slope, _ = np.polyfit(log_r, log_p, 1)
        spectral_slope = float(slope)
    else:
        spectral_slope = -2.0

    # 5. Periodic Spectral Peak Detection
    # Convolutions with stride > 1 and upsampling (ConvTranspose2d) create periodic spikes
    smooth_radial = np.convolve(radial_mean, np.ones(5) / 5.0, mode="same")
    residual = radial_mean[fit_start:fit_end] - smooth_radial[fit_start:fit_end]
    std_res = float(np.std(residual) + 1e-8)
    peaks = np.where(residual > 2.2 * std_res)[0]
    periodic_peak_count = int(len(peaks))

    # 6. Radial Entropy
    prob_dist = radial_mean / total_energy
    radial_entropy = -float(np.sum(prob_dist * np.log(prob_dist + 1e-12)))

    # 7. Heatmap Generation
    heatmap_b64 = _generate_spectrum_heatmap_base64(log_power)

    # 8. Continuous Anomaly Score Formulation [0.0, 1.0]
    # Synthetic cues:
    # a. Periodic peaks (weight 0.40): 0 peaks -> 0.15, 1 peak -> 0.55, >=2 peaks -> 0.85
    # b. Spectral slope deviation from natural (-2.0) (weight 0.30)
    # c. High frequency ratio elevation (> 0.35) (weight 0.30)
    if periodic_peak_count == 0:
        score_peaks = 0.15
    elif periodic_peak_count == 1:
        score_peaks = 0.58
    elif periodic_peak_count == 2:
        score_peaks = 0.78
    else:
        score_peaks = 0.92

    slope_dev = abs(spectral_slope - (-2.0))
    score_slope = float(np.clip(slope_dev / 1.5, 0.1, 0.9))

    score_hf = float(np.clip((hf_ratio - 0.20) / 0.30, 0.1, 0.95))

    raw_anomaly = (
        0.40 * score_peaks +
        0.30 * score_slope +
        0.30 * score_hf
    )
    anomaly_score = float(np.clip(raw_anomaly, 0.05, 0.95))

    return {
        "dimensions": [w, h],
        "high_freq_energy_ratio": round(hf_ratio, 4),
        "spectral_decay_slope": round(spectral_slope, 4),
        "periodic_peak_count": periodic_peak_count,
        "radial_spectral_entropy": round(radial_entropy, 4),
        "heatmap_base64": heatmap_b64,
        "anomaly_score": round(anomaly_score, 4)
    }


class AttentionPoolingVisualDetector(nn.Module):
    """
    Temporal Attention-Pooled Neural Network for visual deepfake detection.
    Processes frame embeddings (e.g. 20 x 1024 dims from CLIP ViT-H/14),
    learns frame-level manipulation attention weights, and predicts manipulation probability.
    Supports single-frame images [batch, 1, 1024] and pooled embeddings [batch, 1024].
    """
    def __init__(self, in_features: int = 1024, hidden_dim: int = 256, dropout: float = 0.3):
        super().__init__()
        self.in_features = in_features
        self.hidden_dim = hidden_dim
        self.attention = nn.Sequential(
            nn.Linear(in_features, 128),
            nn.Tanh(),
            nn.Linear(128, 1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        attn_scores = self.attention(x)
        attn_weights = torch.softmax(attn_scores, dim=1)
        pooled = (x * attn_weights).sum(dim=1)
        logits = self.classifier(pooled).squeeze(-1)
        return logits


_LOADED_VISUAL_MODEL = None
_LOADED_VISUAL_SCHEMA = None


def get_visual_deepfake_classifier() -> Tuple[Any, Dict[str, Any] | None]:
    """
    Lazy loader for trained visual deepfake model and schema.
    Attempts to load PyTorch AttentionPoolingVisualDetector, with fallback to joblib.
    """
    global _LOADED_VISUAL_MODEL, _LOADED_VISUAL_SCHEMA
    if _LOADED_VISUAL_MODEL is None:
        models_dir = Path(__file__).resolve().parent.parent.parent / "models"
        schema_path = models_dir / "deepfake_visual_schema.json"
        pt_path = models_dir / "deepfake_visual_classifier.pt"
        joblib_path = models_dir / "deepfake_visual_classifier.joblib"

        if schema_path.exists():
            try:
                import json
                with open(schema_path, "r", encoding="utf-8") as f:
                    _LOADED_VISUAL_SCHEMA = json.load(f)

                if pt_path.exists():
                    model = AttentionPoolingVisualDetector(in_features=1024)
                    weights = torch.load(pt_path, map_location="cpu", weights_only=True)
                    model.load_state_dict(weights)
                    model.eval()
                    _LOADED_VISUAL_MODEL = model
                elif joblib_path.exists():
                    import joblib
                    _LOADED_VISUAL_MODEL = joblib.load(joblib_path)
            except Exception:
                pass
    return _LOADED_VISUAL_MODEL, _LOADED_VISUAL_SCHEMA
