"""
CYBERGUARD Audio Deepfake & Voice Cloning Forensic Detector.
Extracts real acoustic, spectral, and pitch features from raw WAV audio,
detecting synthetic neural vocoder artifacts, band-limited cutoffs, and pitch anomalies.
"""

import io
import math
import numpy as np
import scipy.io.wavfile as wavfile
import scipy.signal as signal
from typing import Dict, Any, Tuple


def _load_audio_data(audio_input: str | bytes) -> Tuple[int, np.ndarray]:
    """
    Loads audio from either a file path or raw bytes into a mono float32 array.
    """
    try:
        if isinstance(audio_input, bytes):
            sr, raw = wavfile.read(io.BytesIO(audio_input))
        elif isinstance(audio_input, str):
            sr, raw = wavfile.read(audio_input)
        else:
            raise ValueError(f"Unsupported audio input type: {type(audio_input)}")
    except Exception as e:
        raise ValueError(f"Unsupported audio format or corrupted WAV file: {e}")

    # Convert multi-channel to mono
    if raw.ndim > 1:
        raw = raw.mean(axis=1)

    # Normalize integer PCM or float to float32 in [-1.0, 1.0]
    if np.issubdtype(raw.dtype, np.integer):
        max_val = float(np.iinfo(raw.dtype).max)
        audio = (raw.astype(np.float32) / max_val)
    else:
        audio = raw.astype(np.float32)

    # Remove DC offset
    audio = audio - np.mean(audio)
    peak = np.max(np.abs(audio))
    if peak > 0:
        audio = audio / peak

    return int(sr), audio


def _compute_pitch_jitter(audio: np.ndarray, sr: int, frame_len_ms: float = 40.0, hop_ms: float = 20.0) -> Tuple[float, float]:
    """
    Computes pitch (F0) contour via normalized autocorrelation and returns
    (mean_f0, jitter_pct). Synthetic TTS often exhibits unnaturally flat pitch (jitter < 0.5%)
    or metallic glitch spikes (> 6.0%).
    """
    frame_len = int(sr * (frame_len_ms / 1000.0))
    hop_len = int(sr * (hop_ms / 1000.0))
    if len(audio) < frame_len:
        return 0.0, 0.0

    min_period = int(sr / 400.0)  # max f0 = 400 Hz
    max_period = int(sr / 60.0)   # min f0 = 60 Hz

    f0_values = []
    for start in range(0, len(audio) - frame_len, hop_len):
        frame = audio[start:start + frame_len] * np.hamming(frame_len)
        if np.std(frame) < 1e-4:
            continue
        corr = np.correlate(frame, frame, mode='full')
        corr = corr[len(corr) // 2:]
        if len(corr) <= max_period:
            continue
        valid_corr = corr[min_period:max_period]
        if len(valid_corr) == 0:
            continue
        best_lag = min_period + np.argmax(valid_corr)
        peak_val = valid_corr[best_lag - min_period]
        if peak_val > 0.3 * corr[0]:
            f0 = sr / float(best_lag)
            f0_values.append(f0)

    if len(f0_values) < 5:
        return 0.0, 0.0

    f0_arr = np.array(f0_values)
    mean_f0 = float(np.mean(f0_arr))
    # Jitter relative: mean absolute difference between consecutive pitch periods / mean period
    periods = 1.0 / (f0_arr + 1e-8)
    jitter = float(np.mean(np.abs(np.diff(periods))) / (np.mean(periods) + 1e-8)) * 100.0
    return round(mean_f0, 1), round(jitter, 2)


def extract_audio_forensic_features(audio_input: str | bytes) -> Dict[str, Any]:
    """
    Extracts deepfake forensic acoustic & spectral indicators from audio input.
    """
    sr, audio = _load_audio_data(audio_input)
    duration_sec = round(len(audio) / float(sr), 3)

    if len(audio) < 256:
        raise ValueError("Audio clip is too short for forensic analysis (minimum 256 samples required)")

    # 1. Zero-Crossing Rate
    zcr = float(np.mean(np.abs(np.diff(np.signbit(audio)))))

    # 2. Spectrogram & Spectral Moments
    nperseg = min(1024, len(audio))
    noverlap = nperseg // 2
    freqs, times, Sxx = signal.spectrogram(audio, fs=sr, nperseg=nperseg, noverlap=noverlap)
    power = np.abs(Sxx)
    total_power_per_frame = power.sum(axis=0) + 1e-12

    # Spectral Centroid
    centroids = (freqs[:, None] * power).sum(axis=0) / total_power_per_frame
    mean_centroid = float(np.mean(centroids))

    # Spectral Rolloff (85% and 95%)
    cum_power = np.cumsum(power, axis=0) / total_power_per_frame[None, :]
    rolloff_85_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.85), 0, cum_power)
    rolloff_95_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.95), 0, cum_power)
    rolloff_85 = float(np.mean(freqs[np.clip(rolloff_85_idx, 0, len(freqs) - 1)]))
    rolloff_95 = float(np.mean(freqs[np.clip(rolloff_95_idx, 0, len(freqs) - 1)]))

    # Spectral Flux (frame-to-frame Euclidean distance)
    if power.shape[1] > 1:
        norm_power = power / total_power_per_frame[None, :]
        spectral_flux = float(np.mean(np.sqrt(np.sum(np.diff(norm_power, axis=1)**2, axis=0))))
    else:
        spectral_flux = 0.0

    # High-Frequency Energy Ratio (>4000 Hz and >8000 Hz)
    hf_mask_4k = freqs >= 4000
    hf_ratio_4k = float(np.sum(power[hf_mask_4k, :]) / (np.sum(power) + 1e-12))

    hf_mask_8k = freqs >= 8000
    hf_ratio_8k = float(np.sum(power[hf_mask_8k, :]) / (np.sum(power) + 1e-12)) if np.any(hf_mask_8k) else 0.0

    # 3. Neural Vocoder High-Frequency Cutoff Detection
    # Many generative TTS models (HiFi-GAN, WaveGlow) exhibit sharp cutoff cliffs near 8kHz or 11kHz
    max_nyquist = sr / 2.0
    has_steep_cutoff = bool(rolloff_95 < 0.65 * max_nyquist and hf_ratio_8k < 0.015 and max_nyquist >= 8000)

    # 4. Pitch & Jitter
    mean_f0, jitter_pct = _compute_pitch_jitter(audio, sr)

    # 5. Continuous Anomaly Score Formulation [0.0, 1.0]
    # Synthetic cues:
    # a. High-frequency steep cutoff (weight 0.35)
    # b. Pitch unnaturalness: jitter < 0.6% (flat robot) or > 5.5% (synthetic glitch) (weight 0.25)
    # c. Discontinuous spectral flux (> 0.40) (weight 0.20)
    # d. Spectral centroid abnormality relative to human range (weight 0.20)
    score_cutoff = 0.85 if has_steep_cutoff else 0.15

    score_pitch = 0.20
    if jitter_pct > 0.0:
        if jitter_pct < 0.65:
            score_pitch = 0.80  # Unnatural robotic invariance
        elif jitter_pct > 5.0:
            score_pitch = 0.75  # Phase discontinuity / glitch
        else:
            score_pitch = 0.20  # Natural human range

    score_flux = float(np.clip(spectral_flux / 0.60, 0.1, 0.9))

    score_centroid = 0.25
    if mean_centroid < 800 or mean_centroid > 3800:
        score_centroid = 0.75

    raw_anomaly = (
        0.35 * score_cutoff +
        0.25 * score_pitch +
        0.20 * score_flux +
        0.20 * score_centroid
    )
    anomaly_score = float(np.clip(raw_anomaly, 0.05, 0.95))

    return {
        "sample_rate": sr,
        "duration_sec": duration_sec,
        "zero_crossing_rate": round(zcr, 4),
        "spectral_centroid_hz": round(mean_centroid, 1),
        "spectral_rolloff_85_hz": round(rolloff_85, 1),
        "spectral_rolloff_95_hz": round(rolloff_95, 1),
        "spectral_flux": round(spectral_flux, 4),
        "high_freq_ratio_4k": round(hf_ratio_4k, 4),
        "high_freq_ratio_8k": round(hf_ratio_8k, 4),
        "high_freq_cutoff_detected": has_steep_cutoff,
        "mean_f0_hz": mean_f0,
        "pitch_jitter_pct": jitter_pct,
        "anomaly_score": round(anomaly_score, 4)
    }
