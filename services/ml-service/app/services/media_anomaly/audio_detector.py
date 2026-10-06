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
import scipy.fft as fft
from typing import Dict, Any, Tuple


TARGET_SAMPLE_RATE = 16000

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


def _load_audio_data(audio_input: str | bytes) -> Tuple[int, np.ndarray]:
    """
    Standardized CYBERGUARD Audio Preprocessing Pipeline.
    Loads audio from either a file path or raw bytes, converts multi-channel to mono,
    resamples to a common 16 kHz standard using polyphase anti-aliasing filtering,
    removes DC offset, and peak-normalizes to [-1.0, 1.0].
    Guarantees deterministic output and eliminates sample-rate / channel-count leakage.
    """
    try:
        try:
            import soundfile as sf
            if isinstance(audio_input, bytes):
                raw, sr = sf.read(io.BytesIO(audio_input), dtype="float32")
            elif isinstance(audio_input, str):
                raw, sr = sf.read(audio_input, dtype="float32")
            else:
                raise ValueError(f"Unsupported audio input type: {type(audio_input)}")
        except Exception:
            if isinstance(audio_input, bytes):
                sr, raw = wavfile.read(io.BytesIO(audio_input))
            elif isinstance(audio_input, str):
                sr, raw = wavfile.read(audio_input)
            else:
                raise ValueError(f"Unsupported audio input type: {type(audio_input)}")
    except Exception as e:
        raise ValueError(f"Unsupported audio format or corrupted file: {e}")

    # 1. Convert multi-channel to mono
    if raw.ndim > 1:
        raw = raw.mean(axis=1)

    # 2. Normalize integer PCM or float to float32 in [-1.0, 1.0]
    if np.issubdtype(raw.dtype, np.integer):
        max_val = float(np.iinfo(raw.dtype).max)
        audio = (raw.astype(np.float32) / max_val)
    else:
        audio = raw.astype(np.float32)

    # 3. Standardize sample rate to 16,000 Hz via polyphase resampling
    sr = int(sr)
    if sr != TARGET_SAMPLE_RATE and len(audio) > 0:
        gcd = math.gcd(sr, TARGET_SAMPLE_RATE)
        up = TARGET_SAMPLE_RATE // gcd
        down = sr // gcd
        audio = signal.resample_poly(audio, up, down).astype(np.float32)
        sr = TARGET_SAMPLE_RATE

    # 4. Remove DC offset
    if len(audio) > 0:
        audio = audio - float(np.mean(audio))

    # 5. Peak normalization
    peak = float(np.max(np.abs(audio))) if len(audio) > 0 else 0.0
    if peak > 1e-6:
        audio = audio / peak

    return sr, audio


def standardize_audio(audio_input: str | bytes) -> Tuple[int, np.ndarray]:
    """
    Standardizes audio input to 16 kHz mono float32 normalized in [-1.0, 1.0].
    Public interface for validation, testing, and production parity checks.
    """
    return _load_audio_data(audio_input)



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
    All inputs are pre-normalized to 16 kHz mono to prevent sampling rate / encoding leakage.
    Features are strictly computed on normalized acoustic properties.
    Generates the complete 28-feature representation required for Audio V2 inference.
    """
    sr, audio = _load_audio_data(audio_input)
    duration_sec = round(len(audio) / float(sr), 3)

    if len(audio) < 256:
        raise ValueError("Audio clip is too short for forensic analysis (minimum 256 samples required)")

    # 1. Zero-Crossing Rate
    zcr = float(np.mean(np.abs(np.diff(np.signbit(audio)))))
    zcr = 0.0 if math.isnan(zcr) or math.isinf(zcr) else zcr

    # 2. Spectrogram & Spectral Moments
    nperseg = min(1024, len(audio))
    noverlap = nperseg // 2
    freqs, times, Sxx = signal.spectrogram(audio, fs=sr, nperseg=nperseg, noverlap=noverlap)
    power = np.abs(Sxx)
    total_power_per_frame = power.sum(axis=0) + 1e-12
    total_power = float(power.sum()) + 1e-12

    # Spectral Centroid
    centroids = (freqs[:, None] * power).sum(axis=0) / total_power_per_frame
    mean_centroid = float(np.mean(centroids))
    mean_centroid = 0.0 if math.isnan(mean_centroid) or math.isinf(mean_centroid) else mean_centroid

    # Spectral Rolloff (85% and 95%)
    cum_power = np.cumsum(power, axis=0) / total_power_per_frame[None, :]
    rolloff_85_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.85), 0, cum_power)
    rolloff_95_idx = np.apply_along_axis(lambda col: np.searchsorted(col, 0.95), 0, cum_power)
    rolloff_85 = float(np.mean(freqs[np.clip(rolloff_85_idx, 0, len(freqs) - 1)]))
    rolloff_95 = float(np.mean(freqs[np.clip(rolloff_95_idx, 0, len(freqs) - 1)]))
    rolloff_85 = 0.0 if math.isnan(rolloff_85) or math.isinf(rolloff_85) else rolloff_85
    rolloff_95 = 0.0 if math.isnan(rolloff_95) or math.isinf(rolloff_95) else rolloff_95

    # Spectral Flux (frame-to-frame Euclidean distance)
    if power.shape[1] > 1:
        norm_power = power / total_power_per_frame[None, :]
        spectral_flux = float(np.mean(np.sqrt(np.sum(np.diff(norm_power, axis=1)**2, axis=0))))
    else:
        spectral_flux = 0.0
    spectral_flux = 0.0 if math.isnan(spectral_flux) or math.isinf(spectral_flux) else spectral_flux

    # Normalized Sub-band Ratios (strictly within valid 16 kHz band: [0, 8000 Hz])
    # 4000 Hz - 7600 Hz sub-band: assesses harmonic preservation vs band-limited drop-off
    mask_4k_8k = (freqs >= 4000) & (freqs <= 7600)
    subband_ratio_4k_to_8k = float(np.sum(power[mask_4k_8k, :]) / total_power)
    subband_ratio_4k_to_8k = 0.0 if math.isnan(subband_ratio_4k_to_8k) or math.isinf(subband_ratio_4k_to_8k) else subband_ratio_4k_to_8k

    # 2000 Hz - 4000 Hz sub-band: mid-formant speech ratio
    mask_2k_4k = (freqs >= 2000) & (freqs < 4000)
    subband_ratio_2k_to_4k = float(np.sum(power[mask_2k_4k, :]) / total_power)
    subband_ratio_2k_to_4k = 0.0 if math.isnan(subband_ratio_2k_to_4k) or math.isinf(subband_ratio_2k_to_4k) else subband_ratio_2k_to_4k

    # High frequency ratio >= 4000 Hz
    hf_mask_4k = freqs >= 4000
    hf_ratio_4k = float(np.sum(power[hf_mask_4k, :]) / total_power)
    hf_ratio_4k = 0.0 if math.isnan(hf_ratio_4k) or math.isinf(hf_ratio_4k) else hf_ratio_4k

    # Spectral Flatness (Wiener Entropy: geometric mean / arithmetic mean of power spectrum)
    # Neural vocoders and synthetic speech exhibit distinct tonality / flatness smearing
    p_mean_spectrum = np.mean(power, axis=1) + 1e-12
    log_geom = float(np.mean(np.log(p_mean_spectrum)))
    geom_mean = float(np.exp(np.clip(log_geom, -50.0, 50.0)))
    arith_mean = float(np.mean(p_mean_spectrum))
    spectral_flatness = float(geom_mean / (arith_mean + 1e-12))
    spectral_flatness = float(np.clip(spectral_flatness, 0.0, 1.0))
    if math.isnan(spectral_flatness) or math.isinf(spectral_flatness):
        spectral_flatness = 0.0

    # 3. Neural Vocoder Cutoff Detection (at 16 kHz standardized sample rate)
    # Many generative TTS models exhibit unnatural cutoffs below 4.5 kHz or severely suppressed 4-8 kHz energy
    has_steep_cutoff = bool(rolloff_95 < 4600.0 and subband_ratio_4k_to_8k < 0.008)

    # 4. Pitch & Jitter
    mean_f0, jitter_pct = _compute_pitch_jitter(audio, sr)
    mean_f0 = 0.0 if math.isnan(mean_f0) or math.isinf(mean_f0) else mean_f0
    jitter_pct = 0.0 if math.isnan(jitter_pct) or math.isinf(jitter_pct) else jitter_pct

    # 5. Continuous Anomaly Score Formulation [0.0, 1.0]
    score_cutoff = 0.85 if has_steep_cutoff else 0.15

    score_pitch = 0.20
    if jitter_pct > 0.0:
        if jitter_pct < 0.65:
            score_pitch = 0.80  # Robotic invariance
        elif jitter_pct > 5.0:
            score_pitch = 0.75  # Phase discontinuity / glitch
        else:
            score_pitch = 0.20  # Natural human range

    score_flux = float(np.clip(spectral_flux / 0.60, 0.1, 0.9))

    score_centroid = 0.25
    if mean_centroid < 800 or mean_centroid > 3800:
        score_centroid = 0.75

    score_flatness = float(np.clip(abs(spectral_flatness - 0.12) / 0.15, 0.1, 0.9))

    raw_anomaly = (
        0.30 * score_cutoff +
        0.25 * score_pitch +
        0.15 * score_flux +
        0.15 * score_centroid +
        0.15 * score_flatness
    )
    anomaly_score = float(np.clip(raw_anomaly, 0.05, 0.95))

    # 6. Additional 15 Features for Audio V2 (Bandwidth, Spectral Contrast, 10 MFCC Means)
    diff_freqs = (freqs[:, None] - mean_centroid) ** 2
    bandwidth_per_frame = np.sqrt(np.sum(diff_freqs * power, axis=0) / total_power_per_frame)
    spectral_bandwidth_hz = float(np.mean(bandwidth_per_frame))
    spectral_bandwidth_hz = 0.0 if math.isnan(spectral_bandwidth_hz) or math.isinf(spectral_bandwidth_hz) else spectral_bandwidth_hz

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
        c = 0.0 if math.isnan(c) or math.isinf(c) else c
        contrast_vals.append(c)

    fbank = get_mel_filterbank(sr=sr, n_fft=nperseg, n_mels=26, fmin=20.0, fmax=8000.0)
    mel_energy = np.dot(fbank, power)
    log_mel = np.log(mel_energy + 1e-10)
    dct_coeffs = fft.dct(log_mel, type=2, axis=0, norm="ortho")
    mfcc_means = []
    for i in range(1, 11):
        m = float(np.mean(dct_coeffs[i, :]))
        m = 0.0 if math.isnan(m) or math.isinf(m) else m
        mfcc_means.append(m)

    return {
        "sample_rate": sr,
        "duration_sec": duration_sec,
        # Base 13 features
        "zero_crossing_rate": round(zcr, 4),
        "spectral_centroid_hz": round(mean_centroid, 1),
        "spectral_rolloff_85_hz": round(rolloff_85, 1),
        "spectral_rolloff_95_hz": round(rolloff_95, 1),
        "spectral_flux": round(spectral_flux, 4),
        "subband_ratio_4k_to_8k": round(subband_ratio_4k_to_8k, 4),
        "subband_ratio_2k_to_4k": round(subband_ratio_2k_to_4k, 4),
        "high_freq_ratio_4k": round(hf_ratio_4k, 4),
        "spectral_flatness": round(spectral_flatness, 4),
        "high_freq_cutoff_detected": has_steep_cutoff,
        "mean_f0_hz": mean_f0,
        "pitch_jitter_pct": jitter_pct,
        "anomaly_score": round(anomaly_score, 4),
        # Additional 15 features
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

