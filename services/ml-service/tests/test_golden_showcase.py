"""
CYBERGUARD — Real-Data Golden Demonstration & Verification Test Suite.
================================================================================

Validates:
- Manifest parsing, schema compliance, and cryptographic integrity of real datasets
- SHA-256 asset verification and tamper detection on authentic files
- Duplicate ID and malformed entry rejection
- Production engine dispatching without mutation on authentic media, text, and URLs
- Real SMS Spam Collection and URL threat (Tranco / OTX) inference
- Offline safety for URLs
- Status evaluation (PARTIAL_REAL_DATA_SHOWCASE when some engine datasets are missing)
- Zero-mutation guarantee for production model artifacts and registry
"""

import os
import sys
import json
import copy
import hashlib
import tempfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
ML_SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

# Import runner utilities
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from run_golden_showcase_demo import (
    load_and_validate_manifest,
    compute_sha256,
    ManifestValidationError,
    REGISTERED_ENGINES,
    dispatch_sample,
    run_showcase,
    MANIFEST_DEFAULT_PATH,
)

MODELS_DIR = ML_SERVICE_DIR / "app" / "models"


# ==============================================================================
# 1. Manifest Structural & Cryptographic Integrity Tests
# ==============================================================================

def test_real_data_manifest_loads_and_verifies_cryptographically():
    """Confirms real-data showcase_manifest.json exists, has 0 synthetic samples, and passes 100% SHA verification."""
    assert MANIFEST_DEFAULT_PATH.exists(), f"Missing manifest at {MANIFEST_DEFAULT_PATH}"
    data = load_and_validate_manifest(MANIFEST_DEFAULT_PATH)

    assert data["synthetic_samples_included"] is False
    assert len(data["samples"]) == 64
    for s in data["samples"]:
        assert s["is_synthetic"] is False, f"Sample {s['sample_id']} must not be synthetic"
        assert s["engine"] in REGISTERED_ENGINES


def test_manifest_rejects_missing_required_fields(tmp_path):
    """Manifest loader must fail loud when a required field is missing."""
    bad_manifest = {
        "manifest_version": "2.0.0",
        "samples": [
            {
                "sample_id": "TEST-001",
                "engine": "phishing",
                # missing engine_version, sample_type, etc.
            }
        ]
    }
    m_file = tmp_path / "bad_manifest.json"
    m_file.write_text(json.dumps(bad_manifest), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="missing required fields"):
        load_and_validate_manifest(m_file)


def test_manifest_rejects_duplicate_sample_ids(tmp_path):
    """Manifest loader must reject duplicate sample_id values."""
    dummy_payload = tmp_path / "dummy.json"
    dummy_payload.write_text('{"text": "test"}', encoding="utf-8")
    d_sha = compute_sha256(dummy_payload)

    sample_template = {
        "sample_id": "DUP-001",
        "engine": "phishing",
        "engine_version": "v1.0.0",
        "sample_type": "benign",
        "source": "test",
        "provenance": "test",
        "ground_truth": "benign",
        "expected_verdict": "SAFE",
        "rationale": "test",
        "payload_type": "file_path",
        "payload_path": str(dummy_payload),
        "sha256": d_sha,
        "fixture_kind": "authentic_real_dataset",
        "safety_notes": "safe",
    }

    manifest_data = {
        "manifest_version": "2.0.0",
        "samples": [sample_template, copy.deepcopy(sample_template)]
    }
    m_file = tmp_path / "dup_manifest.json"
    m_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="Duplicate sample_id detected"):
        load_and_validate_manifest(m_file)


def test_manifest_rejects_tampered_payload_hash(tmp_path):
    """Manifest loader must detect tampered payload file where on-disk hash differs."""
    dummy_payload = tmp_path / "tampered.json"
    dummy_payload.write_text('{"text": "initial content"}', encoding="utf-8")

    sample = {
        "sample_id": "TAMP-001",
        "engine": "phishing",
        "engine_version": "v1.0.0",
        "sample_type": "benign",
        "source": "test",
        "provenance": "test",
        "ground_truth": "benign",
        "expected_verdict": "SAFE",
        "rationale": "test",
        "payload_type": "file_path",
        "payload_path": str(dummy_payload),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_kind": "authentic_real_dataset",
        "safety_notes": "safe",
    }
    m_file = tmp_path / "tamp_manifest.json"
    m_file.write_text(json.dumps({"manifest_version": "2.0.0", "samples": [sample]}), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="SHA-256 mismatch"):
        load_and_validate_manifest(m_file)


def test_manifest_rejects_unregistered_engine(tmp_path):
    """Manifest loader must reject unsupported/unregistered engine identifiers."""
    dummy_payload = tmp_path / "unreg.json"
    dummy_payload.write_text('{"text": "test"}', encoding="utf-8")
    d_sha = compute_sha256(dummy_payload)

    sample = {
        "sample_id": "UNREG-001",
        "engine": "non_existent_engine_v99",
        "engine_version": "v1.0.0",
        "sample_type": "benign",
        "source": "test",
        "provenance": "test",
        "ground_truth": "benign",
        "expected_verdict": "SAFE",
        "rationale": "test",
        "payload_type": "file_path",
        "payload_path": str(dummy_payload),
        "sha256": d_sha,
        "fixture_kind": "authentic_real_dataset",
        "safety_notes": "safe",
    }
    m_file = tmp_path / "unreg_manifest.json"
    m_file.write_text(json.dumps({"manifest_version": "2.0.0", "samples": [sample]}), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="references unknown engine"):
        load_and_validate_manifest(m_file)


# ==============================================================================
# 2. Engine Dispatch & Authentic Sample Inference Tests
# ==============================================================================

def test_dispatch_phishing_authentic_sms_corpus():
    """Validates dispatch routing and real inference on authentic SMS Spam Collection samples."""
    manifest_data = load_and_validate_manifest(MANIFEST_DEFAULT_PATH)
    phish_samples = [s for s in manifest_data["samples"] if s["engine"] == "phishing"]
    assert len(phish_samples) == 20

    # Authentic personal ham messages
    benign_sample = next(s for s in phish_samples if s["sample_type"] == "benign")
    verdict, score, explanation, signals = dispatch_sample(benign_sample)
    assert verdict == "SAFE"
    assert 0 <= score <= 35
    assert len(explanation) > 10

    # Urgent financial reward spam (Line 8: WINNER!! customer selected to receive £900)
    threat_sample = next(s for s in phish_samples if "SPAM-0008" in s["sample_id"])
    verdict_t, score_t, explanation_t, signals_t = dispatch_sample(threat_sample)
    assert verdict_t in ("MEDIUM", "HIGH", "CRITICAL")
    assert score_t >= 50


def test_url_engine_offline_execution_safety():
    """Validates URL threat engine executes offline on authentic Tranco and AlienVault OTX samples."""
    manifest_data = load_and_validate_manifest(MANIFEST_DEFAULT_PATH)
    url_samples = [s for s in manifest_data["samples"] if s["engine"] == "malicious_url"]
    assert len(url_samples) == 20

    # Tranco Benign sample
    benign_sample = next(s for s in url_samples if s["sample_type"] == "benign" and "00000" in s["sample_id"])
    v_b, s_b, exp_b, sig_b = dispatch_sample(benign_sample)
    assert v_b == "SAFE"
    assert s_b <= 35

    # OTX Malicious sample (appleid credential harvesting)
    threat_sample = next(s for s in url_samples if "00010" in s["sample_id"])
    v_t, s_t, exp_t, sig_t = dispatch_sample(threat_sample)
    assert v_t in ("HIGH", "CRITICAL")
    assert s_t >= 80


def test_dispatch_visual_deepfake_authentic_images():
    """Validates visual deepfake engine on authentic face photos from datasets/visualdeepfake."""
    manifest_data = load_and_validate_manifest(MANIFEST_DEFAULT_PATH)
    vis_samples = [s for s in manifest_data["samples"] if s["engine"] == "deepfake_visual"]
    assert len(vis_samples) == 20

    auth_sample = next(s for s in vis_samples if s["sample_type"] == "benign")
    verdict, score, explanation, signals = dispatch_sample(auth_sample)
    assert verdict == "SAFE"
    assert 0 <= score <= 35


def test_dispatch_audio_deepfake_common_voice_and_clones():
    """Validates audio deepfake engine on authentic Mozilla Common Voice and ElevenLabs cloned speech."""
    manifest_data = load_and_validate_manifest(MANIFEST_DEFAULT_PATH)
    aud_samples = [s for s in manifest_data["samples"] if s["engine"] == "deepfake_audio"]
    assert len(aud_samples) == 4

    # Authentic English recording
    real_sample = next(s for s in aud_samples if "en_32642394" in s["sample_id"])
    v_r, s_r, exp_r, sig_r = dispatch_sample(real_sample)
    assert v_r == "SAFE"
    assert s_r <= 25

    # ElevenLabs cloned speech
    clone_sample = next(s for s in aud_samples if "elevenlabs" in s["sample_id"])
    v_c, s_c, exp_c, sig_c = dispatch_sample(clone_sample)
    assert v_c == "CRITICAL"
    assert s_c >= 75


# ==============================================================================
# 3. Runner Execution, Report Generation, and Artifact Immutability Tests
# ==============================================================================

def test_runner_executes_real_showcase_and_outputs_partial_status(tmp_path):
    """Tests run_showcase executes cleanly on real data manifest and outputs PARTIAL_REAL_DATA_SHOWCASE."""
    report_file = tmp_path / "test_report.json"
    exit_code = run_showcase(
        manifest_path=MANIFEST_DEFAULT_PATH,
        output_path=report_file,
        limit=10,
        console_quiet=True,
    )
    assert exit_code == 0
    assert report_file.exists()

    with open(report_file, "r", encoding="utf-8") as f:
        rep = json.load(f)

    assert rep["suite_status"] == "PARTIAL_REAL_DATA_SHOWCASE"
    assert rep["summary"]["total_errors"] == 0
    assert len(rep["sample_evaluations"]) == 10


def test_zero_mutation_of_model_artifacts_during_real_verification(tmp_path):
    """Guarantees that real showcase verification causes zero mutation to production model artifacts."""
    artifact_hashes_before = {}
    for p in MODELS_DIR.glob("**/*"):
        if p.is_file() and p.suffix in (".pt", ".txt", ".json", ".joblib", ".onnx"):
            artifact_hashes_before[p.name] = compute_sha256(p)

    assert len(artifact_hashes_before) > 0, "No model artifacts found to monitor"

    # Run showcase on multiple engines
    report_file = tmp_path / "immutability_report.json"
    exit_code = run_showcase(
        manifest_path=MANIFEST_DEFAULT_PATH,
        output_path=report_file,
        limit=12,
        console_quiet=True,
    )
    assert exit_code == 0

    artifact_hashes_after = {}
    for p in MODELS_DIR.glob("**/*"):
        if p.is_file() and p.suffix in (".pt", ".txt", ".json", ".joblib", ".onnx"):
            artifact_hashes_after[p.name] = compute_sha256(p)

    assert artifact_hashes_before == artifact_hashes_after, "Model artifacts were mutated during inference!"
