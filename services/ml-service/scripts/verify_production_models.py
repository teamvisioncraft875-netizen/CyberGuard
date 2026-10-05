#!/usr/bin/env python3
"""
CYBERGUARD Production Model Deployment Verification Script.
Validates existence, SHA-256 checksum integrity, and runtime loadability
for all production threat detection models against app/models/model_registry.json.
Exits 0 on total integrity verification; exits 1 on any failure.
"""

import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple

# Workspace and ML service root paths
ML_SERVICE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = ML_SERVICE_DIR.parent.parent

REGISTRY_PATH = ML_SERVICE_DIR / "app" / "models" / "model_registry.json"


def sha256_file(filepath: Path) -> str:
    """Calculates SHA-256 digest of a binary or text file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def test_model_load(engine_key: str, filepath: Path) -> Tuple[bool, str]:
    """Tests runtime model loading using appropriate framework loader."""
    try:
        if engine_key in ("phishing", "malicious_url", "deepfake_audio"):
            import joblib
            obj = joblib.load(filepath)
            return True, f"Loaded ({type(obj).__name__})"
        elif engine_key == "malware":
            import lightgbm as lgb
            booster = lgb.Booster(model_file=str(filepath))
            return True, f"Loaded Booster ({booster.num_trees()} trees)"
        elif engine_key == "deepfake_visual":
            import torch
            from app.services.media_anomaly.image_detector import AttentionPoolingVisualDetector
            model = AttentionPoolingVisualDetector(in_features=1024)
            weights = torch.load(filepath, map_location="cpu", weights_only=True)
            model.load_state_dict(weights)
            model.eval()
            return True, f"Loaded AttentionPoolingVisualDetector ({len(weights)} weight tensors)"
        else:
            return False, f"Unknown engine type: {engine_key}"
    except Exception as exc:
        return False, f"Load failure: {exc}"


def main() -> int:
    # Ensure app directory is importable
    if str(ML_SERVICE_DIR) not in sys.path:
        sys.path.insert(0, str(ML_SERVICE_DIR))

    print("=" * 80)
    print("CYBERGUARD — PRODUCTION MODEL INTEGRITY & LOADABILITY AUDIT")
    print(f"Registry: {REGISTRY_PATH}")
    print("=" * 80)

    if not REGISTRY_PATH.exists():
        print(f"CRITICAL ERROR: Model registry not found at {REGISTRY_PATH}")
        return 1

    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        registry_data = json.load(f)

    models_dict: Dict[str, Any] = registry_data.get("models", {})
    if not models_dict:
        print("CRITICAL ERROR: No models defined in registry.")
        return 1

    all_passed = True
    results = []

    for engine_key, info in models_dict.items():
        name = info.get("engine_name", engine_key)
        version = info.get("model_version", "unknown")
        rel_path = info.get("artifact_path", "")
        expected_sha = info.get("artifact_sha256", "")

        # Resolve artifact path relative to workspace
        artifact_path = WORKSPACE_DIR / rel_path
        if not artifact_path.exists():
            # Try relative to ML service dir
            artifact_path = ML_SERVICE_DIR / rel_path.replace("services/ml-service/", "")

        exists = artifact_path.exists()
        size_bytes = artifact_path.stat().st_size if exists else 0
        actual_sha = sha256_file(artifact_path) if exists else "MISSING"

        hash_matches = (actual_sha == expected_sha)
        if not hash_matches or not exists:
            all_passed = False

        # Test model loading
        load_success, load_msg = test_model_load(engine_key, artifact_path) if exists else (False, "File missing")
        if not load_success:
            all_passed = False

        results.append({
            "engine": name,
            "version": version,
            "path": rel_path,
            "size": size_bytes,
            "actual_sha": actual_sha,
            "expected_sha": expected_sha,
            "hash_status": "MATCH" if hash_matches else "MISMATCH",
            "load_status": "SUCCESS" if load_success else "FAILED",
            "load_details": load_msg
        })

    # Print summary report
    print("\nVERIFICATION REPORT:")
    print("-" * 80)
    for r in results:
        print(f"Engine:       {r['engine']}")
        print(f"Version:      {r['version']}")
        print(f"Path:         {r['path']}")
        print(f"Size:         {r['size']:,} bytes ({r['size'] / (1024*1024):.2f} MB)")
        print(f"Actual SHA:   {r['actual_sha']}")
        print(f"Expected SHA: {r['expected_sha']}")
        print(f"Hash Status:  {r['hash_status']}")
        print(f"Load Status:  {r['load_status']} - {r['load_details']}")
        print("-" * 80)

    if all_passed:
        print("\nALL 5 PRODUCTION MODEL ARTIFACTS VERIFIED: INTEGRITY & LOADABILITY PASS.")
        return 0
    else:
        print("\nINTEGRITY AUDIT FAILED: ONE OR MORE MODELS FAILED CHECKSUM OR LOAD TESTS.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
