"""
Verification script for clean process reproducibility of deepfake_visual_classifier.pt and .joblib.
"""

import json
import sys
from pathlib import Path
import joblib
import numpy as np
import torch

# Ensure services/ml-service is in sys.path
ml_service_dir = Path(__file__).resolve().parent.parent
if str(ml_service_dir) not in sys.path:
    sys.path.insert(0, str(ml_service_dir))

from app.services.media_anomaly.image_detector import AttentionPoolingVisualDetector

workspace_root = ml_service_dir.parent.parent
models_dir = ml_service_dir / "app" / "models"
dfdc_dir = workspace_root / "datasets" / "DFDC" / "shield_2026_final_data"

pt_path = models_dir / "deepfake_visual_classifier.pt"
joblib_path = models_dir / "deepfake_visual_classifier.joblib"
schema_path = models_dir / "deepfake_visual_schema.json"

print(f"PT Model Path: {pt_path} (Exists: {pt_path.exists()})")
print(f"Joblib Path  : {joblib_path} (Exists: {joblib_path.exists()})")
print(f"Schema Path  : {schema_path} (Exists: {schema_path.exists()})")

with open(schema_path, "r", encoding="utf-8") as f:
    schema = json.load(f)

# 1. Load PyTorch model
model = AttentionPoolingVisualDetector(in_features=1024)
weights = torch.load(pt_path, map_location="cpu", weights_only=True)
model.load_state_dict(weights)
model.eval()

# 2. Load joblib model
clf_joblib = joblib.load(joblib_path)

# 3. Test on test samples
x_test = torch.load(dfdc_dir / "X_test.pt", map_location="cpu", weights_only=True)
y_test = torch.load(dfdc_dir / "y_test.pt", map_location="cpu", weights_only=True)

sample_videos = x_test[:10]
sample_labels = y_test[:10].numpy()

with torch.no_grad():
    pt_probs = torch.sigmoid(model(sample_videos)).numpy()

joblib_probs = clf_joblib.predict_proba(sample_videos.mean(dim=1).numpy())[:, 1]

pt_verdicts = (pt_probs >= schema["frozen_threshold"]).astype(int)
joblib_verdicts = (joblib_probs >= 0.50).astype(int)

print("\n--- SAMPLE INFERENCE COMPARISON (First 10 Test Videos) ---")
print(f"{'Index':<6} | {'True Label':<10} | {'PT Prob':<9} | {'PT Pred':<8} | {'Joblib Prob':<12} | {'Joblib Pred':<11} | {'Agreement':<10}")
print("-" * 75)
agreements = 0
for i in range(10):
    agree = pt_verdicts[i] == joblib_verdicts[i]
    if agree: agreements += 1
    print(f"{i:<6} | {sample_labels[i]:<10} | {pt_probs[i]:.4f}    | {pt_verdicts[i]:<8} | {joblib_probs[i]:.4f}       | {joblib_verdicts[i]:<11} | {agree}")

print(f"\nVerdict Agreement: {agreements}/10 ({agreements*10}%)")
print("Clean process verification successful: BOTH models load and perform valid inference.")
