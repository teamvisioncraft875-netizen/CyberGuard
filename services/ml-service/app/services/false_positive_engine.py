"""
CYBERGUARD False Positive Detection & Alert Scoring Engine V1.
Evaluates security alerts using a trained HistGradientBoosting model pipeline on real BETH host telemetry.

Outputs advisory false-positive scores, calibrated probabilities, and XAI explanations for SOC analysts.
Guaranteed non-destructive: never automatically suppresses, deletes, blocks, or closes alerts.
"""

import time
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import joblib

from app.schemas.false_positive import (
    FalsePositiveAnalysisRequest,
    FalsePositiveAnalysisResponse,
    FalsePositiveExplanation,
    FeatureExplanation,
    BatchFalsePositiveRequest,
    BatchFalsePositiveResponse,
)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
REGISTRY_PATH = MODELS_DIR / "model_registry.json"
MODEL_PATH = MODELS_DIR / "false_positive" / "false_positive_classifier_v1.0.0.joblib"
METADATA_PATH = MODELS_DIR / "false_positive" / "false_positive_metadata.json"


class FalsePositiveEngine:
    _instance: Optional["FalsePositiveEngine"] = None

    def __init__(self):
        self._model = None
        self._threshold = 0.75
        self._model_version = "1.0.0"
        self._expected_sha256 = None
        self._load_registry_metadata()
        self._load_model()

    @classmethod
    def get_instance(cls) -> "FalsePositiveEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_registry_metadata(self):
        try:
            if REGISTRY_PATH.exists():
                with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                    reg = json.load(f)
                    fp_entry = reg.get("models", {}).get("false_positive", {})
                    self._expected_sha256 = fp_entry.get("artifact_sha256")
                    self._threshold = float(fp_entry.get("operating_threshold", 0.75))
                    v = fp_entry.get("model_version", "1.0.0")
                    self._model_version = v.lstrip("v") if v else "1.0.0"
        except Exception as e:
            logger.warning(f"Could not parse registry metadata: {e}. Using defaults.")

    def _verify_artifact_sha(self, path: Path) -> bool:
        if not path.exists():
            return False
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        current_sha = hasher.hexdigest()
        if self._expected_sha256 and current_sha != self._expected_sha256:
            logger.error(f"SHA-256 mismatch for {path}: expected {self._expected_sha256}, got {current_sha}")
            return False
        return True

    def _load_model(self):
        # Strict security constraint: restrict model loading to MODELS_DIR
        resolved = MODEL_PATH.resolve()
        if not str(resolved).startswith(str(MODELS_DIR.resolve())):
            raise SecurityError(f"Model path traversal detected: {resolved}")

        if not self._verify_artifact_sha(MODEL_PATH):
            logger.warning(f"Artifact SHA verification failed or missing for {MODEL_PATH}")

        logger.info(f"Loading False Positive V1 model from {MODEL_PATH}...")
        self._model = joblib.load(MODEL_PATH)
        logger.info(f"False Positive V1 model loaded successfully. Threshold={self._threshold}")

    def extract_features(self, req: FalsePositiveAnalysisRequest) -> pd.DataFrame:
        """
        Extracts exactly the approved feature schema:
        event_name, process_name, user_id, is_root, args_num, return_value, is_failed_syscall, is_init_parent
        """
        u_id = float(req.user_id)
        is_root = 1 if u_id == 0 else 0
        args_n = float(req.args_num)
        ret_val = float(req.return_value)
        is_failed = 1 if ret_val < 0 else 0
        
        p_pid = req.parent_process_id if req.parent_process_id is not None else -1
        is_init = 1 if p_pid == 1 else 0

        p_name = req.process_name or "unknown"
        e_name = req.event_name or "unknown"

        return pd.DataFrame([{
            "event_name": str(e_name),
            "process_name": str(p_name),
            "user_id": u_id,
            "is_root": is_root,
            "args_num": args_n,
            "return_value": ret_val,
            "is_failed_syscall": is_failed,
            "is_init_parent": is_init
        }])

    def _generate_explanation(
        self, req: FalsePositiveAnalysisRequest, fp_prob: float, classification: str
    ) -> FalsePositiveExplanation:
        factors = []

        # Process factor
        if req.process_name.lower() in ["landscape-sysin", "sshd", "systemd", "cloud-id", "apt-config"]:
            factors.append(FeatureExplanation(
                feature_name="process_name",
                feature_value=req.process_name,
                contribution_direction="supports_false_positive",
                detail=f"Process '{req.process_name}' is a standard system daemon or maintenance routine frequently generating benign alerts."
            ))
        elif req.process_name.lower() in ["tsm", "w", "krane", "wget", "tar", "passwd"]:
            factors.append(FeatureExplanation(
                feature_name="process_name",
                feature_value=req.process_name,
                contribution_direction="supports_true_threat",
                detail=f"Process '{req.process_name}' is an interactive or administrative tool commonly leveraged during reconnaissance or lateral movement."
            ))

        # Root privilege factor
        if req.user_id == 0:
            factors.append(FeatureExplanation(
                feature_name="is_root",
                feature_value=True,
                contribution_direction="supports_true_threat" if classification == "likely_true_positive" else "supports_false_positive",
                detail="Syscall executed with UID 0 (root). Root privilege elevates scrutiny."
            ))

        # Return value / failed syscall factor
        if req.return_value < 0:
            factors.append(FeatureExplanation(
                feature_name="is_failed_syscall",
                feature_value=True,
                contribution_direction="supports_true_threat",
                detail=f"Syscall failed with error code {req.return_value}. Probing or permission denial observed."
            ))
        else:
            factors.append(FeatureExplanation(
                feature_name="return_value",
                feature_value=req.return_value,
                contribution_direction="supports_false_positive",
                detail=f"Syscall completed successfully (return code {req.return_value})."
            ))

        # Parent process factor
        if req.parent_process_id == 1:
            factors.append(FeatureExplanation(
                feature_name="is_init_parent",
                feature_value=True,
                contribution_direction="supports_false_positive",
                detail="Process spawned directly by init/systemd (PID 1), characteristic of background system services."
            ))

        if classification == "likely_false_positive":
            summary = (
                f"Alert assessed as LIKELY FALSE POSITIVE ({fp_prob*100:.1f}% probability >= {self._threshold*100:.0f}% threshold). "
                f"Behavior aligns with legitimate baseline system workload generated by '{req.process_name}'. "
                f"Advisory: Analysts may deprioritize after routine triage."
            )
        else:
            threat_prob = 1.0 - fp_prob
            summary = (
                f"Alert assessed as LIKELY GENUINE THREAT ({threat_prob*100:.1f}% threat confidence). "
                f"Behavior departs from routine maintenance baselines. "
                f"Advisory: Retain high triage priority for investigation."
            )

        return FalsePositiveExplanation(
            primary_factors=factors,
            summary=summary,
            model_version=self._model_version,
            operating_threshold=self._threshold
        )

    def analyze(self, req: FalsePositiveAnalysisRequest) -> FalsePositiveAnalysisResponse:
        t0 = time.perf_counter()

        if self._model is None:
            self._load_model()

        X = self.extract_features(req)
        # Pipeline predict_proba outputs [P(TP), P(FP)] where class 1 is FP
        probs = self._model.predict_proba(X)[0]
        # In our trained classifier, class 1 is False Positive (evil==0)
        fp_prob = float(probs[1])
        fp_score = round(fp_prob, 4)

        is_fp = fp_prob >= self._threshold
        classification = "likely_false_positive" if is_fp else "likely_true_positive"
        confidence = round(fp_prob if is_fp else (1.0 - fp_prob), 4)

        explanation = self._generate_explanation(req, fp_prob, classification)
        exec_ms = round((time.perf_counter() - t0) * 1000, 3)

        return FalsePositiveAnalysisResponse(
            alert_id=req.alert_id,
            false_positive_score=fp_score,
            false_positive_probability=round(fp_prob, 4),
            classification=classification,
            confidence=confidence,
            threshold=self._threshold,
            is_advisory_only=True,
            explanation=explanation,
            model_version=self._model_version,
            execution_time_ms=exec_ms
        )

    def analyze_batch(self, req: BatchFalsePositiveRequest) -> BatchFalsePositiveResponse:
        t0 = time.perf_counter()
        results = [self.analyze(a) for a in req.alerts]
        fp_count = sum(1 for r in results if r.classification == "likely_false_positive")
        tp_count = len(results) - fp_count
        mean_time = round(((time.perf_counter() - t0) * 1000) / max(len(results), 1), 3)

        return BatchFalsePositiveResponse(
            results=results,
            total_evaluated=len(results),
            likely_false_positive_count=fp_count,
            likely_true_positive_count=tp_count,
            mean_execution_time_ms=mean_time
        )


class SecurityError(Exception):
    pass
