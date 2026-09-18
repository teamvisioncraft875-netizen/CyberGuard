"""
CyberGuard Login Anomaly Detection Package
Standalone behavioral telemetry anomaly detector for Phase 1 AI Workstream.
"""

from app.services.login_anomaly.engine import LoginAnomalyEngine
from app.services.login_anomaly.features import FeatureExtractor, LoginEvent
from app.services.login_anomaly.synthetic import SyntheticTelemetryGenerator

__all__ = [
    "LoginAnomalyEngine",
    "LoginEvent",
    "FeatureExtractor",
    "SyntheticTelemetryGenerator",
]
