"""
CyberGuard ML Service - Login Anomaly Detection Feature Extraction
Extracts, validates, and normalizes behavioral telemetry features for Isolation Forest.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np


@dataclass
class LoginEvent:
    """Standard in-memory representation of a login telemetry event."""
    login_hour: Optional[int] = None
    is_new_device: bool = False
    is_new_location: bool = False
    failed_attempts: int = 0
    impossible_travel: bool = False
    user_id: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "login_hour": self.resolved_hour,
            "is_new_device": int(self.is_new_device),
            "is_new_location": int(self.is_new_location),
            "failed_attempts": int(self.failed_attempts),
            "impossible_travel": int(self.impossible_travel),
            "user_id": self.user_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @property
    def resolved_hour(self) -> int:
        """Resolve login hour from explicit integer or parse ISO timestamp."""
        if self.login_hour is not None:
            return max(0, min(23, int(self.login_hour)))
        if self.timestamp:
            try:
                # Handle ISO 8601 strings (e.g., '2026-09-09T08:15:30Z')
                cleaned = self.timestamp.replace("Z", "+00:00")
                dt = datetime.fromisoformat(cleaned)
                return dt.hour
            except Exception:
                pass
        # Default fallback to business hour if undetermined
        return 12


class FeatureExtractor:
    """
    Extracts numerical feature vectors from raw login event payloads.
    Guarantees deterministic feature ordering for model compatibility.
    """

    FEATURE_NAMES: List[str] = [
        "login_hour",
        "is_new_device",
        "is_new_location",
        "failed_attempts",
        "impossible_travel",
    ]

    @classmethod
    def parse_event(cls, raw_event: Union[LoginEvent, Dict[str, Any], Any]) -> LoginEvent:
        """Convert a raw dictionary, Pydantic model, or LoginEvent instance into a LoginEvent."""
        if isinstance(raw_event, LoginEvent):
            return raw_event

        if hasattr(raw_event, "model_dump"):
            # Pydantic v2
            data = raw_event.model_dump()
        elif hasattr(raw_event, "dict"):
            # Pydantic v1
            data = raw_event.dict()
        elif isinstance(raw_event, dict):
            data = raw_event
        else:
            raise ValueError(f"Unsupported event type: {type(raw_event)}")

        return LoginEvent(
            login_hour=data.get("login_hour"),
            is_new_device=bool(data.get("is_new_device", False) or data.get("device_is_new", False)),
            is_new_location=bool(data.get("is_new_location", False) or data.get("location_is_new", False)),
            failed_attempts=max(0, int(data.get("failed_attempts", 0))),
            impossible_travel=bool(data.get("impossible_travel", False)),
            user_id=data.get("user_id"),
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def extract_vector(cls, event: Union[LoginEvent, Dict[str, Any], Any]) -> np.ndarray:
        """
        Extract a 1D float array of shape (5,) for a single login event.
        [login_hour, is_new_device, is_new_location, failed_attempts, impossible_travel]
        """
        parsed = cls.parse_event(event)
        return np.array([
            float(parsed.resolved_hour),
            1.0 if parsed.is_new_device else 0.0,
            1.0 if parsed.is_new_location else 0.0,
            float(parsed.failed_attempts),
            1.0 if parsed.impossible_travel else 0.0,
        ], dtype=np.float64)

    @classmethod
    def extract_batch(cls, events: Sequence[Union[LoginEvent, Dict[str, Any], Any]]) -> np.ndarray:
        """
        Extract a 2D float array of shape (N, 5) for a sequence of login events.
        """
        if not events:
            return np.empty((0, len(cls.FEATURE_NAMES)), dtype=np.float64)
        vectors = [cls.extract_vector(e) for e in events]
        return np.vstack(vectors)
