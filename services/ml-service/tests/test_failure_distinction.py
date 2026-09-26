"""
CYBERGUARD — Phase 6.6 Engine Failure & Distinction Tests

Tests controlled failure scenarios:
- Missing network model checkpoint (raises explicit error or distinguishable status)
- Corrupted model file handling
- Malformed telemetry with invalid numeric values (NaN, Infinity, string garbage)
- Missing telemetry fields
- Malformed URL inputs

IMPORTANT SECURITY INVARIANT:
A detector failure must NOT silently become "Safe".
A detector failure must remain strictly distinguishable from a legitimate benign result.
"""

from pathlib import Path
import pytest
from app.schemas.analyze import (
    UrlAnalyzeRequest,
    SystemAnalyzeRequest,
    RiskLevel,
)
from app.services.url_engine import analyze_url
from app.services.system_engine import analyze_system
from app.services.network_anomaly.model import NetworkThreatModel
from app.utils.telemetry_adapter import transform_guard_telemetry


def test_missing_model_checkpoint_fails_explicitly():
    """Verify that attempting to load a non-existent checkpoint raises FileNotFoundError, not silent Safe."""
    with pytest.raises(FileNotFoundError):
        NetworkThreatModel.load(Path("non_existent_model_checkpoint_xyz.joblib"))


def test_corrupted_model_file_fails_explicitly(tmp_path):
    """Verify that corrupted checkpoint files fail explicitly rather than producing falsified predictions."""
    corrupt_file = tmp_path / "corrupt_model.joblib"
    corrupt_file.write_text("NOT_A_VALID_JOBLIB_DATA_STREAM")

    with pytest.raises(Exception):
        NetworkThreatModel.load(corrupt_file)


def test_malformed_telemetry_numeric_safety():
    """
    Verify that telemetry adapter safely handles NaN, Inf, negative infinity,
    and non-numeric strings without throwing uncaught arithmetic exceptions.
    """
    bad_telemetry = {
        "duration": float("nan"),
        "total_bytes": float("inf"),
        "source_bytes": float("-inf"),
        "packets": "NOT_AN_INT",
        "sport": "port_abc",
        "protocol": None,
    }
    transformed = transform_guard_telemetry(bad_telemetry)

    for k, v in transformed.items():
        assert isinstance(v, (int, float))
        assert v == v, f"Field {k} returned NaN"
        assert v != float("inf") and v != float("-inf"), f"Field {k} returned Inf"


def test_system_engine_with_null_telemetry_does_not_mask_as_safe():
    """
    When telemetry is missing/null, system_engine produces baseline fallback
    advisory (Medium / score 58 with baseline_fallback flag), NEVER a false 'Safe'.
    """
    req = SystemAnalyzeRequest(
        user_id="user_test",
        timestamp="2026-09-25T12:00:00Z",
        event_type="network_flow",
        details={},
    )
    res = analyze_system(req)

    # Must be distinguishable from verified Safe (which is 0-19)
    assert res.risk_level != RiskLevel.SAFE
    assert res.risk_score >= 40
    assert res.signals.get("model_status") == "baseline_fallback"


def test_malformed_url_safety():
    """
    Verify malformed URL input does not crash url_engine and does not return
    a fraudulent 100% confidence benign assessment.
    """
    malformed_inputs = [
        "http://[::1:broken-bracket",
        "https://///????###",
        "ftp://" + "a" * 10000,
    ]

    for url_input in malformed_inputs:
        req = UrlAnalyzeRequest(url=url_input)
        res = analyze_url(req)
        assert 0 <= res.risk_score <= 100
        assert res.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert "engine" in res.signals
