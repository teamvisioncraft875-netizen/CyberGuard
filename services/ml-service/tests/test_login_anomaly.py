"""
Unit and Integration Tests for CyberGuard Login Anomaly Detection Engine
Verifies normal behavior, injected threat detection, response contract conformance,
score bounds, signal attributions, and determinism.
"""

import pytest
from app.services.login_anomaly import (
    LoginAnomalyEngine,
    LoginEvent,
    FeatureExtractor,
    SyntheticTelemetryGenerator,
)
from app.schemas.login_anomaly import UnifiedAnomalyResult, LoginEventInput


@pytest.fixture(scope="module")
def engine():
    """Shared deterministic anomaly detection engine fitted on baseline."""
    return LoginAnomalyEngine(random_state=42, auto_bootstrap=True)


@pytest.fixture(scope="module")
def synthetic_data():
    """Deterministic synthetic test datasets."""
    gen = SyntheticTelemetryGenerator(random_state=42)
    normal = gen.generate_normal_events(n_samples=100)
    anomalous = gen.generate_anomalous_events(n_samples=40)
    return normal, anomalous


VALID_RISK_LEVELS = {"Safe", "Low", "Medium", "High", "Critical"}


def test_unified_response_contract(engine):
    """Verify that every prediction strictly conforms to CyberGuard's unified response contract."""
    test_event = {
        "login_hour": 14,
        "is_new_device": False,
        "is_new_location": False,
        "failed_attempts": 0,
        "impossible_travel": False,
    }

    result = engine.predict(test_event)

    # 1. Verify required keys exist
    assert "risk_level" in result
    assert "risk_score" in result
    assert "explanation" in result
    assert "recommended_action" in result
    assert "signals" in result

    # 2. Verify types and boundaries
    assert result["risk_level"] in VALID_RISK_LEVELS
    assert isinstance(result["risk_score"], int)
    assert 0 <= result["risk_score"] <= 100
    assert isinstance(result["explanation"], str) and len(result["explanation"]) > 10
    assert isinstance(result["recommended_action"], str) and len(result["recommended_action"]) > 5
    assert isinstance(result["signals"], list)

    # 3. Pydantic schema validation
    validated = UnifiedAnomalyResult(**result)
    assert validated.risk_score == result["risk_score"]


def test_normal_events_generally_benign(engine, synthetic_data):
    """Verify that normal daytime logins with familiar devices are classified as Safe or Low."""
    normal_events, _ = synthetic_data

    safe_or_low_count = 0
    scores = []

    for event in normal_events:
        res = engine.predict(event)
        scores.append(res["risk_score"])
        assert 0 <= res["risk_score"] <= 100
        assert res["risk_level"] in VALID_RISK_LEVELS

        if res["risk_level"] in ("Safe", "Low"):
            safe_or_low_count += 1

    # Normal events should overwhelmingly be Safe or Low (>= 90% benchmark)
    pass_rate = safe_or_low_count / len(normal_events)
    assert pass_rate >= 0.90, f"Expected >= 90% normal events to be Safe/Low, got {pass_rate:.1%}"


def test_injected_anomalous_events_detected(engine, synthetic_data):
    """Verify that injected attack patterns (brute force, ATO, impossible travel) trigger High or Critical."""
    _, anomalous_events = synthetic_data

    elevated_count = 0
    for event in anomalous_events:
        res = engine.predict(event)
        assert 0 <= res["risk_score"] <= 100
        assert res["risk_level"] in VALID_RISK_LEVELS

        if res["risk_level"] in ("High", "Critical"):
            elevated_count += 1

    # Anomalous events should trigger High or Critical at a high rate (>= 90%)
    detection_rate = elevated_count / len(anomalous_events)
    assert detection_rate >= 0.90, f"Expected >= 90% detection of anomalies, got {detection_rate:.1%}"


def test_credential_stuffing_detection(engine):
    """Verify detection of high consecutive failed login attempts."""
    brute_force_event = LoginEvent(
        login_hour=14,
        is_new_device=True,
        is_new_location=False,
        failed_attempts=8,
        impossible_travel=False,
    )

    res = engine.predict(brute_force_event)
    assert res["risk_level"] in ("High", "Critical")
    assert res["risk_score"] >= 75
    assert any(s["name"] == "failed_login_burst" for s in res["signals"])
    assert "failed login attempts" in res["explanation"].lower()


def test_impossible_travel_detection(engine):
    """Verify detection of impossible travel velocity anomaly (Account Takeover)."""
    ato_event = LoginEvent(
        login_hour=10,
        is_new_device=True,
        is_new_location=True,
        failed_attempts=1,
        impossible_travel=True,
    )

    res = engine.predict(ato_event)
    assert res["risk_level"] in ("High", "Critical")
    assert res["risk_score"] >= 80
    assert any(s["name"] == "impossible_travel_detected" for s in res["signals"])
    assert "impossible geographic travel" in res["explanation"].lower()


def test_signals_structure_and_weights(engine):
    """Verify signal array format and normalized weights."""
    compound_event = {
        "login_hour": 3,
        "is_new_device": True,
        "is_new_location": True,
        "failed_attempts": 5,
        "impossible_travel": True,
    }

    res = engine.predict(compound_event)
    signals = res["signals"]

    assert len(signals) >= 3
    for sig in signals:
        assert "name" in sig
        assert "weight" in sig
        assert isinstance(sig["name"], str)
        assert isinstance(sig["weight"], float)
        assert 0.0 <= sig["weight"] <= 1.0

    # Ensure signals are sorted descending by weight
    weights = [s["weight"] for s in signals]
    assert weights == sorted(weights, reverse=True)


def test_input_flexibility(engine):
    """Verify engine accepts LoginEvent, raw dict, or Pydantic LoginEventInput."""
    # 1. LoginEvent object
    ev1 = LoginEvent(login_hour=11, is_new_device=False)
    r1 = engine.predict(ev1)
    assert r1["risk_level"] in VALID_RISK_LEVELS

    # 2. Raw dict
    ev2 = {"login_hour": 11, "is_new_device": False}
    r2 = engine.predict(ev2)
    assert r2["risk_level"] in VALID_RISK_LEVELS

    # 3. Pydantic model
    ev3 = LoginEventInput(login_hour=11, is_new_device=False)
    r3 = engine.predict(ev3)
    assert r3["risk_level"] in VALID_RISK_LEVELS

    # Consistent predictions
    assert r1["risk_score"] == r2["risk_score"] == r3["risk_score"]


def test_timestamp_parsing(engine):
    """Verify ISO timestamp strings are parsed correctly for login_hour."""
    event_with_ts = {
        "timestamp": "2026-09-09T03:30:00Z",  # 3 AM
        "is_new_device": True,
        "failed_attempts": 2,
    }
    res = engine.predict(event_with_ts)
    # Off-hours signal should be present because 3 AM is nocturnal
    assert any(s["name"] == "off_hours_activity" for s in res["signals"])


def test_determinism(engine):
    """Verify repeated predictions for identical events yield identical outputs."""
    event = {
        "login_hour": 2,
        "is_new_device": True,
        "is_new_location": True,
        "failed_attempts": 4,
        "impossible_travel": False,
    }

    res1 = engine.predict(event)
    res2 = engine.predict(event)

    assert res1["risk_score"] == res2["risk_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert res1["explanation"] == res2["explanation"]
    assert res1["signals"] == res2["signals"]
