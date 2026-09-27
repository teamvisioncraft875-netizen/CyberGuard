"""
CYBERGUARD — Cowrie Preprocessor & Session Reconstruction Tests (Phase A)

Tests streaming JSONL parsing, session reconstruction, feature extraction,
temporal cyclical encoding, credential privacy protection, and sensor-level splitting.
"""

import math
import pytest
import pandas as pd
import numpy as np
from pathlib import Path

from app.utils.cowrie_preprocessor import (
    CowriePreprocessor,
    calculate_shannon_entropy,
    parse_cowrie_line,
    reconstruct_sessions_from_events,
    extract_session_features,
    FEATURE_COLUMNS,
    METADATA_COLUMNS,
)


# ---------------------------------------------------------------------------
# Fixtures & Sample Events
# ---------------------------------------------------------------------------

SAMPLE_CONNECT_EVENT = {
    "eventid": "cowrie.session.connect",
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "dst_ip": "10.0.0.1",
    "dst_port": 2222,
    "session": "sess_001",
    "protocol": "ssh",
    "timestamp": "2024-10-23T14:30:00.000000Z",
}

SAMPLE_FAILED_LOGIN = {
    "eventid": "cowrie.login.failed",
    "username": "root",
    "password": "Password123!",
    "src_ip": "192.168.1.100",
    "session": "sess_001",
    "timestamp": "2024-10-23T14:30:02.000000Z",
}

SAMPLE_SUCCESS_LOGIN = {
    "eventid": "cowrie.login.success",
    "username": "admin",
    "password": "secretPassword",
    "src_ip": "192.168.1.100",
    "session": "sess_001",
    "timestamp": "2024-10-23T14:30:05.000000Z",
}

SAMPLE_CLOSED_EVENT = {
    "eventid": "cowrie.session.closed",
    "duration": 5.0,
    "src_ip": "192.168.1.100",
    "session": "sess_001",
    "timestamp": "2024-10-23T14:30:05.000000Z",
}


# ---------------------------------------------------------------------------
# Test 1: Valid Cowrie login event parsing
# ---------------------------------------------------------------------------
def test_valid_cowrie_login_event():
    """A valid failed-login record should parse correctly into standard fields."""
    line = '{"eventid": "cowrie.login.failed", "username": "admin", "password": "123", "src_ip": "1.2.3.4", "session": "s1", "timestamp": "2024-10-23T10:00:00Z"}'
    parsed, is_valid, err = parse_cowrie_line(line)

    assert is_valid is True
    assert err is None
    assert parsed["eventid"] == "cowrie.login.failed"
    assert parsed["username"] == "admin"
    assert parsed["src_ip"] == "1.2.3.4"
    assert parsed["session"] == "s1"
    assert parsed["timestamp"] == "2024-10-23T10:00:00Z"


# ---------------------------------------------------------------------------
# Test 2: Malformed JSON resilience
# ---------------------------------------------------------------------------
def test_malformed_json_resilience():
    """A malformed JSON line must not crash the preprocessor; it must flag error gracefully."""
    bad_line = '{"eventid": "cowrie.login.failed", "username": "admin", corrupt_json...'
    parsed, is_valid, err = parse_cowrie_line(bad_line)

    assert is_valid is False
    assert parsed is None
    assert err is not None


# ---------------------------------------------------------------------------
# Test 3: Missing optional fields
# ---------------------------------------------------------------------------
def test_missing_optional_fields():
    """Events missing optional fields (duration, username, password) must handle safely."""
    # Login event with missing password
    line = '{"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "session": "s1", "timestamp": "2024-10-23T10:00:00Z"}'
    parsed, is_valid, err = parse_cowrie_line(line)
    assert is_valid is True

    # Reconstruct single event session
    sessions = reconstruct_sessions_from_events([parsed], sensor_id="sensor_test")
    assert "s1" in sessions
    row = extract_session_features(sessions["s1"])

    assert row["failed_attempts_count"] == 1
    assert row["unique_usernames_count"] == 0
    assert row["password_entropy"] == 0.0
    assert not np.isnan(row["password_entropy"])


# ---------------------------------------------------------------------------
# Test 4: Zero elapsed time division safety
# ---------------------------------------------------------------------------
def test_zero_elapsed_time_division_safety():
    """Two events with identical timestamps (duration=0) must not produce inf or NaN."""
    ev1 = {
        "eventid": "cowrie.login.failed",
        "username": "u1",
        "password": "p1",
        "src_ip": "1.1.1.1",
        "session": "sess_zero",
        "timestamp": "2024-10-23T12:00:00.000000Z",
    }
    ev2 = {
        "eventid": "cowrie.login.failed",
        "username": "u2",
        "password": "p2",
        "src_ip": "1.1.1.1",
        "session": "sess_zero",
        "timestamp": "2024-10-23T12:00:00.000000Z",
    }
    closed = {
        "eventid": "cowrie.session.closed",
        "duration": 0.0,
        "session": "sess_zero",
        "timestamp": "2024-10-23T12:00:00.000000Z",
    }
    sessions = reconstruct_sessions_from_events([ev1, ev2, closed], sensor_id="s_test")
    row = extract_session_features(sessions["sess_zero"])

    freq = row["attempt_frequency_hz"]
    assert not math.isinf(freq)
    assert not math.isnan(freq)
    assert freq >= 0.0


# ---------------------------------------------------------------------------
# Test 5: Username aggregation
# ---------------------------------------------------------------------------
def test_username_aggregation():
    """Multiple usernames from one source must produce correct count and ratio."""
    events = [
        {"eventid": "cowrie.login.failed", "username": "root", "session": "s_user", "timestamp": "2024-10-23T12:00:01Z", "src_ip": "2.2.2.2"},
        {"eventid": "cowrie.login.failed", "username": "admin", "session": "s_user", "timestamp": "2024-10-23T12:00:02Z", "src_ip": "2.2.2.2"},
        {"eventid": "cowrie.login.failed", "username": "root", "session": "s_user", "timestamp": "2024-10-23T12:00:03Z", "src_ip": "2.2.2.2"},
        {"eventid": "cowrie.login.success", "username": "user1", "session": "s_user", "timestamp": "2024-10-23T12:00:04Z", "src_ip": "2.2.2.2"},
    ]
    sessions = reconstruct_sessions_from_events(events, sensor_id="s_test")
    row = extract_session_features(sessions["s_user"])

    # 4 total attempts, 3 unique usernames (root, admin, user1)
    assert row["failed_attempts_count"] == 3
    assert row["successful_attempts_count"] == 1
    assert row["total_attempts"] == 4
    assert row["unique_usernames_count"] == 3
    assert abs(row["unique_usernames_ratio"] - (3 / 4)) < 1e-5


# ---------------------------------------------------------------------------
# Test 6: Session reconstruction
# ---------------------------------------------------------------------------
def test_session_reconstruction():
    """Events sharing a session ID must be aggregated together."""
    events = [
        SAMPLE_CONNECT_EVENT,
        SAMPLE_FAILED_LOGIN,
        SAMPLE_SUCCESS_LOGIN,
        SAMPLE_CLOSED_EVENT,
    ]
    sessions = reconstruct_sessions_from_events(events, sensor_id="sensor_alpha")
    assert len(sessions) == 1
    s = sessions["sess_001"]

    assert s.session_id == "sess_001"
    assert s.src_ip == "192.168.1.100"
    assert s.protocol == "ssh"
    assert s.failed_logins == 1
    assert s.successful_logins == 1
    assert s.duration == 5.0


# ---------------------------------------------------------------------------
# Test 7: Incomplete session (missing session.closed)
# ---------------------------------------------------------------------------
def test_incomplete_session_handling():
    """A session without cowrie.session.closed must still be processed safely."""
    events = [
        SAMPLE_CONNECT_EVENT,
        SAMPLE_FAILED_LOGIN,
        # No cowrie.session.closed event!
    ]
    sessions = reconstruct_sessions_from_events(events, sensor_id="sensor_alpha")
    row = extract_session_features(sessions["sess_001"])

    assert row["session_id"] == "sess_001"
    assert row["failed_attempts_count"] == 1
    assert not math.isnan(row["session_duration"])
    assert row["session_duration"] >= 0.0


# ---------------------------------------------------------------------------
# Test 8: Cyclical time encoding
# ---------------------------------------------------------------------------
def test_cyclical_time_encoding():
    """Verify login hour 24-hour cyclical encoding (sin and cos)."""
    # 06:00 UTC -> hour = 6.0 -> 2*pi*6/24 = pi/2 -> sin = 1.0, cos = 0.0
    ev = {
        "eventid": "cowrie.login.failed",
        "username": "root",
        "src_ip": "1.1.1.1",
        "session": "s_time",
        "timestamp": "2024-10-23T06:00:00.000000Z",
    }
    sessions = reconstruct_sessions_from_events([ev], sensor_id="s_test")
    row = extract_session_features(sessions["s_time"])

    assert abs(row["login_hour"] - 6.0) < 1e-4
    assert abs(row["login_hour_sin"] - 1.0) < 1e-4
    assert abs(row["login_hour_cos"] - 0.0) < 1e-4

    # 12:00 UTC -> hour = 12.0 -> 2*pi*12/24 = pi -> sin = 0.0, cos = -1.0
    ev12 = {
        "eventid": "cowrie.login.failed",
        "username": "root",
        "src_ip": "1.1.1.1",
        "session": "s_time12",
        "timestamp": "2024-10-23T12:00:00.000000Z",
    }
    sessions12 = reconstruct_sessions_from_events([ev12], sensor_id="s_test")
    row12 = extract_session_features(sessions12["s_time12"])
    assert abs(row12["login_hour_sin"] - 0.0) < 1e-4
    assert abs(row12["login_hour_cos"] - (-1.0)) < 1e-4


# ---------------------------------------------------------------------------
# Test 9: Raw password protection (privacy invariant)
# ---------------------------------------------------------------------------
def test_raw_password_protection():
    """Generated feature dictionaries/DataFrames must never contain plaintext passwords."""
    events = [
        {"eventid": "cowrie.login.failed", "password": "superSecretPassword123!", "session": "s_sec", "timestamp": "2024-10-23T10:00:00Z"},
        {"eventid": "cowrie.login.failed", "password": "anotherSecret456!", "session": "s_sec", "timestamp": "2024-10-23T10:00:01Z"},
    ]
    sessions = reconstruct_sessions_from_events(events, sensor_id="s_test")
    row = extract_session_features(sessions["s_sec"])

    # Ensure no column or value contains the raw password
    for col, val in row.items():
        assert "superSecretPassword123!" not in str(val)
        assert "anotherSecret456!" not in str(val)
        assert "password" not in col or col in {"password_entropy", "unique_password_count", "password_reuse_ratio"}

    # Check Shannon entropy is non-zero
    assert row["password_entropy"] > 0.0
    assert row["unique_password_count"] == 2
    assert row["password_reuse_ratio"] == 0.0


# ---------------------------------------------------------------------------
# Test 10: Sensor split integrity
# ---------------------------------------------------------------------------
def test_sensor_split_integrity(tmp_path):
    """Verify strict sensor holdout: Train sensors intersect Test sensor = empty."""
    # Create mock sensor directories
    sensor_a = tmp_path / "cowrie-logs-sensor_a"
    sensor_b = tmp_path / "cowrie-logs-sensor_b"
    sensor_holdout = tmp_path / "cowrie-logs-172_234_228_9"

    for s_dir in (sensor_a, sensor_b, sensor_holdout):
        s_dir.mkdir()
        log_file = s_dir / "cowrie.json"
        log_file.write_text(
            '{"eventid": "cowrie.login.failed", "username": "admin", "password": "p", "src_ip": "1.2.3.4", "session": "sess_1", "timestamp": "2024-10-23T10:00:00Z"}\n',
            encoding="utf-8",
        )

    preprocessor = CowriePreprocessor(logs_dir=tmp_path, holdout_sensor="172_234_228_9")
    train_df, test_df = preprocessor.process_all()

    train_sensors = set(train_df["sensor_id"].unique())
    test_sensors = set(test_df["sensor_id"].unique())

    assert "172_234_228_9" in test_sensors
    assert "172_234_228_9" not in train_sensors
    assert train_sensors.isdisjoint(test_sensors)
    assert len(train_sensors) == 2
    assert len(test_sensors) == 1


# ---------------------------------------------------------------------------
# Test 11: Empty dataset handling
# ---------------------------------------------------------------------------
def test_empty_dataset_handling(tmp_path):
    """The preprocessor must return empty DataFrames with correct columns on empty input."""
    empty_sensor_dir = tmp_path / "cowrie-logs-empty"
    empty_sensor_dir.mkdir()
    (empty_sensor_dir / "cowrie.json").write_text("", encoding="utf-8")

    preprocessor = CowriePreprocessor(logs_dir=tmp_path, holdout_sensor="empty")
    train_df, test_df = preprocessor.process_all()

    for col in FEATURE_COLUMNS:
        assert col in train_df.columns
        assert col in test_df.columns
    assert len(train_df) == 0
    assert len(test_df) == 0


# ---------------------------------------------------------------------------
# Test 12: Deterministic output
# ---------------------------------------------------------------------------
def test_deterministic_output(tmp_path):
    """Running preprocessing twice on identical data produces identical DataFrames."""
    sensor_dir = tmp_path / "cowrie-logs-det"
    sensor_dir.mkdir()
    content = (
        '{"eventid": "cowrie.session.connect", "src_ip": "10.0.0.1", "session": "s_det", "protocol": "ssh", "timestamp": "2024-10-23T10:00:00Z"}\n'
        '{"eventid": "cowrie.login.failed", "username": "root", "password": "pwd", "src_ip": "10.0.0.1", "session": "s_det", "timestamp": "2024-10-23T10:00:01Z"}\n'
        '{"eventid": "cowrie.login.success", "username": "root", "password": "pwd", "src_ip": "10.0.0.1", "session": "s_det", "timestamp": "2024-10-23T10:00:02Z"}\n'
        '{"eventid": "cowrie.session.closed", "duration": 2.5, "src_ip": "10.0.0.1", "session": "s_det", "timestamp": "2024-10-23T10:00:02.5Z"}\n'
    )
    (sensor_dir / "cowrie.json").write_text(content, encoding="utf-8")

    p1 = CowriePreprocessor(logs_dir=tmp_path, holdout_sensor="det")
    _, test_df1 = p1.process_all()

    p2 = CowriePreprocessor(logs_dir=tmp_path, holdout_sensor="det")
    _, test_df2 = p2.process_all()

    pd.testing.assert_frame_equal(test_df1.reset_index(drop=True), test_df2.reset_index(drop=True))


# ---------------------------------------------------------------------------
# Test 13: Missing holdout sensor validation
# ---------------------------------------------------------------------------
def test_missing_holdout_sensor_raises(tmp_path):
    """If requested holdout sensor does not exist, preprocessor must raise ValueError rather than silent substitute."""
    sensor_dir = tmp_path / "cowrie-logs-sensor_x"
    sensor_dir.mkdir()
    (sensor_dir / "cowrie.json").write_text(
        '{"eventid": "cowrie.login.failed", "username": "admin", "password": "p", "src_ip": "1.2.3.4", "session": "s1", "timestamp": "2024-10-23T10:00:00Z"}\n',
        encoding="utf-8",
    )

    preprocessor = CowriePreprocessor(logs_dir=tmp_path, holdout_sensor="nonexistent_sensor_999")
    with pytest.raises(ValueError, match="Requested holdout sensor 'nonexistent_sensor_999' not found"):
        preprocessor.process_all()

