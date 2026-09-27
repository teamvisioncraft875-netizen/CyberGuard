"""
CYBERGUARD — Cowrie Honeypot Preprocessor & Login Feature Engineering (Phase A)

Transforms raw Cowrie JSONL honeypot logs into structured, numerical,
model-ready authentication session records.
Features:
- Incremental streaming JSONL parsing (low memory overhead)
- Multi-sensor auto-discovery and strict sensor-level holdout splitting
- Session reconstruction across connect, auth, client fingerprint, and closed events
- Privacy-safe credential statistics (Shannon entropy, reuse ratio; zero raw password persistence)
- 24-hour cyclical temporal encoding (sine/cosine transformation)
- Zero division safety and NaN/Inf prevention
"""

import json
import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set

import numpy as np
import pandas as pd

logger = logging.getLogger("cyberguard.cowrie_preprocessor")

EPSILON = 1e-6

# Explicit model feature columns
FEATURE_COLUMNS = [
    "failed_attempts_count",
    "successful_attempts_count",
    "total_attempts",
    "attempt_frequency_hz",
    "unique_usernames_count",
    "unique_usernames_ratio",
    "password_entropy",
    "unique_password_count",
    "password_reuse_ratio",
    "session_duration",
    "login_hour",
    "login_hour_sin",
    "login_hour_cos",
    "day_of_week",
    "proto_ssh",
    "proto_telnet",
    "proto_other",
    "has_client_version",
    "has_hassh",
    "success_after_failure",
]

# Non-feature metadata columns preserved for tracing & evaluation
METADATA_COLUMNS = [
    "sensor_id",
    "session_id",
    "src_ip",
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy H(X) = -sum(p * log2(p)) for a character sequence.
    Returns 0.0 for empty or single-character repeated strings.
    """
    if not text:
        return 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def parse_timestamp(ts_val: Any) -> Optional[datetime]:
    """Safely parses ISO-8601 UTC timestamp string."""
    if not ts_val or not isinstance(ts_val, str):
        return None
    try:
        # Standard format: '2024-10-23T23:15:43.982614Z'
        clean_ts = ts_val.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except (ValueError, TypeError):
        return None


def parse_cowrie_line(line: str) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]:
    """
    Safely parses a single line of Cowrie JSONL log.
    Returns: (parsed_dict, is_valid, error_message).
    Guarantees no unhandled exceptions on malformed input.
    """
    stripped = line.strip()
    if not stripped:
        return None, False, "empty_line"

    try:
        data = json.loads(stripped)
        if not isinstance(data, dict):
            return None, False, "not_a_json_object"
        return data, True, None
    except Exception as e:
        return None, False, f"json_decode_error: {str(e)}"


@dataclass
class CowrieSession:
    """Aggregated state for a reconstructed authentication session."""
    session_id: str
    sensor_id: str
    src_ip: str = "unknown"
    protocol: str = "unknown"
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None
    duration: Optional[float] = None
    failed_logins: int = 0
    successful_logins: int = 0
    usernames: Set[str] = field(default_factory=set)
    passwords: List[str] = field(default_factory=list)
    client_version: Optional[str] = None
    hassh: Optional[str] = None

    def add_event(self, event: Dict[str, Any]) -> None:
        """Integrates a single event into the session state."""
        eid = event.get("eventid", "")
        ts = parse_timestamp(event.get("timestamp"))

        if ts:
            if self.first_timestamp is None or ts < self.first_timestamp:
                self.first_timestamp = ts
            if self.last_timestamp is None or ts > self.last_timestamp:
                self.last_timestamp = ts

        # Source IP resolution
        if self.src_ip in ("unknown", "") and event.get("src_ip"):
            self.src_ip = str(event["src_ip"])

        # Connection setup
        if eid == "cowrie.session.connect":
            proto = event.get("protocol")
            if proto:
                self.protocol = str(proto).lower().strip()

        # Session closure
        elif eid == "cowrie.session.closed":
            dur_val = event.get("duration")
            if dur_val is not None:
                try:
                    dur_float = float(dur_val)
                    if math.isfinite(dur_float) and dur_float >= 0:
                        self.duration = dur_float
                except (ValueError, TypeError):
                    pass

        # Client fingerprints
        elif eid == "cowrie.client.version":
            ver = event.get("version")
            if ver:
                self.client_version = str(ver)

        elif eid == "cowrie.client.kex":
            h = event.get("hassh")
            if h:
                self.hassh = str(h)

        # Login attempts
        elif eid == "cowrie.login.failed":
            self.failed_logins += 1
            u = event.get("username")
            if u:
                self.usernames.add(str(u))
            p = event.get("password")
            if p is not None:
                self.passwords.append(str(p))

        elif eid == "cowrie.login.success":
            self.successful_logins += 1
            u = event.get("username")
            if u:
                self.usernames.add(str(u))
            p = event.get("password")
            if p is not None:
                self.passwords.append(str(p))


def reconstruct_sessions_from_events(
    events: List[Dict[str, Any]], sensor_id: str
) -> Dict[str, CowrieSession]:
    """
    Groups a list of Cowrie event dicts into reconstructed CowrieSession objects.
    """
    sessions: Dict[str, CowrieSession] = {}
    for ev in events:
        sid = ev.get("session")
        if not sid:
            continue
        sid_str = str(sid)
        if sid_str not in sessions:
            sessions[sid_str] = CowrieSession(session_id=sid_str, sensor_id=sensor_id)
        sessions[sid_str].add_event(ev)
    return sessions


def extract_session_features(session: CowrieSession) -> Dict[str, Any]:
    """
    Transforms a reconstructed CowrieSession into a clean numerical feature record.
    Strictly preserves password privacy (raw passwords are discarded).
    Guarantees no NaN, Infinite, or division-by-zero outputs.
    """
    failed = session.failed_logins
    success = session.successful_logins
    total_attempts = failed + success

    # Duration calculation
    if session.duration is not None and math.isfinite(session.duration) and session.duration >= 0.0:
        duration = float(session.duration)
    elif session.first_timestamp and session.last_timestamp:
        elapsed = (session.last_timestamp - session.first_timestamp).total_seconds()
        duration = max(elapsed, 0.0) if math.isfinite(elapsed) else 0.0
    else:
        duration = 0.0

    # Attempt frequency (Hz) safely guarded with 1.0s floor
    effective_dur = max(duration, 1.0)
    attempt_frequency_hz = total_attempts / effective_dur

    # Username behavior
    unique_usernames_count = len(session.usernames)
    unique_usernames_ratio = (
        unique_usernames_count / max(total_attempts, 1) if total_attempts > 0 else 0.0
    )

    # Password behavior (privacy-safe statistical features only)
    unique_pwd_set = set(session.passwords)
    unique_password_count = len(unique_pwd_set)
    if total_attempts <= 1:
        password_reuse_ratio = 0.0
    else:
        # Reused attempts = total attempts - distinct passwords
        password_reuse_ratio = max(0.0, (total_attempts - unique_password_count) / total_attempts)

    # Shannon entropy of passwords attempted
    if unique_pwd_set:
        entropies = [calculate_shannon_entropy(pwd) for pwd in unique_pwd_set]
        password_entropy = float(np.mean(entropies))
    else:
        password_entropy = 0.0

    # Temporal cyclical encoding
    ref_ts = session.first_timestamp
    if ref_ts is not None:
        login_hour = float(ref_ts.hour + ref_ts.minute / 60.0)
        day_of_week = ref_ts.weekday()
    else:
        login_hour = 0.0
        day_of_week = 0

    login_hour_sin = math.sin(2.0 * math.pi * (login_hour / 24.0))
    login_hour_cos = math.cos(2.0 * math.pi * (login_hour / 24.0))

    # Protocol one-hot
    proto_str = session.protocol.lower()
    proto_ssh = 1 if proto_str == "ssh" else 0
    proto_telnet = 1 if proto_str == "telnet" else 0
    proto_other = 1 if (proto_ssh == 0 and proto_telnet == 0) else 0

    # Client fingerprints
    has_client_version = 1 if session.client_version else 0
    has_hassh = 1 if session.hassh else 0

    # Attack pattern: success after failure
    success_after_failure = 1 if (success > 0 and failed > 0) else 0

    return {
        # Metadata
        "sensor_id": session.sensor_id,
        "session_id": session.session_id,
        "src_ip": session.src_ip,
        # Feature columns
        "failed_attempts_count": failed,
        "successful_attempts_count": success,
        "total_attempts": total_attempts,
        "attempt_frequency_hz": float(attempt_frequency_hz),
        "unique_usernames_count": unique_usernames_count,
        "unique_usernames_ratio": float(unique_usernames_ratio),
        "password_entropy": float(password_entropy),
        "unique_password_count": unique_password_count,
        "password_reuse_ratio": float(password_reuse_ratio),
        "session_duration": float(duration),
        "login_hour": float(login_hour),
        "login_hour_sin": float(login_hour_sin),
        "login_hour_cos": float(login_hour_cos),
        "day_of_week": int(day_of_week),
        "proto_ssh": proto_ssh,
        "proto_telnet": proto_telnet,
        "proto_other": proto_other,
        "has_client_version": has_client_version,
        "has_hassh": has_hassh,
        "success_after_failure": success_after_failure,
    }


class CowriePreprocessor:
    """
    Streaming preprocessor and dataset split generator for Cowrie honeypot logs.
    """

    def __init__(
        self,
        logs_dir: Path,
        holdout_sensor: str = "172_234_228_9",
        only_auth_sessions: bool = True,
    ):
        self.logs_dir = Path(logs_dir)
        self.holdout_sensor = holdout_sensor
        self.only_auth_sessions = only_auth_sessions

        # Metrics & parsing counters
        self.stats = {
            "total_lines": 0,
            "valid_events": 0,
            "malformed_lines": 0,
            "ignored_events": 0,
            "sessions_reconstructed": 0,
            "authentication_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
        }

    def discover_sensors(self) -> List[Tuple[str, Path]]:
        """
        Discovers all sensor directories under logs_dir.
        Returns a list of (sensor_id, directory_path).
        """
        sensors: List[Tuple[str, Path]] = []
        if not self.logs_dir.exists():
            return sensors

        for entry in sorted(self.logs_dir.iterdir()):
            if entry.is_dir():
                name = entry.name
                if name.startswith("cowrie-logs-"):
                    sensor_id = name.replace("cowrie-logs-", "")
                else:
                    sensor_id = name
                sensors.append((sensor_id, entry))
        return sensors

    @staticmethod
    def get_chronological_files(sensor_dir: Path) -> List[Path]:
        """
        Returns all cowrie.json* files in chronological order:
        Rotated files (cowrie.json.YYYY-MM-DD) sorted by date,
        followed by active cowrie.json.
        """
        files = [
            f
            for f in sensor_dir.glob("cowrie.json*")
            if not f.name.endswith(".log") and not f.name.endswith(".gitignore")
        ]
        # Rotated daily files have format cowrie.json.YYYY-MM-DD
        # Active file is cowrie.json
        return sorted(files, key=lambda p: (1, p.name) if p.name == "cowrie.json" else (0, p.name))

    def process_sensor(self, sensor_id: str, sensor_dir: Path) -> pd.DataFrame:
        """
        Streams all JSONL files for a single sensor, reconstructs sessions,
        and extracts feature vectors.
        """
        json_files = self.get_chronological_files(sensor_dir)
        sessions: Dict[str, CowrieSession] = {}

        for file_path in json_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        self.stats["total_lines"] += 1
                        parsed, is_valid, err = parse_cowrie_line(line)
                        if not is_valid:
                            if err != "empty_line":
                                self.stats["malformed_lines"] += 1
                            continue

                        self.stats["valid_events"] += 1
                        eid = parsed.get("eventid", "")
                        sid = parsed.get("session")

                        if not sid:
                            self.stats["ignored_events"] += 1
                            continue

                        sid_str = str(sid)
                        if sid_str not in sessions:
                            sessions[sid_str] = CowrieSession(session_id=sid_str, sensor_id=sensor_id)

                        sessions[sid_str].add_event(parsed)

                        if eid == "cowrie.login.failed":
                            self.stats["authentication_events"] += 1
                            self.stats["failed_logins"] += 1
                        elif eid == "cowrie.login.success":
                            self.stats["authentication_events"] += 1
                            self.stats["successful_logins"] += 1

            except Exception as e:
                logger.error(f"Error streaming file {file_path}: {e}")

        self.stats["sessions_reconstructed"] += len(sessions)

        rows = []
        for s in sessions.values():
            if self.only_auth_sessions and (s.failed_logins + s.successful_logins == 0):
                continue
            rows.append(extract_session_features(s))

        all_cols = METADATA_COLUMNS + FEATURE_COLUMNS
        if not rows:
            return pd.DataFrame(columns=all_cols)

        df = pd.DataFrame(rows)[all_cols]
        return df

    def process_all(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Discovers all sensors, applies strict sensor-level holdout split,
        and returns (train_df, test_df).
        """
        sensors = self.discover_sensors()
        discovered_ids = [s[0] for s in sensors]

        # Verify holdout sensor exists if there are sensors present
        if sensors and self.holdout_sensor not in discovered_ids:
            raise ValueError(
                f"Requested holdout sensor '{self.holdout_sensor}' not found among discovered sensors: {discovered_ids}"
            )

        train_dfs: List[pd.DataFrame] = []
        test_dfs: List[pd.DataFrame] = []

        all_cols = METADATA_COLUMNS + FEATURE_COLUMNS

        for sensor_id, sensor_dir in sensors:
            logger.info(f"Processing sensor {sensor_id} ({sensor_dir})...")
            sensor_df = self.process_sensor(sensor_id, sensor_dir)

            if sensor_id == self.holdout_sensor:
                test_dfs.append(sensor_df)
            else:
                train_dfs.append(sensor_df)

        train_df = pd.concat(train_dfs, ignore_index=True) if train_dfs else pd.DataFrame(columns=all_cols)
        test_df = pd.concat(test_dfs, ignore_index=True) if test_dfs else pd.DataFrame(columns=all_cols)

        return train_df, test_df

    def run_and_save(self, output_dir: Path) -> Tuple[Path, Path]:
        """
        Executes end-to-end preprocessing and saves Parquet feature files:
        - <output_dir>/train_login_features.parquet
        - <output_dir>/test_login_features.parquet
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        train_df, test_df = self.process_all()

        train_path = output_dir / "train_login_features.parquet"
        test_path = output_dir / "test_login_features.parquet"

        train_df.to_parquet(train_path, index=False)
        test_df.to_parquet(test_path, index=False)

        return train_path, test_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    repo_root = Path(__file__).resolve().parents[4]
    dataset_dir = repo_root / "datasets" / "logs_dataset"
    ml_service_dir = Path(__file__).resolve().parents[2]
    out_dir = ml_service_dir / "data" / "login"

    print("=" * 70)
    print("CYBERGUARD — Phase A: Cowrie Dataset Preprocessing & Feature Extraction")
    print("=" * 70)
    print(f"Dataset directory: {dataset_dir}")
    print(f"Output directory:  {out_dir}")

    preprocessor = CowriePreprocessor(logs_dir=dataset_dir, holdout_sensor="172_234_228_9")
    train_path, test_path = preprocessor.run_and_save(out_dir)

    train_df = pd.read_parquet(train_path)
    test_df = pd.read_parquet(test_path)

    print("\n" + "=" * 70)
    print("PARSING STATISTICS")
    print("=" * 70)
    for k, v in preprocessor.stats.items():
        print(f"  {k:<25}: {v:,}")

    print("\n" + "=" * 70)
    print("DATASET SPLIT & VALIDATION")
    print("=" * 70)
    train_sensors = sorted(list(train_df["sensor_id"].unique()))
    test_sensors = sorted(list(test_df["sensor_id"].unique()))
    print(f"Training rows:            {len(train_df):,}")
    print(f"Testing rows:             {len(test_df):,}")
    print(f"Training sensors ({len(train_sensors)}):     {train_sensors}")
    print(f"Testing sensor ({len(test_sensors)}):       {test_sensors}")

    # Check for NaNs and Infs
    num_cols = [c for c in FEATURE_COLUMNS if c in train_df.columns]
    train_nans = int(train_df[num_cols].isna().sum().sum())
    test_nans = int(test_df[num_cols].isna().sum().sum())
    train_infs = int(np.isinf(train_df[num_cols].select_dtypes(include=[np.number])).sum().sum())
    test_infs = int(np.isinf(test_df[num_cols].select_dtypes(include=[np.number])).sum().sum())

    print(f"Training NaNs:            {train_nans}")
    print(f"Testing NaNs:             {test_nans}")
    print(f"Training Infs:            {train_infs}")
    print(f"Testing Infs:             {test_infs}")

    # Verify sensor separation
    overlap = set(train_sensors).intersection(set(test_sensors))
    print(f"Sensor Overlap (Leakage): {len(overlap)} (Must be 0)")
    assert len(overlap) == 0, "Data leakage detected between train and test sensors!"

    print(f"\nGenerated Parquet Files:")
    print(f"  Train: {train_path} ({train_path.stat().st_size / (1024*1024):.2f} MB)")
    print(f"  Test:  {test_path} ({test_path.stat().st_size / (1024*1024):.2f} MB)")
    print("=" * 70)

