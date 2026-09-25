"""
CYBERGUARD — CTU-13 Network Flow Preprocessor & Feature Extraction

Transforms raw bidirectional NetFlow records into standardized, numerical,
model-ready feature matrices for network threat & anomaly detection engines.
Designed for chunked streaming to handle gigabyte-scale datasets within low RAM footprints.
"""

from typing import Dict, Any, Tuple, Optional, Generator, List
import pandas as pd
import numpy as np


FEATURE_COLUMNS = [
    "dur",
    "tot_pkts",
    "tot_bytes",
    "src_bytes",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "src_byte_ratio",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "is_well_known_dport",
    "is_bidirectional",
]

EPSILON = 1e-6


def _to_float(val: Any, default: float = 0.0) -> float:
    """Safely cast value to float, defaulting to 0.0 on invalid/missing."""
    if val is None or pd.isna(val):
        return default
    try:
        f = float(val)
        return f if np.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def _to_int(val: Any, default: int = 0) -> int:
    """Safely cast value to integer."""
    if val is None or pd.isna(val):
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def parse_flow_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses a single flow record dict into model-ready numerical features.
    Guarantees no division by zero and no NaN/infinite outputs.
    """
    dur = max(_to_float(row.get("Dur")), 0.0)
    tot_pkts = max(_to_float(row.get("TotPkts")), 0.0)
    tot_bytes = max(_to_float(row.get("TotBytes")), 0.0)
    src_bytes = max(_to_float(row.get("SrcBytes")), 0.0)

    # Rates: use epsilon floor for duration to prevent zero division
    effective_dur = max(dur, EPSILON)
    packet_rate = tot_pkts / effective_dur
    byte_rate = tot_bytes / effective_dur

    # Packet size asymmetry
    avg_packet_size = tot_bytes / max(tot_pkts, 1.0)
    src_byte_ratio = src_bytes / max(tot_bytes, 1.0)

    # Protocol one-hot encoding
    proto_str = str(row.get("Proto") or "").strip().lower()
    proto_tcp = 1 if proto_str == "tcp" else 0
    proto_udp = 1 if proto_str == "udp" else 0
    proto_icmp = 1 if proto_str == "icmp" else 0
    proto_other = 1 if (proto_tcp == 0 and proto_udp == 0 and proto_icmp == 0) else 0

    # Destination Port analysis
    dport = _to_int(row.get("Dport"), default=-1)
    is_well_known_dport = 1 if (0 <= dport < 1024) else 0

    # Direction analysis
    dir_str = str(row.get("Dir") or "").strip()
    is_bidirectional = 1 if "<->" in dir_str else 0

    # Target Label: Flag botnet threat
    label_str = str(row.get("Label") or "").strip().lower()
    is_threat = 1 if "botnet" in label_str else 0

    return {
        "dur": dur,
        "tot_pkts": tot_pkts,
        "tot_bytes": tot_bytes,
        "src_bytes": src_bytes,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "avg_packet_size": avg_packet_size,
        "src_byte_ratio": src_byte_ratio,
        "proto_tcp": proto_tcp,
        "proto_udp": proto_udp,
        "proto_icmp": proto_icmp,
        "proto_other": proto_other,
        "is_well_known_dport": is_well_known_dport,
        "is_bidirectional": is_bidirectional,
        "is_threat": is_threat,
    }


def extract_features_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Vectorized feature extraction from a raw CTU-13 DataFrame chunk.
    Returns (features_df, target_series).
    """
    if df.empty:
        empty_features = pd.DataFrame(columns=FEATURE_COLUMNS, dtype=np.float64)
        empty_target = pd.Series(dtype=np.int32, name="is_threat")
        return empty_features, empty_target

    dur = pd.to_numeric(df.get("Dur"), errors="coerce").fillna(0.0).clip(lower=0.0)
    tot_pkts = pd.to_numeric(df.get("TotPkts"), errors="coerce").fillna(0.0).clip(lower=0.0)
    tot_bytes = pd.to_numeric(df.get("TotBytes"), errors="coerce").fillna(0.0).clip(lower=0.0)
    src_bytes = pd.to_numeric(df.get("SrcBytes"), errors="coerce").fillna(0.0).clip(lower=0.0)

    effective_dur = np.maximum(dur.values, EPSILON)
    packet_rate = tot_pkts.values / effective_dur
    byte_rate = tot_bytes.values / effective_dur

    avg_packet_size = tot_bytes.values / np.maximum(tot_pkts.values, 1.0)
    src_byte_ratio = src_bytes.values / np.maximum(tot_bytes.values, 1.0)

    proto_s = df.get("Proto", pd.Series("", index=df.index)).astype(str).str.strip().str.lower()
    proto_tcp = (proto_s == "tcp").astype(np.int32)
    proto_udp = (proto_s == "udp").astype(np.int32)
    proto_icmp = (proto_s == "icmp").astype(np.int32)
    proto_other = ((proto_tcp == 0) & (proto_udp == 0) & (proto_icmp == 0)).astype(np.int32)

    dport = pd.to_numeric(df.get("Dport"), errors="coerce").fillna(-1)
    is_well_known_dport = ((dport >= 0) & (dport < 1024)).astype(np.int32)

    dir_s = df.get("Dir", pd.Series("", index=df.index)).astype(str)
    is_bidirectional = dir_s.str.contains(r"<->", regex=True, na=False).astype(np.int32)

    features = pd.DataFrame(
        {
            "dur": dur.values,
            "tot_pkts": tot_pkts.values,
            "tot_bytes": tot_bytes.values,
            "src_bytes": src_bytes.values,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "avg_packet_size": avg_packet_size,
            "src_byte_ratio": src_byte_ratio,
            "proto_tcp": proto_tcp.values,
            "proto_udp": proto_udp.values,
            "proto_icmp": proto_icmp.values,
            "proto_other": proto_other.values,
            "is_well_known_dport": is_well_known_dport.values,
            "is_bidirectional": is_bidirectional.values,
        },
        index=df.index,
    )[FEATURE_COLUMNS]

    label_s = df.get("Label", pd.Series("", index=df.index)).astype(str).str.lower()
    is_threat = label_s.str.contains("botnet", regex=False, na=False).astype(np.int32)
    is_threat.name = "is_threat"

    return features, is_threat


class CTU13Preprocessor:
    """
    Streamlined preprocessor for CTU-13 network telemetry.
    Supports in-memory transform and chunked file streaming.
    """

    def __init__(self, feature_columns: Optional[List[str]] = None):
        self.feature_columns = feature_columns or FEATURE_COLUMNS

    def transform(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Transform a raw CTU-13 DataFrame into (X, y)."""
        return extract_features_dataframe(df)

    def stream_process_file(
        self,
        file_path: str,
        chunk_size: int = 100000,
        sample_ratio: Optional[float] = None,
        random_state: int = 42,
    ) -> Generator[Tuple[pd.DataFrame, pd.Series], None, None]:
        """
        Yields (features, target) chunks from a large CTU-13 binetflow file.
        Keeps RAM overhead minimal during multi-gigabyte ingestion.
        """
        for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
            if sample_ratio is not None and 0.0 < sample_ratio < 1.0:
                chunk = chunk.sample(frac=sample_ratio, random_state=random_state)
            yield extract_features_dataframe(chunk)
