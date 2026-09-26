import pytest
import pandas as pd
import numpy as np

# This will fail initially because the module does not exist yet (TDD Step 2.1)
from app.utils.ctu13_preprocessor import (
    CTU13Preprocessor,
    parse_flow_record,
    extract_features_dataframe,
    FEATURE_COLUMNS,
)


SAMPLE_RECORDS = [
    # Standard TCP Botnet flow
    {
        "StartTime": "2011/08/10 11:04:27.140727",
        "Dur": "0.045125",
        "Proto": "tcp",
        "SrcAddr": "147.32.84.165",
        "Sport": "1027",
        "Dir": " ->",
        "DstAddr": "74.125.232.195",
        "Dport": "80",
        "State": "SRPA_SPA",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": "7",
        "TotBytes": "882",
        "SrcBytes": "629",
        "Label": "flow=From-Botnet-V42-TCP-HTTP-Google-Net-Established-6",
    },
    # Standard UDP Background flow with zero duration
    {
        "StartTime": "2011/08/10 09:46:53.048843",
        "Dur": "0.000000",
        "Proto": "udp",
        "SrcAddr": "84.13.246.132",
        "Sport": "28431",
        "Dir": " <->",
        "DstAddr": "147.32.84.229",
        "Dport": "13363",
        "State": "CON",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": "2",
        "TotBytes": "135",
        "SrcBytes": "75",
        "Label": "flow=Background-UDP-Established",
    },
    # ICMP Normal flow with missing/irregular fields
    {
        "StartTime": "2011/08/10 09:47:00.000000",
        "Dur": "1.500000",
        "Proto": "icmp",
        "SrcAddr": "147.32.84.59",
        "Sport": "",  # missing port
        "Dir": " <?>",
        "DstAddr": "147.32.84.1",
        "Dport": "unknown",  # invalid port string
        "State": "INT",
        "sTos": "0",
        "dTos": "0",
        "TotPkts": "10",
        "TotBytes": "1000",
        "SrcBytes": "1000",
        "Label": "flow=From-Normal-V42-ICMP",
    },
    # Corrupt / Missing numeric values
    {
        "StartTime": "2011/08/10 09:48:00.000000",
        "Dur": "invalid_dur",
        "Proto": "custom_proto",
        "SrcAddr": "10.0.0.1",
        "Sport": "50000",
        "Dir": " ->",
        "DstAddr": "10.0.0.2",
        "Dport": "443",
        "State": "CON",
        "sTos": None,
        "dTos": None,
        "TotPkts": None,
        "TotBytes": "corrupt",
        "SrcBytes": "",
        "Label": "flow=Background",
    },
]


def test_required_columns_defined():
    """Verify that expected model feature columns are explicitly defined."""
    assert isinstance(FEATURE_COLUMNS, list)
    expected_subset = {
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
        "is_well_known_dport",
        "is_bidirectional",
    }
    assert expected_subset.issubset(set(FEATURE_COLUMNS))


def test_parse_single_record_botnet():
    """Verify that a valid botnet record is parsed and target is mapped to 1."""
    parsed = parse_flow_record(SAMPLE_RECORDS[0])
    assert parsed["is_threat"] == 1
    assert parsed["dur"] == pytest.approx(0.045125, rel=1e-4)
    assert parsed["tot_pkts"] == 7
    assert parsed["tot_bytes"] == 882
    assert parsed["src_bytes"] == 629
    assert parsed["proto_tcp"] == 1
    assert parsed["proto_udp"] == 0
    assert parsed["is_well_known_dport"] == 1  # port 80 is well-known


def test_parse_single_record_background():
    """Verify that normal/background flow maps target to 0."""
    parsed = parse_flow_record(SAMPLE_RECORDS[1])
    assert parsed["is_threat"] == 0
    assert parsed["proto_udp"] == 1
    assert parsed["proto_tcp"] == 0
    assert parsed["is_bidirectional"] == 1


def test_zero_duration_safe_division():
    """Verify zero duration does not raise ZeroDivisionError and produces finite rates."""
    parsed = parse_flow_record(SAMPLE_RECORDS[1])
    assert parsed["dur"] == 0.0
    assert np.isfinite(parsed["packet_rate"])
    assert np.isfinite(parsed["byte_rate"])
    assert parsed["packet_rate"] >= 0.0
    assert parsed["byte_rate"] >= 0.0


def test_rate_calculations():
    """Verify packet and byte rate calculations for non-zero duration."""
    parsed = parse_flow_record(SAMPLE_RECORDS[0])
    expected_packet_rate = 7 / 0.045125
    expected_byte_rate = 882 / 0.045125
    assert parsed["packet_rate"] == pytest.approx(expected_packet_rate, rel=1e-3)
    assert parsed["byte_rate"] == pytest.approx(expected_byte_rate, rel=1e-3)


def test_average_packet_size_and_src_ratio():
    """Verify avg packet size and src bytes ratio."""
    parsed = parse_flow_record(SAMPLE_RECORDS[0])
    assert parsed["avg_packet_size"] == pytest.approx(882 / 7, rel=1e-3)
    assert parsed["src_byte_ratio"] == pytest.approx(629 / 882, rel=1e-3)


def test_invalid_and_missing_values_handled_safely():
    """Verify corrupt/missing fields default safely to zero without throwing exceptions."""
    parsed = parse_flow_record(SAMPLE_RECORDS[3])
    assert parsed["dur"] == 0.0
    assert parsed["tot_pkts"] == 0.0
    assert parsed["tot_bytes"] == 0.0
    assert parsed["src_bytes"] == 0.0
    assert parsed["is_threat"] == 0
    assert np.isfinite(parsed["packet_rate"])
    assert np.isfinite(parsed["byte_rate"])
    assert np.isfinite(parsed["avg_packet_size"])
    assert np.isfinite(parsed["src_byte_ratio"])


def test_dataframe_feature_extraction():
    """Verify dataframe batch processing returns exact expected feature matrix."""
    df_raw = pd.DataFrame(SAMPLE_RECORDS)
    df_features, y = extract_features_dataframe(df_raw)

    assert len(df_features) == 4
    assert len(y) == 4
    assert list(y) == [1, 0, 0, 0]
    assert list(df_features.columns) == FEATURE_COLUMNS
    assert not df_features.isnull().values.any(), "Features must contain zero NaN values"
    assert np.isfinite(df_features.values).all(), "Features must contain only finite numbers"


def test_ctu13_preprocessor_class_deterministic():
    """Verify CTU13Preprocessor class operates deterministically."""
    preprocessor = CTU13Preprocessor()
    df_raw = pd.DataFrame(SAMPLE_RECORDS)
    
    feats1, y1 = preprocessor.transform(df_raw)
    feats2, y2 = preprocessor.transform(df_raw)

    pd.testing.assert_frame_equal(feats1, feats2)
    pd.testing.assert_series_equal(y1, y2)
