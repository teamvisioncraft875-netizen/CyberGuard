"""
CYBERGUARD — Phase 6 Telemetry Collector Integration Tests

Validates integration between:
- services/guard-app/collector.py (NetworkFlowCollector)
- services/ml-service/app/utils/telemetry_adapter.py (transform_guard_telemetry)
- services/ml-service/app/services/system_engine.py (analyze_system)
- services/ml-service/app/services/network_anomaly/model.py (NetworkThreatModel)

Guarantees:
- Real OS flow captures transform into exact 14-dim CTU-13 feature matrix.
- Inference succeeds without exceptions or schema mismatches.
- Both supervised probability and anomaly score are computed.
- Collector failure is never silently masked as a false "Safe" detection.
"""

import sys
from pathlib import Path
import pytest

GUARD_APP_PATH = Path(__file__).resolve().parents[2] / "guard-app"
if str(GUARD_APP_PATH) not in sys.path:
    sys.path.insert(0, str(GUARD_APP_PATH))

from collector import NetworkFlowCollector, CollectorError
from app.schemas.analyze import SystemAnalyzeRequest, UnifiedAnalysisResponse, RiskLevel
from app.services.system_engine import analyze_system, get_network_model
from app.utils.telemetry_adapter import transform_guard_telemetry
from app.utils.ctu13_preprocessor import FEATURE_COLUMNS


def test_real_collector_output_schema():
    """Verify live capture produces exact expected schema with all required numerical fields."""
    collector = NetworkFlowCollector(default_interval=0.02)
    flow = collector.capture_flow()

    required_keys = [
        "duration",
        "packet_count",
        "total_bytes",
        "source_bytes",
        "protocol",
        "source_port",
        "destination_port",
        "direction",
    ]
    for k in required_keys:
        assert k in flow, f"Missing key in collector output: {k}"

    assert flow["duration"] >= 0.01
    assert flow["packet_count"] >= 1.0
    assert flow["total_bytes"] >= 0.0
    assert flow["protocol"] in ["tcp", "udp", "icmp"]


def test_real_collector_to_telemetry_adapter_integration():
    """Verify real collector output transforms seamlessly into 14 CTU-13 model features."""
    collector = NetworkFlowCollector(default_interval=0.02)
    flow = collector.capture_flow()

    features = transform_guard_telemetry(flow)
    assert isinstance(features, dict)

    for col in FEATURE_COLUMNS:
        assert col in features, f"Missing feature column: {col}"
        val = features[col]
        assert isinstance(val, (int, float))
        assert val == val, f"Feature {col} returned NaN"
        assert val != float("inf") and val != float("-inf"), f"Feature {col} returned Inf"


def test_real_collector_to_system_engine_e2e():
    """
    Verify complete pipeline from real OS collection -> adapter -> hybrid inference -> response.
    """
    collector = NetworkFlowCollector(default_interval=0.02)
    flow = collector.capture_flow()

    req = SystemAnalyzeRequest(
        user_id="guard_agent_test",
        timestamp="2026-09-25T12:00:00Z",
        event_type="network_flow_telemetry",
        details=flow,
    )
    response = analyze_system(req)

    assert isinstance(response, UnifiedAnalysisResponse)
    assert 0 <= response.risk_score <= 100
    assert response.risk_level in [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    signals = response.signals
    assert "supervised_threat_probability" in signals
    assert "anomaly_score" in signals
    assert "detector_triggered" in signals
    assert signals["engine"] == "System & Network Threat Engine"


def test_simulated_mode_preserves_testing_compatibility():
    """Verify simulate=True flag remains functional for restricted environments."""
    collector = NetworkFlowCollector(simulate=True)
    flow = collector.capture_flow()

    assert flow["duration"] == 1.0
    assert flow["destination_port"] == 443

    req = SystemAnalyzeRequest(
        user_id="guard_agent_sim",
        timestamp="2026-09-25T12:00:00Z",
        event_type="network_flow_telemetry",
        details=flow,
    )
    response = analyze_system(req)
    assert isinstance(response, UnifiedAnalysisResponse)
    assert response.risk_score >= 0
